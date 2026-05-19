# W154 — CreateNewBlock + BlockAssembler (rustoshi)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`, `addPackageTxs`/`addChunks`
(ancestor-feerate selection), `resetBlock`, `ClampOptions`, `AddToBlock`,
`TestChunkBlockLimits`, `TestChunkTransactions`, `RegenerateCommitments`,
`GenerateCoinbaseCommitment`, `UpdateUncommittedBlockStructures`,
`UpdateTime`, `GetMinimumTime`, `IncrementExtraNonce`, `BlockMerkleRoot` /
`BlockWitnessMerkleRoot`, `generatetoaddress`, `generateblock`,
`generatetodescriptor`, `getblocktemplate` (BIP-22/23), `submitblock`,
`getmininginfo`, coinbase scriptSig (BIP-34, bad-cb-length 2..100),
anti-fee-sniping `nLockTime = nHeight - 1`, witness commitment OP_RETURN
0xaa21a9ed (BIP-141), `nVersion` ComputeBlockVersion (BIP-9/320),
`m_lock_time_cutoff = pindexPrev->GetMedianTimePast()` (BIP-113),
`MAX_BLOCK_WEIGHT=4000000`, `WITNESS_SCALE_FACTOR=4`,
`DEFAULT_BLOCK_RESERVED_WEIGHT=8000`, `MINIMUM_BLOCK_RESERVED_WEIGHT=2000`,
`DEFAULT_BLOCK_MIN_TX_FEE` (1 sat/kvB).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.cpp:122-237` — `BlockAssembler::CreateNewBlock`
  (resetBlock, mempool addChunks under cs lock, coinbase build with
  `CScript() << nHeight`, optional OP_0 dummy extranonce for h≤16,
  `nLockTime = nHeight-1`, `GenerateCoinbaseCommitment`,
  `UpdateTime + GetNextWorkRequired`, terminal `TestBlockValidity`).
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`:
  `block_reserved_weight ∈ [MINIMUM_BLOCK_RESERVED_WEIGHT(2000), MAX_BLOCK_WEIGHT]`,
  `nBlockMaxWeight ∈ [*block_reserved_weight, MAX_BLOCK_WEIGHT]`.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`:
  `nBlockWeight = *block_reserved_weight`,
  `nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`
  (default `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400`).
- `bitcoin-core/src/node/miner.cpp:239-260` — `TestChunkBlockLimits`
  (`>= nBlockMaxWeight` and `>= MAX_BLOCK_SIGOPS_COST` are STRICT), and
  `TestChunkTransactions` (per-tx `IsFinalTx` re-check inside chunk loop).
- `bitcoin-core/src/node/miner.cpp:279-334` — `addChunks`:
  iterates chunks from mempool's cluster-aware builder, applies
  `blockMinFeeRate` early-return (`return`, not `continue`),
  MAX_CONSECUTIVE_FAILURES=1000 + BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000 bail.
- `bitcoin-core/src/node/miner.cpp:36-65` — `GetMinimumTime`:
  `max(prev.MTP + 1, prev.BlockTime - MAX_TIMEWARP)` at retarget boundaries
  ON ALL NETWORKS (BIP-94 always-on for miner); `UpdateTime` picks
  `max(GetMinimumTime, NodeClock::now)` and re-runs `GetNextWorkRequired`
  if `fPowAllowMinDifficultyBlocks`.
- `bitcoin-core/src/node/miner.h:80-88` — `BlockAssembler::Options`:
  `nBlockMaxWeight{DEFAULT_BLOCK_MAX_WEIGHT}`,
  `blockMinFeeRate{DEFAULT_BLOCK_MIN_TX_FEE}` (CFeeRate{1} = 1 sat/kvB,
  NOT 1 sat/vB), `test_block_validity{true}` (terminal sanity check).
- `bitcoin-core/src/policy/policy.h:25-36` — `DEFAULT_BLOCK_MAX_WEIGHT
  = MAX_BLOCK_WEIGHT = 4_000_000`, `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`,
  `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000`, `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400`,
  `DEFAULT_BLOCK_MIN_TX_FEE = 1` (sat per **kvB**, fed to
  `CFeeRate{1}` whose constructor takes sat/kvB — feerate.h:41).
- `bitcoin-core/src/consensus/consensus.h:15-32` — `MAX_BLOCK_WEIGHT=4_000_000`,
  `MAX_BLOCK_SIGOPS_COST=80_000`, `WITNESS_SCALE_FACTOR=4`,
  `MAX_BLOCK_SERIALIZED_SIZE=4_000_000`, `MAX_TIMEWARP=600`.
- `bitcoin-core/src/consensus/validation.h:18,147-164` —
  `MINIMUM_WITNESS_COMMITMENT=38`, `GetWitnessCommitmentIndex` scan-from-end.
- `bitcoin-core/src/validation.cpp:3985-4019` —
  `GenerateCoinbaseCommitment` + `UpdateUncommittedBlockStructures`:
  the commitment is added iff `commitpos == NO_WITNESS_COMMITMENT` AND
  segwit-active (`DeploymentActiveAfter(prev, *this, DEPLOYMENT_SEGWIT)`);
  the witness-nonce `tx.vin[0].scriptWitness.stack[0]` is added iff segwit
  active AND coinbase lacks witness — i.e. **commitment + nonce are
  segwit-active-gated, NOT mempool-content-gated**.
- `bitcoin-core/src/rpc/mining.cpp:164-182` — `generateBlocks`:
  `miner.createNewBlock({.coinbase_output_script=...,
  .include_dummy_extranonce=true}, /*cooldown=*/false)` → `GenerateBlock`
  (mining.cpp:137-162) increments `block.nNonce` until PoW satisfies
  `CheckProofOfWork(block.GetHash(), block.nBits, …)`.
- `bitcoin-core/src/rpc/mining.cpp:264-300` — `generatetoaddress`,
  `generatetodescriptor` (mining.cpp:219-255), `generateblock`
  (mining.cpp:303-385).
- `bitcoin-core/src/rpc/mining.cpp:846-1034` — `getblocktemplate`:
  `mode` ∈ {"template", "proposal"} (BIP-23), `rules` array MUST contain
  "segwit" (lines 854-857), `longpollid = tip.GetHex() +
  ToString(nTransactionsUpdatedLast)` (line 1002),
  `mintime = GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())`
  (line 1004), pre-segwit `sigoplimit/sizelimit/=WITNESS_SCALE_FACTOR`,
  pre-segwit skip `weightlimit`, `default_witness_commitment =
  block_template->getCoinbaseTx().required_outputs[0].scriptPubKey` only
  when set.
- `bitcoin-core/src/rpc/mining.cpp:502-544` — `prioritisetransaction`.
- `bitcoin-core/src/rpc/mining.cpp:444-499` — `getmininginfo`: emits
  `currentblockweight` / `currentblocktx` when
  `BlockAssembler::m_last_block_weight` / `m_last_block_num_txs` set.
- `bitcoin-core/src/rpc/mining.cpp:66-69` — `getnetworkhashps` lookup
  validation: `if (lookup < -1 || lookup == 0) throw RPC_INVALID_PARAMETER`.

**Files audited**
- `crates/consensus/src/block_template.rs` — `build_block_template`
  (line 291-534), `BlockTemplateConfig` (line 135-181) including
  `coinbase_script_pubkey`, `coinbase_extra_data`, `max_weight`,
  `max_sigops`, `block_min_fee_rate`, `block_version`;
  `BlockTemplate` struct (line 99-127); `is_final_tx` (line 201-229);
  `build_coinbase_tx` (line 558-629); `build_witness_commitment`
  (line 635-664); `encode_coinbase_height` (line 682-710);
  `estimate_coinbase_weight` (line 719-737); constants
  `DEFAULT_BLOCK_RESERVED_WEIGHT=8_000` (line 63),
  `MINIMUM_BLOCK_RESERVED_WEIGHT=2_000` (line 67),
  `MAX_CONSECUTIVE_FAILURES=1_000` (line 71),
  `BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4_000` (line 76),
  `SEQUENCE_FINAL=0xFFFFFFFF` (line 83), `MAX_SEQUENCE_NONFINAL` (line 87).
- `crates/consensus/src/mempool.rs` — `get_sorted_for_mining`
  (line 2340-2365), `get_modified_fee` (line 3298-3305),
  `MempoolConfig::default` with `verify_scripts: false` (line 747),
  `MempoolConfig::production()` (line 785-790), `MAX_CLUSTER_SIZE=64`
  (line 144), ancestor accounting (`ancestor_count`, `ancestor_size`,
  `ancestor_fees` at line 831-835 / 1788-1986 / 4324-4341).
- `crates/consensus/src/params.rs` — `MAX_BLOCK_WEIGHT=4_000_000`
  (line referenced by lib.rs:80), `MAX_BLOCK_SIGOPS_COST=80_000`
  (line 77), `MAX_BLOCK_SERIALIZED_SIZE=4_000_000` (line 73),
  `WITNESS_SCALE_FACTOR=4`, `MAX_TIMEWARP=600` (line 213),
  `SUBSIDY_HALVING_INTERVAL=210_000` (line 228), `block_subsidy`
  (line 298), `is_segwit_active` (line 982-984), `is_taproot_active`
  (line 987-989), `pow_allow_min_difficulty_blocks` (line 485 /
  per-network 569 / 752 / 808 / 896 / 937), `enforce_bip94` (line 490 /
  per-network 571 / 754 / 810 / 898 / 939).
- `crates/consensus/src/validation.rs` — `count_block_sigops`
  (line 547-555), `get_legacy_sigop_count` (line 562-571),
  `get_p2sh_sigop_count` (line 581-600), `get_transaction_sigop_cost`
  (line 612-655), `count_witness_sigops` (line 670-697),
  `bad-cb-length` 2..100 enforcement (line 425-427),
  `CoinbaseScriptSize` reject token (line 279-281),
  `skip_scripts` IBD branch (line 1554, 1803).
- `crates/consensus/src/versionbits.rs` — `compute_block_version`
  (line 504-520), `get_state_for` (line 285-289), `VERSIONBITS_TOP_BITS
  = 0x20000000` (line 40), `get_deployments` (line 536+).
- `crates/rpc/src/server.rs` — `get_block_template` (line 4065-4329),
  `submit_block` (line 4331+), `get_mining_info` (line 4624-4669),
  `generate_to_address` (line 5522-5556), `generate_block`
  (line 5558-5606), `generate_to_descriptor` (line 5608-5654),
  `mine_blocks` (line 9354-9371), `mine_block_with_txs` (line 9374-9381),
  `mine_single_block` (line 9384-9620), state-level mempool
  construction (`MempoolConfig::default()` at line 172 / 199).
- `crates/rpc/src/types.rs` — `BlockTemplateResult` (line 583+),
  `BlockTemplateTransaction` (line ~595), `MiningInfo` (line 525-546).
- `crates/storage/src/indexes/coinstatsindex.rs` — `get_block_subsidy`
  (line 293-303), `HALVING_INTERVAL: u32 = 210_000` (line 295) — second
  hardcoded subsidy halving (W145 carry-forward).
- `crates/consensus/tests/test_w108_gbt.rs` — 30-gate GBT audit, 8
  open `#[ignore]` BUG/MISSING tests from prior wave.
- `crates/consensus/tests/test_w123_mining_gbt.rs` — 30-gate W123 audit,
  20 open `#[ignore]` BUG/MISSING tests from prior wave.

---

## Gate matrix (32 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | resetBlock initial counters | G1: `nBlockWeight = block_reserved_weight` | PASS (`block_template.rs:314-315`) |
| 1 | … | G2: `nBlockSigOpsCost = coinbase_output_max_additional_sigops` (Core default 400) | **BUG-1 (P1)** — `coinbase_sigop_reserve: u64 = 0` (block_template.rs:323), no `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400` reservation; block template can over-pack sigops vs Core |
| 2 | ClampOptions | G3: `block_reserved_weight ∈ [MINIMUM_BLOCK_RESERVED_WEIGHT(2000), MAX_BLOCK_WEIGHT]` | **BUG-2 (P1)** — `BlockTemplateConfig` has NO clamp helper; caller passing `max_weight > MAX_BLOCK_WEIGHT` results in `block_reserved_weight = MAX_BLOCK_WEIGHT.saturating_sub(max_weight) = 0`, violating `MINIMUM_BLOCK_RESERVED_WEIGHT` |
| 2 | … | G4: `nBlockMaxWeight ∈ [block_reserved_weight, MAX_BLOCK_WEIGHT]` | **BUG-3 (P2)** — no clamp; `max_weight = 0` causes loop to admit no transactions silently |
| 3 | Transaction selection (addPackageTxs / addChunks) | G5: chunk-based selection via mempool's `GetBlockBuilderChunk` | **BUG-4 (P0-CDIV)** — `get_sorted_for_mining` returns a FLAT txid list sorted by single-tx ancestor_fee_rate (mempool.rs:2340-2365), not Core's cluster-aware chunks (`m_mempool->GetBlockBuilderChunk(selected_transactions)`, miner.cpp:293). A 3-tx cluster (parent + two children with CPFP) is treated as 3 independent priorities rather than a single chunk |
| 3 | … | G6: topological ordering enforced (parent-before-child in block) | **BUG-5 (P0-CDIV)** — comment at block_template.rs:1262 admits "In our simplified implementation, we don't enforce strict topological order during selection." If a child precedes its parent in `template.transactions`, the assembled block fails block-validation `missing-inputs` (parent UTXO not yet in view); template silently produces an unminable block |
| 3 | … | G7: blockMinFeeRate STOP (not skip) on first below-floor chunk | PASS (`block_template.rs:383-385` uses `break`) |
| 3 | … | G8: blockMinFeeRate units = sat per kvB (Core CFeeRate{1} = 0.001 sat/vB) | **BUG-6 (P1)** — `block_min_fee_rate: 1.0` (block_template.rs:177) with comment "1 sat/vbyte (Bitcoin Core DEFAULT_BLOCK_MIN_TX_FEE)". Core's `DEFAULT_BLOCK_MIN_TX_FEE = 1` is fed to `CFeeRate{1}` whose constructor takes **sat per kvB** (feerate.h:41). Rustoshi's floor is **1000× higher** than Core's (1 sat/vB vs 0.001 sat/vB). Mempool entries Core would mine, rustoshi rejects |
| 3 | … | G9: weight strict-`>=` cap uses `m_options.nBlockMaxWeight` (clamped to MAX_BLOCK_WEIGHT) | **BUG-7 (P2)** — `weight_fails = total_weight + priority.weight >= MAX_BLOCK_WEIGHT` (block_template.rs:393). Compares against ABSOLUTE ceiling (4_000_000) instead of `max_weight` (= MAX_BLOCK_WEIGHT - block_reserved_weight, 3_992_000 default). Double-subtracts the reservation; carry-forward W108 G8 still open |
| 3 | … | G10: MAX_CONSECUTIVE_FAILURES=1000 + BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000 bail | PASS (`block_template.rs:423-427`) |
| 4 | Coinbase construction | G11: BIP-34 height encoding via `CScript() << nHeight` | PASS (`encode_coinbase_height`, block_template.rs:682-710) |
| 4 | … | G12: bad-cb-length minimum 2 bytes (append OP_0 at h≤16) | PASS (`block_template.rs:579-581`) |
| 4 | … | G13: bad-cb-length maximum 100 bytes (caller-controlled extra_data) | **BUG-8 (P1)** — `build_coinbase_tx` (block_template.rs:558-629) does not check `coinbase_script.len() <= 100`. With operator-controlled `coinbase_extra_data` (W120 wishlist) or a 95-byte pool tag, the assembled coinbase fails `bad-cb-length` (validation.rs:425-427). Build silently produces an unminable block; the docstring at line 138-139 promises "Max 100 bytes total in coinbase scriptSig" but is not enforced |
| 4 | … | G14: `nLockTime = nHeight - 1` (anti-fee-sniping) | PASS (`block_template.rs:609`) |
| 4 | … | G15: `nSequence = MAX_SEQUENCE_NONFINAL` (0xFFFFFFFE) | PASS (`block_template.rs:619`) |
| 4 | … | G16: coinbase value = subsidy + total_fees from chainparams subsidy schedule | PARTIAL — `block_subsidy(height, params.subsidy_halving_interval)` (block_template.rs:453) is correct; but `crates/storage/src/indexes/coinstatsindex.rs:295` hardcodes `HALVING_INTERVAL: u32 = 210_000` in parallel helper (W145 BUG-3 carry-forward, ~3 weeks open) |
| 5 | Witness commitment (BIP-141) | G17: commitment added iff segwit-active at this height (Core: `DeploymentActiveAfter(prev, *this, DEPLOYMENT_SEGWIT)`) | **BUG-9 (P0-CDIV-MINER)** — gated on `has_witness = txs.iter().any(|tx| tx.has_witness())` (block_template.rs:586,598), NOT on `params.is_segwit_active(height)`. **(W142 BUG-13 carry-forward, 4th instance — W108+W123 regression tests still on disk at `tests/test_w108_gbt.rs:502` and `tests/test_w123_mining_gbt.rs:G3`, ignored 6+ weeks.)** On a segwit-active chain with an empty mempool or all-non-witness txs, the coinbase has NO witness commitment → assembled block fails `bad-witness-merkle-match` |
| 5 | … | G18: witness-nonce in coinbase scriptWitness stack[0] = 32 zero bytes, gated on segwit-active | **BUG-9 cross-cite** — witness nonce is added iff `has_witness` (block_template.rs:620-624), same shape as G17 |
| 5 | … | G19: commitment script = `OP_RETURN || PUSH_36 || 0xaa21a9ed || SHA256d(witness_root || nonce)` (38 bytes) | PASS (`build_witness_commitment`, block_template.rs:635-664) |
| 5 | … | G20: `BlockWitnessMerkleRoot` correctly treats coinbase wtxid as 32 zero bytes | PASS (`block_template.rs:641-642`) |
| 5 | … | G21: `RegenerateCommitments` called when mempool changes / custom_txs replace | **BUG-10 (P0-CDIV-MINER)** — `mine_single_block` (server.rs:9452-9461): when `custom_txs` replaces the mempool-selected txs, the merkle root is recomputed but the **witness commitment in the existing coinbase is NOT regenerated**. The commitment hash references `selected_txs` from the original mempool call which were just dropped at line 9454-9456. If `custom_txs` contains a witness tx the block fails `bad-witness-merkle-match`; if it doesn't, the commitment still references stale txs |
| 6 | Timestamp + nBits + nVersion | G22: `pblock->nTime = NodeClock::now()` then `UpdateTime` clamps to `max(GetMinimumTime, NodeClock::now)` | **BUG-11 (P1)** — `get_block_template` (server.rs:4071-4074) uses `SystemTime::now()` directly; **no clamp** to `max(now, MTP+1)`. If the system clock is behind the parent's MTP, the assembled template's `nTime` is < MTP+1 and validation rejects with `time-too-old`. Core's `UpdateTime` (miner.cpp:49-57) explicitly clamps |
| 6 | … | G23: `GetMinimumTime` always-on BIP-94 timewarp clamp at retarget boundaries (all networks) | **BUG-12 (P1)** — `mintime` in GBT response (server.rs:4316) is simply `(median_time_past + 1) as u32`. Core's `GetMinimumTime` (miner.cpp:36-47) additionally enforces `max(MTP+1, prev.BlockTime - MAX_TIMEWARP)` at retarget boundaries on ALL networks (BIP-94 always-on for miners as future-proofing). Rustoshi's mintime can be lower than Core's at the boundary; miner templates may build blocks rejected on testnet4/regtest |
| 6 | … | G24: `nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus())` with versionbits cache + chain context | **BUG-13 (P2)** — `build_block_template` (block_template.rs:487-509) calls `compute_block_version::<NoBlock>(None, &pairs, None)` whose `get_state_for(None, …)` returns `Defined` for any deployment with non-special start_time (versionbits.rs:299-302). Result: `version` is always `VERSIONBITS_TOP_BITS = 0x20000000` regardless of any STARTED/LOCKED_IN deployment. **Production miners never signal new soft-fork bits via BIP-9 / BIP-320 version-rolling.** `get_block_template`'s `gbt_vbavailable` (server.rs:4284-4300) is also forever empty (same `NoBlock` issue) — `vbavailable` map MUST report STARTED/LOCKED_IN deployments per BIP-9 to coordinate miner signaling |
| 6 | … | G25: `-blockversion=N` regtest override (Core miner.cpp:143-144) | **BUG-14 (P3)** — no `-blockversion` CLI flag; regtest soft-fork testing harnesses (e.g. forktest) cannot exercise version-bit roll-out paths |
| 7 | GBT request parsing (BIP-22/23) | G26: parse `mode` field, dispatch `"proposal"` to `TestBlockValidity` | **BUG-15 (P2)** — `_params` is a dead parameter (server.rs:4067); no mode parsing. BIP-23 proposal-mode unsupported. (W108 G4/G5 carry-forward) |
| 7 | … | G27: require `"segwit"` in `rules` array (Core mining.cpp:854-857) | **BUG-16 (P2)** — no rules validation; client may omit "segwit" and still receive a template, in violation of BIP-23. (W108 G1 carry-forward) |
| 7 | … | G28: `longpollid = tip.hex + decimal(nTransactionsUpdatedLast)` | **BUG-17 (P2)** — `longpollid: format!("{}:{}", state.best_hash.to_hex(), state.best_height)` (server.rs:4311). Format wrong: uses `:` separator AND height counter instead of decimal nTransactionsUpdatedLast. Long-polling miners that parse the suffix to detect template changes never see mempool-only changes. (W108 G3 carry-forward) |
| 7 | … | G29: terminal `TestBlockValidity` on assembled template (Core miner.cpp:223-228) | **BUG-18 (P2)** — `build_block_template` never validates the assembled block before returning; a build_block_template bug (wrong BIP-34 height, malformed witness commitment, sigops over-count) reaches the miner unchecked. Only the `mine_single_block` path routes through `process_block` after PoW is found (server.rs:9509) |
| 8 | GBT response fields | G30: `sigoplimit/sizelimit/=WITNESS_SCALE_FACTOR` and skip `weightlimit` when pre-segwit | **BUG-19 (P3)** — `sigoplimit: 80000`, `sizelimit: 4000000`, `weightlimit: 4000000` are hardcoded constants (server.rs:4319-4321). Pre-segwit case never specially handled; on a hypothetical pre-segwit fork the GBT response is wrong per Core mining.cpp:1009-1019. Acceptable for live networks where segwit is active |
| 8 | … | G31: `default_witness_commitment` only when commitment present + segwit-active | PARTIAL — server.rs:4215-4231 gates on `state.params.is_segwit_active(new_height)`, but the coinbase commitment itself was built with `has_witness` gate (BUG-9 cross-cite). Result: at a segwit-active height with empty mempool, `default_witness_commitment` is `None` because the coinbase has no commitment — miners receive no commitment to splice |
| 9 | Mining RPCs / mempool config | G32: production mempool created with `MempoolConfig::production()` (verify_scripts: true) | **BUG-20 (P0-SEC)** — `rpc/src/server.rs:172, 199` constructs the production mempool via `Mempool::new(MempoolConfig::default())`. `MempoolConfig::default()` sets `verify_scripts: false` (mempool.rs:747). Carry-forward of **W150 BUG-2 P0-SEC** ("`verify_scripts: false` production default"). The block-builder selects from this unverified mempool; a tx admitted by the bypassed gate becomes part of an assembled block. The miner wastes work mining an invalid block (which validation rejects → loss of subsidy + fees and an invalid block broadcast to peers) |

---

## BUG-1 (P1) — `coinbase_output_max_additional_sigops` reservation absent

**Severity:** P1. Bitcoin Core's `BlockAssembler::resetBlock` sets
`nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`
(miner.cpp:115), where the default `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS
= 400` (policy.h:29). This reserves a 400-sigop budget for whatever
sigop-bearing scripts the coinbase output may contain (typical pools use
P2WPKH coinbase outputs with multiple OP_CHECKSIGADD or paymail commitment
schemes, etc.). The selection loop then admits txs only until the
combined block sigops + this reservation hits `MAX_BLOCK_SIGOPS_COST`.

rustoshi (`block_template.rs:323`) hard-codes:

```rust
let coinbase_sigop_reserve: u64 = 0;
let mut total_sigops: u64 = coinbase_sigop_reserve;
```

No reservation. The selection loop admits txs up to the full 80,000 cap.
After selection, the actual coinbase sigops are recomputed (line 472-478)
and the placeholder is swapped out — but if the actual coinbase carries
≥ 1 sigop, the swap can push `total_sigops` over `MAX_BLOCK_SIGOPS_COST`.
Validation then rejects the assembled block.

**File:** `crates/consensus/src/block_template.rs:316-324, 472-478`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:114-115`,
`bitcoin-core/src/policy/policy.h:29`.

**Impact:** rare-but-real: a pool with a sigop-rich coinbase output (e.g.
multi-sig PoW commitments or zk-rollup operator key sets in a witness
script) can mine an over-sigops block. Loss of the block + reward.

---

## BUG-2 (P1) — No `ClampOptions` equivalent; `block_reserved_weight` can be 0

**Severity:** P1. Bitcoin Core's `ClampOptions` (miner.cpp:79-88) enforces:

```cpp
options.block_reserved_weight = std::clamp<size_t>(
    options.block_reserved_weight.value_or(DEFAULT_BLOCK_RESERVED_WEIGHT),
    MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT);
options.nBlockMaxWeight = std::clamp<size_t>(
    options.nBlockMaxWeight, *options.block_reserved_weight, MAX_BLOCK_WEIGHT);
```

Both knobs are clamped at construction. The `MINIMUM_BLOCK_RESERVED_WEIGHT
= 2000` lower bound is critical: it guarantees the coinbase + tx-count
varint + block header (≥ 1200 weight units) always fits, even when the
operator passes hostile `-blockreservedweight=0` or large
`-blockmaxweight=4_000_000` values.

rustoshi's `BlockTemplateConfig::default` (block_template.rs:164-181)
hard-codes `max_weight: MAX_BLOCK_WEIGHT - DEFAULT_BLOCK_RESERVED_WEIGHT`
but offers no `clamp_options` helper and no validation for caller-provided
config. The `build_block_template` body derives:

```rust
let block_reserved_weight = MAX_BLOCK_WEIGHT.saturating_sub(config.max_weight);
```

— if a caller passes `max_weight = MAX_BLOCK_WEIGHT` (or anything > the
ceiling), `block_reserved_weight = 0`. The header+coinbase will then
overflow the configured budget mid-selection, and the assembled block
violates `MAX_BLOCK_WEIGHT` at validation.

**File:** `crates/consensus/src/block_template.rs:135-181, 314-315`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:79-88`,
`bitcoin-core/src/policy/policy.h:34` (MINIMUM_BLOCK_RESERVED_WEIGHT).

**Impact:** misconfigured templates produce oversized or undersized blocks.
The constant `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000` is even already
imported (block_template.rs:67) — defined but not consulted (dead-data
plumbing).

---

## BUG-3 (P2) — `max_weight = 0` admits no transactions silently

**Severity:** P2. Cross-fold of BUG-2. If a caller passes
`BlockTemplateConfig { max_weight: 0, .. }`, then
`block_reserved_weight = MAX_BLOCK_WEIGHT - 0 = 4_000_000` and
`total_weight: u64 = 4_000_000` at line 315. The selection loop's
`weight_fails = 4_000_000 + priority.weight >= MAX_BLOCK_WEIGHT` is **always
true**: the template is empty (coinbase only). No error reported.

Core's `ClampOptions` rejects `nBlockMaxWeight < block_reserved_weight`
implicitly via the clamp upper-bound, so a 0-config is never reached.

**File:** `crates/consensus/src/block_template.rs:314-315, 393`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:79-88`.

**Impact:** silent empty-template footgun for misconfigured callers.

---

## BUG-4 (P0-CDIV) — Selection is flat-sorted txid list, not cluster chunks

**Severity:** P0-CDIV. Bitcoin Core's `BlockAssembler::addChunks`
(miner.cpp:279-334) iterates over the mempool's cluster-aware chunk
builder:

```cpp
chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
// ... selected_transactions holds an entire topologically-sorted chunk
// (parent + descendants) at the highest effective chunk feerate.
```

The `GetBlockBuilderChunk` API returns a complete cluster prefix: all
transactions in a chunk are admitted (or skipped) atomically, with a single
`chunk_feerate = (sum_fees, sum_size)`. This correctly handles CPFP:
a low-fee parent with a high-fee child is selected as a single chunk whose
combined feerate determines inclusion, AND topological ordering is
guaranteed by the chunk's own sorting.

rustoshi's `get_sorted_for_mining` (mempool.rs:2340-2365):

```rust
pub fn get_sorted_for_mining(&self) -> Vec<Hash256> {
    // ... per-entry ancestor_fee_rate, sort flat by f64 ...
    entries.into_iter().map(|(_, txid)| txid).collect()
}
```

Returns a **flat** vector of txids, sorted by **per-entry**
`ancestor_fee_rate`. The selection loop in `build_block_template`
(block_template.rs:330-450) pops one txid at a time, applies the
weight/sigops check to **that single tx**, and either includes it or
skips. There is no chunk concept; a parent and child are processed
independently.

Two concrete divergences:

1. **CPFP under-inclusion**: a parent with fee 0 + child with fee 100,000
   has the child's `ancestor_fee_rate ≈ (0+100000)/(parent_size+child_size)`
   which ranks high. But popping the **child** first triggers a missing
   parent (the parent is never selected because its standalone
   `ancestor_fee_rate = 0/parent_size = 0` is below `block_min_fee_rate
   = 1.0`). Core selects them as a single chunk and includes both.
2. **Topological ordering**: child can appear in `template.transactions`
   BEFORE its parent, even when both are individually high-feerate.
   See BUG-5.

**File:** `crates/consensus/src/block_template.rs:328-450`;
`crates/consensus/src/mempool.rs:2340-2365`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-334`
(addChunks → GetBlockBuilderChunk).

**Impact:** lower miner revenue (CPFP packages dropped silently); produced
blocks may fail validation due to ordering (see BUG-5).

---

## BUG-5 (P0-CDIV) — Comment-as-confession: "we don't enforce topological order"

**Severity:** P0-CDIV. Bitcoin block consensus requires that when a tx in
block N spends an output of a tx in block N (same-block spend), the
**spender appears after the spent** in `block.vtx`. This is enforced by
`Consensus::CheckTxInputs` walking the UTXO view: a spent UTXO must exist
in the view at the time of the spend, and same-block-tx outputs are added
to the view in `block.vtx` order during connect-block.

rustoshi's test_transactions_in_topological_order (`block_template.rs:1204-
1266`) ends with:

```rust
// Note: In our simplified implementation, we don't enforce strict topological
// order during selection. A more complete implementation would ensure
// parents come before children. For now, we just verify both are included.
// The actual block validation would catch ordering issues.
```

This is a **comment-as-confession** pattern (8th fleet instance tracked
in W141..W145). The build_block_template selection loop pops txids by
fee-rate order; if a child's `ancestor_fee_rate` exceeds its parent's,
the child gets popped first and inserted at index N in `template.transactions`,
and the parent at index N+1 — assembled block fails validation with
`bad-txns-inputs-missingorspent` on the child's input.

Empirical effect: a CPFP package with child-feerate ≫ parent-feerate is
near-certain to violate. Tests skip this by happening to pop the parent
first (random tiebreak on f64).

**File:** `crates/consensus/src/block_template.rs:1262-1266`,
selection loop at lines 372-450.

**Core ref:** `bitcoin-core/src/node/miner.cpp:262-277, 279-334`
(AddToBlock per-chunk preserves the chunk's internal topological order).

**Impact:** templates with CPFP packages produce blocks that fail
validation. Miner wastes work, loses subsidy + fees. The "block
validation would catch ordering issues" line in the comment is exactly
the loss vector: catch happens after PoW, not before.

---

## BUG-6 (P1) — `block_min_fee_rate` units mis-documented; 1000× higher floor than Core

**Severity:** P1. Bitcoin Core's `DEFAULT_BLOCK_MIN_TX_FEE = 1` is fed
to `CFeeRate{1}` whose constructor takes **sat per kvB** (`feerate.h:41`:
`explicit CFeeRate(const I m_feerate_kvb) : m_feerate(FeePerVSize(m_feerate_kvb, 1000)) {}`).
So Core's default mining floor is **1 sat per 1000 vBytes = 0.001 sat/vB**.

rustoshi's `BlockTemplateConfig::default` (block_template.rs:175-178):

```rust
// DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/vbyte (Bitcoin Core DEFAULT_BLOCK_MIN_TX_FEE).
// See Bitcoin Core policy.h `DEFAULT_BLOCK_MIN_TX_FEE`.
block_min_fee_rate: 1.0,
```

The comment is wrong — Core's `1` is sat/kvB, not sat/vB. The `1.0` value
treated as sat/vB means rustoshi's miner rejects any tx below 1 sat/vB,
while Core mines down to 0.001 sat/vB. On mainnet today this is mostly
academic (almost no tx pays < 1 sat/vB), but on regtest / testnet
benchmark scripts, rustoshi misses orders of magnitude more transactions
than Core would.

**File:** `crates/consensus/src/block_template.rs:151-153, 176-177`
(comment); used at line 383 as the gate.

**Core ref:** `bitcoin-core/src/policy/policy.h:36` (constant);
`bitcoin-core/src/policy/feerate.h:41` (CFeeRate constructor units).

**Impact:** rustoshi miner has 1000× higher fee floor than Core; cross-impl
divergence on near-zero-fee testnet/regtest workloads.

---

## BUG-7 (P2) — Weight cap compares to `MAX_BLOCK_WEIGHT`, ignoring caller's `max_weight`

**Severity:** P2. Bitcoin Core's `TestChunkBlockLimits` (miner.cpp:241):

```cpp
if (nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight) {
    return false;
}
```

Compares against the post-ClampOptions `nBlockMaxWeight`, which respects
`-blockmaxweight`.

rustoshi (block_template.rs:393):

```rust
let weight_fails = total_weight + priority.weight >= MAX_BLOCK_WEIGHT;
```

Compares against the absolute ceiling. A caller setting `max_weight =
2_000_000` would expect a 2 MB target block (e.g. for low-latency
propagation), but the selection loop instead admits txs up to the full
4 MB cap. Result: the produced block exceeds the operator-configured
size, and `max_weight` is silently a dead parameter — the only knob that
actually matters in selection is `MAX_BLOCK_WEIGHT`.

W108 G8 documents the same bug (open `#[ignore]` test for ~3 weeks).

**File:** `crates/consensus/src/block_template.rs:393`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:241`.

**Impact:** `-blockmaxweight` CLI semantics (BUG-21) and any pool-side
custom `max_weight` are silently ignored at the upper bound; oversized
blocks compared to operator intent.

---

## BUG-8 (P1) — Coinbase scriptSig max-length (100 bytes) not enforced at build

**Severity:** P1. Bitcoin Core consensus rule `bad-cb-length` (tx_check.cpp:49):
`scriptSig.size()` must be in `[2, 100]`. rustoshi enforces this at
validation (validation.rs:425-427) but NOT at build:

```rust
// block_template.rs:572-583 — build_coinbase_tx
let mut coinbase_script = Vec::new();
let height_bytes = encode_coinbase_height(height);
coinbase_script.extend_from_slice(&height_bytes);
if height >= 1 && height <= 16 {
    coinbase_script.push(0x00); // OP_0 dummy extranonce
}
coinbase_script.extend_from_slice(extra_data);
// MISSING: assert!(coinbase_script.len() <= 100, "bad-cb-length: scriptSig must be ≤ 100 bytes");
```

`BlockTemplateConfig::coinbase_extra_data` is operator/caller-supplied,
defaulting to `b"/rustoshi/"` (10 bytes) but capped at … nothing. The
docstring at line 138-139 says:

```rust
/// Extra data to include in coinbase (e.g., pool name).
/// Max 100 bytes total in coinbase scriptSig.
pub coinbase_extra_data: Vec<u8>,
```

— but no code enforces the cap. A pool wanting to embed an OP_RETURN-style
identifier (e.g. SHA1-rev signature, paymail commitment) longer than ~95
bytes silently produces an unminable block.

**File:** `crates/consensus/src/block_template.rs:558-629` (build_coinbase_tx
has no length check); cross-cite docstring promise at line 139.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:49` (consensus rule);
implicit upper bound at miner.cpp:186 enforced via TestBlockValidity at
line 225 (Core's terminal validity check would catch the overshoot).

**Impact:** miner builds an over-100-byte coinbase, hits validation, loses
subsidy + fees. Combined with BUG-18 (no terminal TestBlockValidity in
rustoshi), the broken template reaches the GBT-consuming miner without any
gate firing.

---

## BUG-9 (P0-CDIV-MINER) — Witness commitment gated on `has_witness`, not on segwit-active

**Severity:** P0-CDIV-MINER (**W142 BUG-13 carry-forward — 4th instance,
W108 G11 / W123 G3 regression tests still on disk and `#[ignore]`d for
6+ weeks**). Bitcoin Core's `ChainstateManager::GenerateCoinbaseCommitment`
(validation.cpp:3997-4019) **always** adds the OP_RETURN 0xaa21a9ed
commitment output when none exists AND segwit is active for the prev
block (`commitpos == NO_WITNESS_COMMITMENT` check at line 3999, segwit
gate in `UpdateUncommittedBlockStructures` at line 3989). The commitment
references the witness merkle root where coinbase wtxid = 32 zero bytes,
regardless of whether any non-coinbase tx has witness data.

rustoshi's `build_coinbase_tx` (block_template.rs:586-604):

```rust
// Check if any transaction has witness data
let has_witness = selected_txs.iter().any(|tx| tx.has_witness());
// ...
if has_witness {
    let commitment = build_witness_commitment(selected_txs, &witness_nonce);
    outputs.push(TxOut { value: 0, script_pubkey: commitment });
}
```

And the matching witness-nonce gate at lines 619-624:

```rust
witness: if has_witness {
    vec![witness_nonce]
} else {
    vec![]
},
```

On a segwit-active chain with an **empty mempool or all-legacy txs in
the template**, `has_witness = false`, no commitment is added. The block
is then mined and broadcast WITHOUT the required witness commitment.
Validation by any other node rejects with `bad-witness-merkle-match`.

**Multiple "consensus pipelines" pattern**: rustoshi has three witness-
commitment definitions across `build_witness_commitment` (block_template.rs:635),
the validation-side `check_witness_commitment` (validation.rs), and the
RPC-side commitment-extraction at server.rs:4218-4228. The third
correctly gates on `state.params.is_segwit_active(new_height)`, but
extracts from the second-coinbase-output that the FIRST may not have
created — net result is that even RPC-side gating cannot recover the
missing commitment.

**File:** `crates/consensus/src/block_template.rs:586-604, 619-624`.

**Core ref:** `bitcoin-core/src/validation.cpp:3985-4019` (segwit-active
gate at line 3989); `bitcoin-core/src/consensus/validation.h:147-164`
(`GetWitnessCommitmentIndex` always scans the coinbase).

**Impact:** **chain-split candidate on testnet4/regtest** where segwit is
active from height 1 and an empty mempool template (the common case for
generatetoaddress runs) produces a coinbase with NO commitment. Block
fails validation at every other rustoshi node AND every Core node.

---

## BUG-10 (P0-CDIV-MINER) — `mine_single_block` custom_txs path does not regenerate witness commitment

**Severity:** P0-CDIV-MINER. `generate_block` RPC accepts an explicit
list of hex-encoded transactions; the handler routes through
`mine_block_with_txs` → `mine_single_block(..., custom_txs=Some(txs), ...)`.
At server.rs:9452-9461:

```rust
if let Some(txs) = custom_txs {
    // Keep the coinbase, add custom transactions
    let coinbase = template.transactions.remove(0);
    template.transactions = vec![coinbase];
    template.transactions.extend(txs);

    // Recompute merkle root
    let merkle_root = compute_merkle_root(&template.transactions);
    template.header.merkle_root = merkle_root;
}
```

The **txid merkle root** is recomputed, but the **witness commitment**
embedded in the existing coinbase (`template.coinbase_tx` / `template.
transactions[0]`) was constructed against the ORIGINAL `selected_txs`
which were just dropped at the `remove(0)` + `extend` lines. The coinbase
output at index 1 still contains the stale commitment hash.

Two failure modes:
1. **custom_txs contains witness txs** — commitment hash references
   non-existent wtxids; block rejected `bad-witness-merkle-match`.
2. **custom_txs are all-legacy** — commitment hash references the OLD
   selected_txs (which may have been witness txs); block rejected
   `bad-witness-merkle-match`.

The fee accounting is also stale: `template.coinbase_tx.outputs[0].value`
includes the fees from the original `selected_txs`, not from `custom_txs`.
If the totals differ, the block is `bad-cb-amount`. The chain_state
process_block call at line 9509 then rejects, losing the block.

Core handles this via `RegenerateCommitments` (miner.cpp:67-77):

```cpp
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman) {
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);
    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, ...);
    chainman.GenerateCoinbaseCommitment(block, prev_block);
    block.hashMerkleRoot = BlockMerkleRoot(block);
}
```

— removes the existing commitment, recomputes from the new tx set,
re-emits. rustoshi has no equivalent path.

**File:** `crates/rpc/src/server.rs:9451-9461`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77` (`RegenerateCommitments`).

**Impact:** `generate_block` regtest RPC is broken whenever `transactions`
arg is non-empty and contains any witness tx; the block fails validation.
Regression test harnesses that call `generateblock <addr> ["<hex_wtx>"]`
silently fail with a confusing `bad-witness-merkle-match`.

---

## BUG-11 (P1) — `getblocktemplate` does not clamp `nTime` to `max(NodeClock::now, MTP+1)`

**Severity:** P1. Bitcoin Core's `UpdateTime` (miner.cpp:49-57):

```cpp
int64_t nNewTime{std::max<int64_t>(
    GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
    TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};
if (nOldTime < nNewTime) {
    pblock->nTime = nNewTime;
}
```

`nTime` is set to `max(GetMinimumTime, NodeClock::now())`. If the system
clock is behind the parent's MTP+1 (e.g. clock-skew, miner-time hop on
testnet, NTP catastrophe), `nNewTime` is bumped to `GetMinimumTime`.

rustoshi's `get_block_template` (server.rs:4071-4074):

```rust
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u32;
```

No clamp. If `timestamp < median_time_past + 1`, the assembled template's
`header.timestamp` is `< MTP+1` and consensus validation rejects with
`time-too-old` (validation.rs reject token; Core: `BlockTimeTooOld`).
The GBT response also reports `mintime = MTP+1` (correctly) but
`curtime = timestamp` (possibly below mintime). A naive miner would mine
the broken `curtime`.

**File:** `crates/rpc/src/server.rs:4071-4074`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-57` (UpdateTime clamp).

**Impact:** clock-skewed mining hosts produce templates that fail
validation. No graceful degradation; the miner loses work indefinitely
until the clock catches up.

---

## BUG-12 (P1) — `mintime` skips BIP-94 timewarp clamp at retarget boundaries

**Severity:** P1. Bitcoin Core's `GetMinimumTime` (miner.cpp:36-47):

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev,
                       const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(
            min_time,
            pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

At retarget boundaries (h ≡ 0 mod 2016), the minimum block time is
`max(MTP+1, prev.BlockTime - MAX_TIMEWARP)`. BIP-94 (timewarp fix) is
applied here as future-proofing on ALL networks (mainnet, testnet3,
testnet4, signet, regtest) regardless of `enforce_bip94`.

rustoshi's `get_block_template` (server.rs:4316):

```rust
mintime: (median_time_past + 1) as u32,
```

Only the MTP+1 half. At retarget boundaries on testnet4 (where
`enforce_bip94 = true`), a block built at the rustoshi `mintime` may
violate the consensus BIP-94 clamp and be rejected. On other networks
the rule is not consensus-enforced (yet), but the miner-side guard is.

**File:** `crates/rpc/src/server.rs:4316`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47` (GetMinimumTime).
`crates/consensus/src/params.rs:213` (MAX_TIMEWARP defined but only used
in pow.rs retarget, never in miner.rs / block_template.rs).

**Impact:** at retarget boundaries on testnet4 (every 2016 blocks),
miners building from rustoshi's GBT response may produce blocks below the
BIP-94 clamp. Block rejected; miner loses work. `MAX_TIMEWARP=600` constant
exists in params.rs but never imported into block_template.rs — dead-data
plumbing.

---

## BUG-13 (P2) — `ComputeBlockVersion` produces only `VERSIONBITS_TOP_BITS` (no soft-fork signaling)

**Severity:** P2. Bitcoin Core's `BlockAssembler::CreateNewBlock` (miner.cpp:140):

```cpp
pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache
    .ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
```

Uses the per-chain versionbits cache and the parent block index to OR in
deployment bits for every STARTED or LOCKED_IN deployment. Miners then
naturally signal active soft-forks (e.g. taproot during the 2021 mainnet
rollout: bit 2 set on every produced block).

rustoshi's `build_block_template` (block_template.rs:484-509):

```rust
let block_version = config.block_version.unwrap_or_else(|| {
    struct NoBlock;
    impl VersionbitsBlockInfo for NoBlock {
        fn height(&self) -> u32 { unreachable!() }
        // ...
    }
    let deployments_map = get_deployments(params);
    let pairs: Vec<(&DeploymentId, &BIP9Deployment)> = deployments_map.iter().collect();
    compute_block_version::<NoBlock>(None, &pairs, None)
});
```

Calls `compute_block_version(None, ..., None)`. The cascade:
1. `compute_block_version` iterates deployments and calls `get_state_for(None, deployment, None)`.
2. `get_state_for(None, ..., ...)` returns `ThresholdState::Defined`
   (versionbits.rs:299-302) for any deployment with non-special start_time.
3. The OR-in branch (`Started | LockedIn`) is never taken.
4. Final version = `VERSIONBITS_TOP_BITS = 0x20000000`.

**Production effect**: rustoshi miners never signal any soft-fork bit
via BIP-9. The `gbt_vbavailable` map in `get_block_template`
(server.rs:4284-4300) is built via the same `get_state_for::<NoBlock>(None, ...)`
path and is therefore **forever empty**, regardless of whether the chain
has active STARTED/LOCKED_IN deployments. Mining pools relying on
`vbavailable` to drive signaling never see bits to set.

Callers can override via `BlockTemplateConfig::block_version: Some(v)`,
but both production sites (`get_block_template` at server.rs:4164-4167
and `mine_single_block` at server.rs:9435-9438) use
`..Default::default()` and leave `block_version: None`.

**File:** `crates/consensus/src/block_template.rs:484-509`;
`crates/rpc/src/server.rs:4164-4167, 9435-9438, 4284-4300`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:140`
(ComputeBlockVersion with chain context).

**Impact:** rustoshi miners cannot signal soft-fork activation; rustoshi
GBT responses cannot advertise BIP-9 bits to client miners. Any future
soft-fork rollout via BIP-9 is dead-on-arrival from a rustoshi miner.

---

## BUG-14 (P3) — `-blockversion=N` regtest override missing

**Severity:** P3. Bitcoin Core's `BlockAssembler::CreateNewBlock`
(miner.cpp:141-145):

```cpp
if (chainparams.MineBlocksOnDemand()) {
    pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
}
```

On regtest only, `-blockversion=N` overrides the computed nVersion. Used
by integration tests to mine blocks with specific version bits set
(e.g. to exercise BIP-9 rollouts in tests).

rustoshi has no `-blockversion` CLI flag and no per-call override knob.

**File:** `crates/rpc/src/server.rs` (CLI args), `crates/consensus/src/block_template.rs:155-161`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:141-145`.

**Impact:** rustoshi cannot reproduce Core's `bitcoind -regtest -blockversion=4`
test harness pattern; BIP-9 rollout regression tests cannot be automated
against rustoshi.

---

## BUG-15 (P2) — `getblocktemplate` `_params` is a dead parameter (no mode / rules / longpollid parse)

**Severity:** P2 (W108 G1 / G4 / G5 carry-forward, ~6 weeks open).
Bitcoin Core's `getblocktemplate` (mining.cpp:846-870) parses
`request.params[0]` as a JSON object with fields:
- `mode` ∈ {"template", "proposal"} — proposal mode runs
  `TestBlockValidity` and returns BIP-22 result string instead of a template.
- `rules` array — MUST contain "segwit"; throws `RPC_INVALID_PARAMETER`
  otherwise (mining.cpp:854-857).
- `longpollid` — for long-polling.
- `capabilities` — BIP-22 client capabilities (`coinbasetxn`,
  `coinbasevalue`, `workid`, etc.).

rustoshi (server.rs:4065-4068):

```rust
async fn get_block_template(
    &self,
    _params: Option<serde_json::Value>,
) -> RpcResult<serde_json::Value> {
```

The underscore prefix advertises the dead-parameter status. No mode
parse, no rules enforcement, no longpollid, no capabilities. A client
omitting `rules: ["segwit"]` still receives a template, in violation of
BIP-23.

**File:** `crates/rpc/src/server.rs:4065-4068`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:846-870`.

**Impact:** miners using rustoshi cannot use proposal mode (test a block
before mining), cannot use longpolling effectively (see BUG-17), and the
"segwit" rule precondition is never enforced.

---

## BUG-16 (P2) — `rules` array `"segwit"` precondition not enforced (BIP-23)

**Severity:** P2. Cross-cite of BUG-15. Core mining.cpp:854-857:

```cpp
const UniValue& aClientRules = oparam.find_value("rules");
if (aClientRules.isArray()) {
    for (unsigned int i = 0; i < aClientRules.size(); ++i) {
        const UniValue& v = aClientRules[i];
        setClientRules.insert(v.get_str());
    }
}
// ... later:
if (!setClientRules.count("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the segwit rule set ...");
}
```

Without this gate, a pre-segwit-aware client would receive a template
with segwit transactions in it, fail to handle them, and either reject
or produce a malformed block.

**File:** `crates/rpc/src/server.rs:4065-4068` (no parse).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:854-857`.

**Impact:** legacy-only mining clients silently receive segwit templates;
no protection against rolling old client software against a segwit-active
chain.

---

## BUG-17 (P2) — `longpollid` format wrong (uses `:height` instead of `<decimal_tx_counter>`)

**Severity:** P2 (W108 G3 carry-forward). Bitcoin Core (mining.cpp:1002):

```cpp
result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

Format: `<64-hex-tip-hash><decimal-tx-update-counter>`. Both halves of
the longpollid change when the template's underlying assumptions change:
the tip hash on a new block, the counter on any mempool admit/evict.

rustoshi (server.rs:4311):

```rust
longpollid: format!("{}:{}", state.best_hash.to_hex(), state.best_height),
```

Wrong format AND wrong second half. The colon separator is non-spec. The
height counter changes only on new blocks — mempool-driven template
refreshes never trigger a longpoll wake. Pools using longpolling against
rustoshi will not get fee-rate-driven template refreshes.

**File:** `crates/rpc/src/server.rs:4311`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1002`;
`bitcoin-core/src/txmempool.cpp::GetTransactionsUpdated`.

**Impact:** miners get stale templates between tip changes; rustoshi
emits no `nTransactionsUpdatedLast`-style mempool counter at all
(grep returns 0 production sites for any such counter).

---

## BUG-18 (P2) — No terminal `TestBlockValidity` after template construction

**Severity:** P2. Bitcoin Core's `BlockAssembler::CreateNewBlock`
ends with (miner.cpp:223-228):

```cpp
if (m_options.test_block_validity) {
    if (BlockValidationState state{TestBlockValidity(
            m_chainstate, *pblock,
            /*check_pow=*/false, /*check_merkle_root=*/false)};
        !state.IsValid()) {
        throw std::runtime_error(strprintf("TestBlockValidity failed: %s",
                                            state.ToString()));
    }
}
```

A terminal sanity check that catches build_block_template bugs (wrong
BIP-34 height, oversized scriptSig, missing witness commitment, etc.)
BEFORE the template ships to the miner. Default `test_block_validity = true`.

rustoshi's `build_block_template` never calls validation. The
`mine_single_block` path catches errors via `chain_state.process_block`
after PoW is found (server.rs:9509), which means CPU is wasted on PoW
for an invalid template.

The `get_block_template` path returns the template without ANY validation
gate. A miner consuming the GBT response then PoW-grinds an invalid
template and submits it back to `submit_block` where it gets rejected.

**File:** `crates/consensus/src/block_template.rs:291-534`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-228`.

**Impact:** combined with BUG-1 / 7 / 8 / 9 / 10 / 11 / 12, a template
defect propagates through PoW grinding and is only caught at submission.
Wasted electricity, dropped mining rewards.

---

## BUG-19 (P3) — `sigoplimit / sizelimit / weightlimit` hardcoded; pre-segwit case not handled

**Severity:** P3. Bitcoin Core (mining.cpp:1007-1019):

```cpp
int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
if (fPreSegWit) {
    CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
    nSigOpLimit /= WITNESS_SCALE_FACTOR;
    CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
    nSizeLimit /= WITNESS_SCALE_FACTOR;
}
result.pushKV("sigoplimit", nSigOpLimit);
result.pushKV("sizelimit", nSizeLimit);
if (!fPreSegWit) {
    result.pushKV("weightlimit", MAX_BLOCK_WEIGHT);
}
```

Pre-segwit: sigops and size divided by WITNESS_SCALE_FACTOR (legacy
block: 20_000 sigops, 1_000_000 bytes); weightlimit omitted entirely
(pre-segwit doesn't have a weight concept).

rustoshi (server.rs:4319-4321) hardcodes:

```rust
sigoplimit: 80000,
sizelimit: 4000000,
weightlimit: 4000000,
```

Numeric literals (vs the `MAX_BLOCK_SIGOPS_COST`, `MAX_BLOCK_SERIALIZED_SIZE`
constants that exist in `crates/consensus/src/params.rs`). Always-post-segwit
view, no pre-segwit fallback. Mostly fine on live networks (segwit active
everywhere), but a parity gap for any forked-network exercises.

**File:** `crates/rpc/src/server.rs:4319-4321`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1019`.

**Impact:** cosmetic / parity gap only on live networks; pre-segwit
forks (none exist publicly) would receive wrong response.

---

## BUG-20 (P0-SEC) — Production mempool config uses `verify_scripts: false` (W150 BUG-2 carry-forward)

**Severity:** P0-SEC. **Carry-forward of W150 BUG-2 ("`verify_scripts:
false` production default")**. `rpc/src/server.rs:172, 199`:

```rust
mempool: Mempool::new(MempoolConfig::default()),
```

`MempoolConfig::default` sets `verify_scripts: false` (mempool.rs:747)
with a self-flagging comment "MUST set this to true at config-construction
time to enable PolicyScriptChecks + ConsensusScriptChecks". `MempoolConfig::
production()` (mempool.rs:785-790) — which sets the flag to true — is
NEVER called in production paths.

Effect on block-builder: every transaction in `state.mempool` was admitted
without script verification. `build_block_template` picks them up by
fee-rate (mempool.rs:2340-2365), no further check. An invalid-signature
tx that never would have made it into Core's mempool becomes a candidate
for inclusion in rustoshi's mined block. The miner then:
1. Builds the block.
2. PoW-grinds the nonce.
3. Calls `chain_state.process_block` — which DOES verify scripts
   (validation.rs:1554, 1803) — and the block is rejected.
4. Loses subsidy + fees, wastes work, and (if propagation order beats
   the local rejection) broadcasts an invalid block to peers.

The mining-time loss vector is the same shape as the W150 P0-SEC, with
additional teeth: a malicious peer that gets a bad-signature tx into the
local mempool wastes the operator's block-builder cycles.

**File:** `crates/rpc/src/server.rs:172, 199`;
`crates/consensus/src/mempool.rs:747, 785-790`.

**Core ref:** `bitcoin-core/src/init.cpp` (no equivalent flag; scripts
always verified in Core's mempool admit).

**Impact:** miner can be DoS'd into wasting PoW cycles via a single
bad-sig tx; mined blocks containing such txs are rejected by validation,
losing the block's subsidy + fees.

---

## BUG-21 (P3) — `-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight` CLI flags missing

**Severity:** P3 (W123 G21 / G25 carry-forward). Bitcoin Core
(`ApplyArgsManOptions`, miner.cpp:98-109):

```cpp
options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
    if (const auto parsed{ParseMoney(*blockmintxfee)})
        options.blockMinFeeRate = CFeeRate{*parsed};
}
options.print_modified_fee = args.GetBoolArg("-printpriority", options.print_modified_fee);
if (!options.block_reserved_weight) {
    options.block_reserved_weight = args.GetIntArg("-blockreservedweight");
}
```

rustoshi has no `-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`,
`-printpriority` CLI flags. Operator cannot tune mining template size
or fee floor without source modification.

**File:** `crates/rpc/src/server.rs` (CLI parse); no flags defined.

**Core ref:** `bitcoin-core/src/node/miner.cpp:98-109` (ApplyArgsManOptions).

**Impact:** operator must rebuild to change defaults; tooling parity
gap.

---

## BUG-22 (P1) — `prioritisetransaction` RPC missing (W108 G26 carry-forward)

**Severity:** P1. Bitcoin Core (mining.cpp:502-544): accepts `(txid,
fee_delta)`, applies delta to `MempoolEntry::nFeeDelta`, and returns
`true`. The delta is consulted by:
- mining selection (`GetModifiedFee` raises the tx's effective feerate);
- mempool RBF Rule 3 (Replacement transaction must pay > all conflicts'
  modified fees);
- mempool persistence (`map_deltas` survives restart).

rustoshi has the `fee_delta` field on `MempoolEntry` (mempool.rs:823-827)
and `get_modified_fee` (mempool.rs:3298-3305) consults it. But there is
NO `prioritisetransaction` RPC handler. The field is updated only by
test paths. Pool operators relying on prioritise to force-include
out-of-mempool CPFP arrangements cannot do so.

The mempool.rs comment at line 823-825 itself confesses:

> always zero (rustoshi does not yet implement `prioritisetransaction`)

**File:** `crates/rpc/src/server.rs` (no `prioritisetransaction` handler).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:502-544`.

**Impact:** mining pool operators cannot reweight transactions for
inclusion; comment-as-confession at mempool.rs:825 makes the gap explicit.

---

## BUG-23 (P3) — `getmininginfo` missing `currentblockweight` and `currentblocktx`

**Severity:** P3 (W108 G27 carry-forward). Bitcoin Core (mining.cpp:467-468):

```cpp
if (BlockAssembler::m_last_block_weight)
    obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
if (BlockAssembler::m_last_block_num_txs)
    obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
```

Optional fields populated from `BlockAssembler::m_last_block_weight` and
`m_last_block_num_txs` (static class members set on every CreateNewBlock).

rustoshi's `MiningInfo` struct (types.rs:525-546) lacks both fields.
There is also no equivalent `m_last_block_weight` tracking — every
`build_block_template` call computes fresh and discards.

**File:** `crates/rpc/src/types.rs:525-546` (MiningInfo);
`crates/rpc/src/server.rs:4655-4668` (handler).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:466-497, 467-468`;
`bitcoin-core/src/node/miner.h:96-98` (static members).

**Impact:** mining monitoring tools (e.g. fork-monitor.py, Stratum proxy
dashboards) cannot retrieve the most recent template's weight/tx count
from rustoshi.

---

## BUG-24 (P3) — `getmininginfo.networkhashps` hardcoded to 0.0

**Severity:** P3 (W123 G27 carry-forward). Bitcoin Core (mining.cpp:474):

```cpp
obj.pushKV("networkhashps", getnetworkhashps(self, request).get_real());
```

Calls `getnetworkhashps` to compute a real network hash rate estimate
from the last 120 blocks.

rustoshi (server.rs:4660):

```rust
networkhashps: 0.0, // would need to compute from recent blocks
```

Comment-as-confession (5th fleet instance tracked in W141..W145).
Mining tools that compute pool share of network hashrate see `0.0`,
which usually triggers divide-by-zero / NaN errors downstream.

**File:** `crates/rpc/src/server.rs:4660`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:474`.

**Impact:** mining stats consumers see 0 network hashrate; downstream
math errors.

---

## Summary

**Bug count:** 24 (P0-CDIV: 4, P0-CDIV-MINER: 2, P0-SEC: 1, P1: 8, P2: 6, P3: 3).

**P0-class concentration: 7 of 24 (29%).** All are mining-loss or
chain-split candidates from a rustoshi-mined block.

**Top 3 findings**

1. **BUG-9 (P0-CDIV-MINER) — witness commitment gated on `has_witness`,
   not `segwit_active`.** **W142 BUG-13 fourth carry-forward** — W108 G11
   and W123 G3 regression tests still on disk, `#[ignore]`d for 6+ weeks.
   On a segwit-active chain (mainnet h≥481,824, testnet4 from h=1, regtest
   always) an empty-mempool template (the common case for
   `generatetoaddress` runs) produces a coinbase with NO commitment;
   the block is rejected fleet-wide as `bad-witness-merkle-match`.

2. **BUG-4 + BUG-5 (P0-CDIV pair) — selection is flat txid sort, not
   cluster chunks, AND topological order not enforced (comment-as-
   confession at block_template.rs:1262: "we don't enforce strict
   topological order during selection").** rustoshi pops single txids
   from a heap; a child can land BEFORE its parent in
   `template.transactions`. Same-block-spend then fails with
   `bad-txns-inputs-missingorspent`. CPFP packages are systematically
   under-selected because the parent's standalone feerate is below the
   floor, even when the child's `ancestor_fee_rate` is high.

3. **BUG-20 (P0-SEC) — production mempool config uses `verify_scripts:
   false`** (carry-forward of W150 BUG-2). The block-builder selects from
   a mempool whose entries never had scripts verified. A bad-sig tx
   admitted via the bypassed gate becomes a candidate for inclusion in
   a mined block; the miner PoW-grinds it, then validation rejects
   `block-script-verify-flag-failed`. DoS vector: a malicious peer that
   poisons a single tx into the local mempool wastes the operator's
   mining cycles and may broadcast an invalid block.

**Carry-forward verdicts**
- W142 BUG-13 (witness commitment gating): **still open, 4th instance** ;
  regression tests at `tests/test_w108_gbt.rs::test_g11_witness_commitment_always_present_when_segwit_active`
  and `tests/test_w123_mining_gbt.rs` G3 still `#[ignore]`.
- W145 BUG-3 (parallel hardcoded subsidy halving in
  `storage::indexes::coinstatsindex::get_block_subsidy`): **still open**;
  `crates/storage/src/indexes/coinstatsindex.rs:295` hardcodes `HALVING_INTERVAL: u32 = 210_000`.
  `build_block_template` itself uses the params-aware `block_subsidy`
  (block_template.rs:453), so the miner is currently safe — but the
  parallel helper is wired into coinstatsindex which mining tooling
  may consume.
- W150 BUG-2 (verify_scripts default false): **still open**;
  rustoshi production constructs mempool via `MempoolConfig::default()`
  (server.rs:172, 199) which sets `verify_scripts: false`. Cross-cite
  BUG-20.

**Fleet patterns observed**
- **Comment-as-confession (6th–8th fleet instances)**: three confessions
  inline in rustoshi (block_template.rs:1262 "we don't enforce strict
  topological order", server.rs:4660 "would need to compute from recent
  blocks", mempool.rs:825 "rustoshi does not yet implement
  prioritisetransaction").
- **N-pipeline drift (mining-internal vs RPC-coinbase-extraction vs
  RPC-default_witness_commitment)**: rustoshi has THREE witness-commitment
  awareness sites — `build_witness_commitment` (block_template.rs:635),
  the RPC's commitment extraction at server.rs:4218-4228, and the
  validation-side check_witness_commitment. First and third use
  `has_witness`; second uses `is_segwit_active` — divergent gates on the
  same property.
- **Dead-data plumbing**: `MINIMUM_BLOCK_RESERVED_WEIGHT=2000` (BUG-2),
  `MAX_TIMEWARP=600` (BUG-12), `BlockTemplateConfig::block_version`
  (BUG-13), `coinbase_sigop_reserve = 0` (BUG-1), `nFeeDelta` (BUG-22).
- **Wiring-look-but-no-wire**: `MempoolConfig::production()` exists,
  documented, and exported — never called from any production site
  (BUG-20).
- **Asymmetric defensive depth**: validation enforces `bad-cb-length`
  2..100 at the consensus boundary (validation.rs:425-427), but
  build_coinbase_tx (block_template.rs:558-629) does not pre-check
  (BUG-8). Same impl, two phases, divergent depth.
- **Carry-forward re-anchor**: 3 carry-forwards (W142 BUG-13 #4, W145
  BUG-3, W150 BUG-2) all still unfixed in production paths even though
  regression tests exist as `#[ignore]` rust harnesses.

