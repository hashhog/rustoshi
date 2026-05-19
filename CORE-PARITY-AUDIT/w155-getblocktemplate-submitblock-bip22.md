# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (rustoshi)

**Wave:** W155 — `getblocktemplate` (BIP-22/BIP-23/BIP-9/BIP-145),
`submitblock` (BIP-22), `submitheader`, `getmininginfo`,
`prioritisetransaction`, `getprioritisedtransactions`,
`getnetworkhashps`, plus BIP-22 wire fields:
`mode`/`capabilities`/`rules`/`longpollid`/`data`/per-tx
`depends|fee|sigops|weight|required`, response fields
`version|rules|vbavailable|vbrequired|previousblockhash|transactions|
coinbaseaux|coinbasevalue|coinbasetxn|longpollid|target|mintime|mutable|
noncerange|sigoplimit|sizelimit|weightlimit|curtime|bits|height|
signet_challenge|default_witness_commitment|capabilities` and the
`BIP22ValidationResult` decision string set.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:615-1036` — `getblocktemplate`
  RPCHelpMan with full request/response shape (BIP-22 sections
  `mode`/`capabilities`/`rules`/`longpollid`/`data`).
- `bitcoin-core/src/rpc/mining.cpp:766-775` — pre-template gating:
  refuses on `!isTestChain && GetNodeCount(Both)==0` (RPC_CLIENT_NOT_CONNECTED)
  and `!isTestChain && isInitialBlockDownload()` (RPC_CLIENT_IN_INITIAL_DOWNLOAD).
- `bitcoin-core/src/rpc/mining.cpp:783-845` — BIP-22 long-poll loop
  (`waitTipChanged` + `mempool.GetTransactionsUpdated()` watchdog,
  60s + 10s checktx interval).
- `bitcoin-core/src/rpc/mining.cpp:849-857` — required-rules
  enforcement: `signet` rule mandatory on signet, `segwit` rule
  mandatory on all networks.
- `bitcoin-core/src/rpc/mining.cpp:730-751` — BIP-23 `mode=proposal`
  dispatcher: `LookupBlockIndex(hash)` → returns `duplicate` /
  `duplicate-invalid` / `duplicate-inconclusive`, else
  `TestBlockValidity(check_pow=false, check_merkle_root=true)`.
- `bitcoin-core/src/rpc/mining.cpp:587-603` — `BIP22ValidationResult`
  decision-string mapper: empty reject → "rejected"; non-empty →
  reject token; valid → JSON null.
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`:
  (a) `LOCK(cs_main); UpdateUncommittedBlockStructures(block, pindexPrev)`
  BEFORE `ProcessNewBlock` so a stripped-witness coinbase is auto-padded
  with the 32-zero witness nonce; (b) registers a
  `submitblock_StateCatcher` and returns "inconclusive" if `!sc->found`;
  (c) returns "duplicate" if `!new_block && accepted`.
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader` (no
  rustoshi analogue).
- `bitcoin-core/src/rpc/mining.cpp:547-583` — `getprioritisedtransactions`
  (no rustoshi analogue).
- `bitcoin-core/src/rpc/mining.cpp:416-485` — `getmininginfo`:
  `currentblockweight` / `currentblocktx` from `BlockAssembler::m_last_*`;
  `signet_challenge` only on signet; `warnings` field changed to ARR
  in Core 28+; `blockmintxfee` is `assembler_options.blockMinFeeRate
  .GetFeePerK()` (sat per kvB).
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`:
  `min_time = MTP+1`, then **at every retarget boundary** (height %
  difficulty_adjustment_interval == 0) clamp `min_time = max(min_time,
  prev_block_time - MAX_TIMEWARP)` (BIP-94 timewarp protection;
  applied on all networks as a safety belt).
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`: actual
  block timestamp = `max(GetMinimumTime(...), NodeClock::now())`.
- `bitcoin-core/src/validation.cpp:3985-3995` —
  `UpdateUncommittedBlockStructures`: if coinbase has a witness
  commitment output but lacks the 32-zero scriptWitness stack[0],
  Core inserts it pre-validation.
- `bitcoin-core/src/validation.cpp:3997-4019` —
  `GenerateCoinbaseCommitment` (Core's `regtestmine` /
  `RegenerateCommitments` path used by `generateblock`).
- `bitcoin-core/src/policy/feerate.h:41` — `CFeeRate(int64_t sats_per_kvb)`.
  `DEFAULT_BLOCK_MIN_TX_FEE = 1000` (`policy.h`).

**Files audited**
- `crates/rpc/src/server.rs:436-448` — RPC trait surface for
  `getblocktemplate` / `submitblock` / `getmininginfo`.
- `crates/rpc/src/server.rs:4065-4329` —
  `RustoshiRpcServer::get_block_template` implementation.
- `crates/rpc/src/server.rs:4331-4622` —
  `RustoshiRpcServer::submit_block` implementation.
- `crates/rpc/src/server.rs:4624-4669` —
  `RustoshiRpcServer::get_mining_info` implementation.
- `crates/rpc/src/server.rs:7055-7082` —
  `RustoshiRpcServer::prioritise_transaction` implementation.
- `crates/rpc/src/server.rs:5522-5654` — `generate_to_address`,
  `generate_block`, `generate_to_descriptor` (regtest path).
- `crates/rpc/src/server.rs:8292-8352` — `get_network_hash_ps`
  implementation.
- `crates/rpc/src/server.rs:7184-7274` — `help` RPC (lists
  user-visible mining commands).
- `crates/rpc/src/types.rs:583-645` — `BlockTemplateResult` and
  `BlockTemplateTransaction` JSON shapes.
- `crates/rpc/src/types.rs:547-581` — `MiningInfo` /
  `MiningInfoNext` JSON shapes.
- `crates/consensus/src/block_template.rs:133-181` —
  `BlockTemplateConfig` defaults (carry-forward references W154 BUG-6
  `block_min_fee_rate=1.0`, W154 BUG-13 `block_version=None`).
- `crates/consensus/src/block_template.rs:291-534` —
  `build_block_template` (mempool-driven assembly path; cross-cite
  W154 BUG-9 `has_witness`-gated commitment).
- `crates/consensus/src/block_template.rs:558-629` —
  `build_coinbase_tx`.
- `crates/consensus/src/validation.rs:228-490` —
  `bip22_string()` mapper (rustoshi's `BIP22ValidationResult` analogue).
- `crates/consensus/src/chain_state.rs:395-465` — `process_block` /
  `process_block_at_height` (entry from `submit_block`).
- `crates/consensus/src/mempool.rs:676-787` — `MempoolConfig`
  `verify_scripts: false` default (cross-cite W154 BUG-20 carry-forward).
- `crates/consensus/src/versionbits.rs:285-302` — `get_state_for`
  (returns `Defined` when `block=None`, the call shape used by
  `get_block_template`'s `vbavailable` builder — carry-forward W154 BUG-13).

---

## Gate matrix (40 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Pre-template gating (Core mining.cpp:766-775) | G1: refuse with RPC_CLIENT_NOT_CONNECTED when `!isTestChain && GetNodeCount(Both)==0` | **BUG-1 (P1)** — `get_block_template` (server.rs:4065-4329) never consults the peer manager / connection count. A non-test chain GBT request with zero peers silently returns a template that the miner will eventually mine into a chain-fork-from-nothing. |
| 1 | … | G2: refuse with RPC_CLIENT_IN_INITIAL_DOWNLOAD when `!isTestChain && isInitialBlockDownload()` | **BUG-2 (P0-CDIV)** — `get_block_template` does not check `state.is_ibd` (server.rs:131). On a fresh-IBD node, GBT happily returns a template against a stale tip; the miner produces a block that, once IBD finishes, becomes an orphan. This is the exact Bitcoin Core CVE class that mandated the `isInitialBlockDownload` gate in #6571 (2015). |
| 2 | BIP-22 long-poll | G3: `longpollid` request field parsed; blocks until tip changes OR `mempool.GetTransactionsUpdated()` changes | **BUG-3 (P0-CDIV)** — `_params` parameter is ignored entirely (server.rs:4067). No long-poll logic. Long-polling miners (Slush, Marathon, etc.) hang on dead requests until their HTTP timeout. (W108 G1 carry-forward, ~6+ weeks open) |
| 2 | … | G4: `longpollid = tip.GetHex() + decimal(nTransactionsUpdatedLast)` (NO separator) | **BUG-4 (P2)** — `longpollid: format!("{}:{}", state.best_hash.to_hex(), state.best_height)` (server.rs:4311) uses `:` separator AND height counter instead of decimal `nTransactionsUpdatedLast`. Format diverges from Core; mempool-only template changes never trigger a long-poll wakeup. (W154 BUG-17 / W108 G3 carry-forward, ~3 weeks open) |
| 3 | BIP-22 request rules array (mining.cpp:849-857) | G5: parse `rules` array; reject if `"segwit"` missing | **BUG-5 (P1)** — `_params` is dead. Clients that omit `segwit` from `rules` still receive a template. Modern miner SW (cgminer, bfgminer, ckpool) assert at parse-time that the server enforced this — rustoshi will not refuse, so the miner downstream-asserts the contract and crashes. (W154 BUG-16 / W108 G1 carry-forward) |
| 3 | … | G6: reject if `signet` missing on signet | **BUG-6 (P0-CDIV)** — no rules-array parsing. On signet, miner can request a template without acknowledging signet rules and receive a non-signet-challenge template, then produce blocks the signet network rejects. |
| 4 | BIP-23 `mode=proposal` (mining.cpp:730-751) | G7: parse `mode` field; dispatch `"proposal"` to `TestBlockValidity` | **BUG-7 (P2)** — no `mode` parsing. `mode=proposal` is silently treated as `template`. (W154 BUG-15 / W108 G4 carry-forward) |
| 4 | … | G8: proposal-mode duplicate detection returns one of "duplicate" / "duplicate-invalid" / "duplicate-inconclusive" | **BUG-7 cross-cite** — `submit_block` (server.rs:4378-4384) returns flat `"duplicate"` for any already-stored block. The three-way duplicate distinction (matches Core's `BLOCK_VALID_SCRIPTS` / `BLOCK_FAILED_VALID` / fallback) is absent. Wallets/miners watching the BIP-22 wire cannot distinguish "already mined OK" from "this hash maps to a known-invalid block, do not retry". (W108 G5 carry-forward) |
| 5 | Response wire shape (mining.cpp:947-1031) | G9: `capabilities: ["proposal"]` array emitted | **BUG-8 (P2)** — `BlockTemplateResult` (types.rs:583-626) has no `capabilities` field; the serializer does not emit it. Modern miner SW relies on the array to negotiate server capabilities. (W154 BUG-12 / W123 G13 carry-forward) |
| 5 | … | G10: `mutable: ["time", "transactions", "prevblock"]` matches Core | PASS — server.rs:4317 emits exactly the three Core entries. |
| 5 | … | G11: `coinbaseaux` emitted as JSON object (typically empty `{}`) | PASS — server.rs:4309 emits `serde_json::json!({})`. |
| 5 | … | G12: `coinbasevalue` is JSON NUMBER (not string), in satoshis | PASS — `coinbasevalue: u64` (types.rs:601) serializes as integer. |
| 5 | … | G13: `target` is byte-reversed 32-byte hex of the compact target | **BUG-9 (P2)** — server.rs:4312 emits `hex::encode(template.target)`. `template.target` comes from `header.target()` (block_template.rs:521) which returns the target as native-byte-order bytes. Core's `arith_uint256().GetHex()` (`mining.cpp:1003`) writes the value in big-endian (display order). Without verifying that `header.target()` returns big-endian (the code returns `[u8; 32]` from a `set_compact` codepath; in the rustoshi codebase the convention is little-endian internal for hashes, but `arith_uint256::GetHex` emits MSB-first), the GBT target field disagrees with `getblockhash` / `getblockheader.bits`-derived target by byte-order. Even if today it happens to match Core, the type contract is implicit (no test in `test_w123_mining_gbt.rs:G2` enforces a specific Core byte-string for target). |
| 5 | … | G14: `signet_challenge` emitted when chain is signet | **BUG-10 (P2)** — `BlockTemplateResult` struct has no `signet_challenge` field at all (types.rs:583-626). Signet miners receive a template with NO challenge to splice into the block, then assemble blocks that fail signet validation. |
| 5 | … | G15: `sizelimit` = `MAX_BLOCK_SERIALIZED_SIZE` (4,000,000 post-segwit; 1,000,000 pre-segwit) | PARTIAL — server.rs:4320 hardcodes `sizelimit: 4_000_000`. On a chain BEFORE segwit activation (mainnet < 481,824, testnet3 < 834,624) Core divides by `WITNESS_SCALE_FACTOR` to emit `1_000_000` (`mining.cpp:1009-1014`). Rustoshi's hardcode advertises a post-segwit size to a pre-segwit miner, which the miner then exceeds and the resulting block fails `bad-blk-length`. Not exercised on mainnet today (segwit long-active), but a regtest from-genesis or testnet3 pre-481824 replay sees the divergence. |
| 5 | … | G16: `sigoplimit` = `MAX_BLOCK_SIGOPS_COST` (80,000 post-segwit; 20,000 pre-segwit) | PARTIAL — server.rs:4319 hardcodes `sigoplimit: 80000`. Same pre-segwit-divide gap as G15. |
| 5 | … | G17: `weightlimit` = `MAX_BLOCK_WEIGHT` (4,000,000) — emitted ONLY post-segwit (Core mining.cpp:1017-1019) | PARTIAL — server.rs:4321 emits `weightlimit: 4_000_000` unconditionally. Core gates this with `if (!fPreSegWit)` — a pre-segwit miner reading the field assumes the server knows about weight (which it does not). |
| 6 | `default_witness_commitment` (mining.cpp:1028-1031) | G18: emitted iff segwit-active AND coinbase has commitment | **BUG-11 (P0-CDIV-MINER) cross-cite W154 BUG-9 fourth carry-forward** — server.rs:4215-4231 gates emission on `state.params.is_segwit_active(new_height) && coinbase has commitment`. The coinbase commitment ITSELF is gated by `has_witness` (block_template.rs:586, 598). Net effect: at segwit-active height with empty mempool, `default_witness_commitment = None` because the coinbase has no commitment built. Miners that splice the field get nothing; the assembled block fails `bad-witness-merkle-match`. (W142 BUG-13 / W108 G11 / W123 G3 / W154 BUG-9 — **5th carry-forward instance, 6+ weeks open, regression tests #[ignore]d**) |
| 6 | … | G19: commitment scriptPubKey format: `OP_RETURN || 0x24 || 0xaa21a9ed || sha256d(witness_root \|\| nonce)` | PASS when the commitment is present (server.rs:4220-4222 validates the header bytes before emitting). |
| 7 | Per-tx response object (mining.cpp:911-935) | G20: `data` hex-encoded with witness | PASS — server.rs:4189 uses `tx.serialize()` which encodes the full witness-including byte stream (`Encodable for Transaction`, transaction.rs:326-339 writes marker+flag when `has_witness()`). |
| 7 | … | G21: `txid` (non-witness) and `hash` (wtxid) BOTH emitted, byte-reversed hex | PASS — server.rs:4190-4191. |
| 7 | … | G22: `depends` array populated with 1-based indices of parent txs in the same template | **BUG-12 (P2)** — server.rs:4192 emits `depends: vec![]` for every tx. Modern mining pools rely on `depends` to schedule parallel transaction validation; rustoshi's hardcoded empty array forces serial replay of the whole template. (W154 BUG-11 / W123 G11 carry-forward) |
| 7 | … | G23: `fee` per-tx populated from `block_template->getTxFees()` (sats) | **BUG-13 (P1)** — server.rs:4193 emits `fee: 0` for every tx with comment `// would need to look up from mempool`. Without per-tx fees, the miner cannot compute the coinbase output (which Core supplies via `coinbasevalue`, but the per-tx breakdown is needed for pool payout math and BIP-141 witness commitment fee verification). The mempool's `MempoolEntry.fee` is right there in scope but unused. (W154 BUG-8 / W123 G8 carry-forward) |
| 7 | … | G24: `sigops` per-tx populated from `block_template->getTxSigops()` | PASS (server.rs:4194-4199; uses `template.per_tx_sigops` index-aligned with `template.transactions`). |
| 7 | … | G25: `weight` per-tx in weight units | PASS (server.rs:4200; `tx.weight() as u32` fits at <4M cap). |
| 7 | … | G26: per-tx `required: true` for BIP-23 "required to be in the block" | MISSING — `BlockTemplateTransaction` (types.rs:630-645) has no `required` field. Core uses this for required transactions in compact-block-relayed templates (mining.cpp emits when `pblocktemplate->vTxRequired` is set). Rustoshi has no plumbing for "required" txs at the template-builder layer either. |
| 8 | `mintime` BIP-94 timewarp adjustment (miner.cpp:36-47) | G27: `mintime = max(MTP+1, prev_block_time - MAX_TIMEWARP)` at retarget boundaries | **BUG-14 (P1)** — server.rs:4316 emits `(median_time_past + 1) as u32`. The BIP-94 clamp at `(height % DifficultyAdjustmentInterval) == 0` (Core: `min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP)`) is missing. On testnet4 (BIP-94 active) the miner may set a block timestamp that satisfies MTP+1 but VIOLATES the timewarp rule, producing a block that fails `time-timewarp-attack` (validation.rs:88-89). The clamp is meant as a safety belt on all networks per Core's comment: `// Account for BIP94 timewarp rule on all networks. This makes future activation safer.` |
| 9 | `curtime` clock-skew handling (miner.cpp:49-65) | G28: `curtime = max(GetMinimumTime(...), NodeClock::now())` | **BUG-15 (P1)** — server.rs:4322 emits `timestamp = SystemTime::now()` directly (server.rs:4071-4074). When the system clock is behind the parent's MTP, `curtime < mintime` and the block built with `timestamp` fails BIP-113. Core's `UpdateTime` clamps the actual block timestamp to `mintime` floor; rustoshi's `build_block_template` accepts `timestamp` verbatim and so the produced block can be DOA. |
| 10 | `vbavailable` BIP-9 deployment map (mining.cpp:965-991) | G29: emit name→bit for every STARTED or LOCKED_IN BIP-9 deployment | **BUG-16 (P0-CDIV) cross-cite W154 BUG-13** — server.rs:4284-4300 calls `get_state_for::<NoBlock>(None, dep, None)`. `get_state_for` returns `Defined` when `block=None` for any non-special start_time (versionbits.rs:299-302). Net: `vbavailable` is FOREVER EMPTY. `rules` array's BIP-9 active-set is also forever empty (line 4273; same `NoBlock` issue). Production miners never learn what BIP-9 / BIP-320 bits to signal. (W154 BUG-13 carry-forward, 4 weeks open) |
| 10 | … | G30: `vbrequired` bit mask of required version bits | PARTIAL — server.rs:4306 emits `vbrequired: 0`. Core also emits 0 today, but the *value* is not derived from `gbtstatus` (rustoshi has no `gbtstatus` plumbing). When a future BIP-9 deployment becomes LOCKED_IN-mandatory, rustoshi will continue emitting 0. |
| 11 | submitblock pre-process (Core mining.cpp:1083-1090) | G31: `UpdateUncommittedBlockStructures(block, pindexPrev)` injects 32-zero witness nonce when missing | **BUG-17 (P0-CDIV)** — rustoshi's `submit_block` (server.rs:4331-4622) parses the block, validates it, and connects it WITHOUT pre-processing. A pool that mined a block but produced a stripped-witness coinbase (Core's `block_template->getCoinbaseTx()` separates `required_outputs` and the pool stitches them in) has the nonce inserted by Core's `UpdateUncommittedBlockStructures`. Rustoshi rejects the same block with `bad-witness-nonce-size`. Cross-pool divergence: a rustoshi-served template can ONLY be submitted back to rustoshi (not to a Core peer that does the pre-process). |
| 11 | … | G32: registers a `submitblock_StateCatcher` and returns "inconclusive" if `!sc->found` | PARTIAL — rustoshi returns "inconclusive" ONLY in the `PrevBlockNotFound` arm (server.rs:4607) when the block stored on a side-branch but is not yet best-work. Core returns "inconclusive" any time the validation interface didn't observe the block's hash being checked (e.g. a non-fatal processing race). Different semantics. |
| 12 | BIP22ValidationResult string mapping | G33: empty reject-reason → "rejected" (Core: `if (strRejectReason.empty()) return "rejected"`) | PASS (validation.rs:228 + tests at server.rs:13177-13183 cover the catch-all). |
| 12 | … | G34: canonical token names match Core's `validation.cpp` strings | PASS for tested variants (server.rs:13128-13180). |
| 13 | Mining RPC surface coverage | G35: `submitheader` RPC dispatched | **BUG-18 (P1)** — no `submitheader` in rustoshi's RPC trait (server.rs:436-448), no handler. Core registers it as a "mining" command (mining.cpp:1156). RPC-driven header-only sync workflows (test harnesses, hashrate-derivatives indexers, light-wallet servers) cannot submit out-of-band headers to rustoshi. |
| 13 | … | G36: `getprioritisedtransactions` RPC dispatched | **BUG-19 (P1)** — no `getprioritisedtransactions` in rustoshi (Core mining.cpp:547-583). The prioritisation deltas applied via `prioritise_transaction` (server.rs:7064) are write-only — operators cannot inspect what's currently prioritised. |
| 13 | … | G37: `help` command list includes `getnetworkhashps`, `submitheader`, `getprioritisedtransactions` | **BUG-20 (P3)** — `help` (server.rs:7253) only lists `getblocktemplate, getmininginfo, prioritisetransaction, submitblock`. `getnetworkhashps` IS implemented (server.rs:8292) but missing from the help list. `submitheader` and `getprioritisedtransactions` are missing both from the help list AND from the implementation surface. |
| 14 | `getmininginfo` parity (mining.cpp:416-485) | G38: `networkhashps` populated from `getnetworkhashps()` | **BUG-21 (P2)** — server.rs:4660 hardcodes `networkhashps: 0.0` with comment `// would need to compute from recent blocks`. The implementation that *does* compute this (`get_network_hash_ps`, server.rs:8292) is already in the same impl block — `getmininginfo` could call it directly. Operators monitoring hashrate via `getmininginfo` see permanent `0.0` and silently lose signal. |
| 14 | … | G39: `currentblockweight` / `currentblocktx` (last assembled block) | **BUG-22 (P2)** — `MiningInfo` (types.rs:547-568) lacks both fields. Core emits them when `BlockAssembler::m_last_block_weight` is set. Rustoshi has no equivalent per-process counter; the most recent template's weight is unrecoverable via RPC. (W154 BUG-25 / W123 G18 carry-forward) |
| 14 | … | G40: `blockmintxfee` is `assembler_options.blockMinFeeRate.GetFeePerK()` (sat per kvB) | **BUG-23 (P1)** — server.rs:4664 emits `BtcAmount::from_sats(1)` = 0.00000001 BTC. Core's default is `DEFAULT_BLOCK_MIN_TX_FEE=1000` sat/kvB = `GetFeePerK() = 1000 sat = 0.00001 BTC`. Rustoshi's value is **1000× smaller** than Core's. Same unit-confusion as W154 BUG-6 (`block_min_fee_rate: 1.0` is also 1000× wrong) — these two bugs together mean the operator-visible feerate (`getmininginfo.blockmintxfee`) is 1000× smaller than the assembler's actual floor, which is also 1000× smaller than Core's. Two layers of compounding 1000× errors that nearly cancel in user-visible terms but propagate in fleet comparison. |
| 14 | … | G41: `warnings` is ARRAY in Core 28+ (was STR in legacy) | **BUG-24 (P2)** — `MiningInfo.warnings: String` (types.rs:567). Core 28+ emits `Vec<String>`. Tooling pinned to current Core schema sees a JSON-type mismatch on rustoshi. `getblockchaininfo.warnings` is already `Option<Vec<String>>` in rustoshi (types.rs:1039) — the inconsistency is internal. |
| 14 | … | G42: `signet_challenge` in `getmininginfo` on signet | **BUG-25 (P2)** — `MiningInfo` struct (types.rs:547-568) has no `signet_challenge` field. Symmetric to BUG-10 in GBT response. |

---

## BUG-1 (P1) — `getblocktemplate` does not require any peers connected

**Severity:** P1. Bitcoin Core's `getblocktemplate` (mining.cpp:766-770)
refuses to serve a template when (`!isTestChain &&
GetNodeCount(Both)==0`):

```cpp
if (!miner.isTestChain()) {
    const CConnman& connman = EnsureConnman(node);
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, CLIENT_NAME " is not connected!");
    }
    ...
}
```

This protects against a miner producing a chain-from-nothing on
an unconnected node: the operator-observable error makes the
mistake loud rather than silent. rustoshi's `get_block_template`
(server.rs:4065-4329) never touches the peer manager.

**File:** `crates/rpc/src/server.rs:4065-4329` (no peer-count check).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-770`.

**Impact:** an unconnected mainnet node will produce a template
that, once mined, becomes the operator's private chain — they will
have wasted PoW on a block that no peer will accept once the node
reconnects.

---

## BUG-2 (P0-CDIV) — `getblocktemplate` does not refuse on IBD

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate` (mining.cpp:772-774)
refuses to serve a template during IBD:

```cpp
if (miner.isInitialBlockDownload()) {
    throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                       CLIENT_NAME " is in initial sync and waiting for blocks...");
}
```

This is a CVE-class gate added in Bitcoin Core PR #6571 (2015) after
several mining-pool incidents where pools served stale-tip templates
during their own IBD, miners produced blocks that became orphans the
moment the pool finished syncing, and miners burned the rented hashrate.

rustoshi's `get_block_template` does not consult `state.is_ibd`
(server.rs:131) at all. The latch flips correctly during sync
(`should_exit_ibd`, server.rs:1125-1163), but the GBT path doesn't
read it.

**File:** `crates/rpc/src/server.rs:4065-4329` (no IBD check).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:772-774`; Bitcoin Core
PR #6571 (CVE-precedent rationale).

**Impact:** during fresh IBD a mainnet rustoshi node will hand out
GBT templates against the headers-only tip (or worse, the stale
synced tip). Miners producing blocks against those templates will
have those blocks orphaned the moment IBD completes; if the
operator was on a stratum pool, the pool's accepted-share count is
inflated by phantom work.

---

## BUG-3 (P0-CDIV) — BIP-22 long-poll completely unimplemented (W108 G1 / W154 BUG-15 carry-forward)

**Severity:** P0-CDIV (BIP-22 wire-protocol mandatory feature for any
serious mining workflow; carry-forward ~6 weeks open, third instance).
Bitcoin Core's `getblocktemplate` (mining.cpp:783-845) implements
long-poll as: when the client supplies `longpollid` in the request,
the server holds the RPC connection open until either (a) the active
tip changes (`waitTipChanged(hashWatchedChain)`) or (b) the mempool's
transactions-updated counter advances above the client-supplied
suffix. The first check happens after 1 minute, then every 10
seconds.

rustoshi's `get_block_template` signature is:

```rust
async fn get_block_template(
    &self,
    _params: Option<serde_json::Value>,  // <-- DEAD PARAMETER
) -> RpcResult<serde_json::Value> {
    let state = self.state.read().await;
    let timestamp = SystemTime::now()...
    // ... returns a fresh template synchronously
}
```

The `_params` (Rust convention: prefix-underscore = unused) is a
syntactic admission of the gap. No `longpollid` is parsed, no wait
loop is set up, no mempool-counter / tip-hash watcher exists.

**File:** `crates/rpc/src/server.rs:4067` (`_params` dead).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:728, 783-845`.

**Impact:**
- Stratum-style pool servers (which front-end BIP-22 to stratum)
  poll GBT every few seconds, defeating any pretense of efficiency
  the long-poll was meant to provide.
- Modern miner SW (cgminer) treats long-poll absence as a server
  bug and floods the RPC server with new-template polls (Core's
  GBT is expensive; rustoshi's is even more so since it walks
  the difficulty header chain on every call, server.rs:4090-4162).
- `mempool.GetTransactionsUpdated()` ↔ longpoll wakeup is the
  only mechanism that triggers a new template when mempool changes
  without a new block — without it, the miner mines an old template
  for up to its full polling interval.

This is the **third** wave that flags this bug (W108 G1, W154 BUG-15,
W155 BUG-3). The fix is non-trivial (requires plumbing into mempool's
update counter and the chain manager's tip-change notifier) — still
open.

---

## BUG-4 (P2) — `longpollid` format diverges from Core (W108 G3 / W154 BUG-17 carry-forward)

**Severity:** P2. Bitcoin Core (mining.cpp:1002):

```cpp
result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

The longpollid is the bare concatenation of `tip_hex` (64 chars)
and the decimal `nTransactionsUpdatedLast` counter (no separator,
no encoding marker). The 64-char prefix is parsed back out at
mining.cpp:809 with `lpstr.substr(0, 64)` and the suffix at
`lpstr.substr(64)`.

rustoshi (server.rs:4311):

```rust
longpollid: format!("{}:{}", state.best_hash.to_hex(), state.best_height),
```

Two divergences:
1. **`:` separator** — Core uses no separator. A miner that parses
   `longpollid[0..64]` against a rustoshi response gets the tip hash
   plus a `:`; against Core it gets only the hash. A miner that
   parses `longpollid.split(':')` against Core gets a single-element
   array; against rustoshi it gets two.
2. **`best_height` instead of `nTransactionsUpdatedLast`** — Core's
   suffix advances on every mempool change so long-poll fires on
   mempool churn. Rustoshi's suffix only changes on a new block, so
   even a *correctly implemented* long-poll would never fire on
   mempool-only updates.

**File:** `crates/rpc/src/server.rs:4311`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1002` (format),
`mining.cpp:809-810` (parse).

**Impact:** even if BUG-3 is fixed and long-poll wired up, the
field's format diverges from BIP-22's reference implementation,
so existing miner clients (cgminer / ckpool / nicehash) fail to
parse it back. This is the **third** wave that flags this
(W108 G3, W154 BUG-17, W155 BUG-4).

---

## BUG-5 (P1) — `rules` array not parsed; `segwit` opt-in unenforced (W108 G1 / W154 BUG-16 carry-forward)

**Severity:** P1. Bitcoin Core (mining.cpp:854-857):

```cpp
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       "getblocktemplate must be called with the segwit rule set "
                       "(call with {\"rules\": [\"segwit\"]})");
}
```

BIP-145 makes the `segwit` capability mandatory in client `rules`.
A client that doesn't list it is treated as a pre-segwit miner that
cannot parse `default_witness_commitment`, and Core refuses to
serve a post-segwit template.

rustoshi's GBT does not look at the rules array at all (`_params`
is dead). A client that omits `segwit` from `rules`:
- still receives the template (including `default_witness_commitment`),
- their miner SW may crash on the unexpected field,
- their assembled block (without the commitment splice) fails
  `bad-witness-merkle-match`.

**File:** `crates/rpc/src/server.rs:4067` (`_params` dead).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:854-857`.

**Impact:** silent BIP-145 violation; pre-segwit miner SW receives
post-segwit fields without the negotiation it expected. Cross-cite
BUG-3 / BUG-7 / BUG-15.

---

## BUG-6 (P0-CDIV) — `signet` rule not enforced on signet chains

**Severity:** P0-CDIV. Bitcoin Core (mining.cpp:849-852):

```cpp
if (consensusParams.signet_blocks && !setClientRules.contains("signet")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       "getblocktemplate must be called with the signet rule set ...");
}
```

A signet miner MUST explicitly acknowledge that they understand
signet's challenge-and-signature block-finality rule (BIP-325). If
the client doesn't, Core refuses to serve a template, because the
client will produce blocks that fail signet's `block_signature`
verification.

rustoshi's GBT does not parse `rules`, so a client requesting GBT
against rustoshi's signet endpoint with `rules: ["segwit"]` (no
signet) gets a template. They produce a block. That block lacks
the signet signature (which the client did not know to construct
because they did not opt into the signet rule). The block fails
peer-side validation with `bad-signet-blksig`. The miner has burned
PoW.

**File:** `crates/rpc/src/server.rs:4067` (`_params` dead).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:849-852`.

**Impact:** signet-deployed rustoshi serves templates that
unsuspecting miners cannot complete. The cross-cite with BUG-10
(no `signet_challenge` in response) compounds: even a signet-aware
miner that explicitly passes `rules: ["segwit", "signet"]` to
rustoshi does not receive the challenge to splice.

---

## BUG-7 (P2) — BIP-23 `mode=proposal` not parsed; `_params` is a dead parameter (W108 G4/G5 / W154 BUG-15 carry-forward)

**Severity:** P2 (BIP-23 optional-but-common feature; carry-forward
~6 weeks open, 3rd instance). Bitcoin Core (mining.cpp:730-751)
parses the `mode` field of the request:

```cpp
if (strMode == "proposal") {
    const UniValue& dataval = oparam.find_value("data");
    if (!dataval.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

    CBlock block;
    if (!DecodeHexBlk(block, dataval.get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex) {
        if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
            return "duplicate";
        if (pindex->nStatus & BLOCK_FAILED_VALID)
            return "duplicate-invalid";
        return "duplicate-inconclusive";
    }

    return BIP22ValidationResult(TestBlockValidity(chainman.ActiveChainstate(), block,
                                                  /*check_pow=*/false,
                                                  /*check_merkle_root=*/true));
}
```

`mode=proposal` is the BIP-23 pre-flight check: a miner can ask the
server to validate a proposed block WITHOUT submitting it (allowing
the miner to fix any errors before burning PoW on a doomed block).

rustoshi's `_params: Option<serde_json::Value>` is a dead parameter
(server.rs:4067). No `mode` parsing. The function unconditionally
returns a fresh template. A client requesting `mode=proposal` with
their hex-encoded candidate block receives a NEW template, not a
validation verdict — they have to either parse the response shape
(template vs proposal) themselves or fall back to `submitblock`
(which burns the block to disk if accepted, and emits a real
network broadcast).

**File:** `crates/rpc/src/server.rs:4067`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-751`.

**Impact:**
- mining pool software that uses proposal-mode as a pre-flight check
  (Slush, Foundry's solo-mining client) cannot validate against
  rustoshi without round-tripping the block onto the chain.
- BIP-22 wire test suites that exercise proposal mode see a
  template-shape response when expecting a string-shape response
  — type confusion fails the test silently.
- Cross-cite BUG-17: when the candidate block's coinbase is
  stripped-witness, rustoshi has no pre-process step, so even a
  manually-routed `submitblock` from a proposal-aware miner
  fails on a block that Core would accept.

---

## BUG-8 (P2) — `capabilities` response field missing (W123 G13 / W154 BUG-12 carry-forward)

**Severity:** P2. Bitcoin Core (mining.cpp:895, 948):

```cpp
UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");
...
result.pushKV("capabilities", std::move(aCaps));
```

Core advertises its server-side capability set. The minimum-viable
set is `["proposal"]`, meaning the server supports BIP-23 proposal
mode. Modern miner SW reads this array to negotiate which features
to use (e.g., `serverlist` for load-balancer setups, `workid` for
deduplication).

rustoshi's `BlockTemplateResult` (types.rs:583-626) has no
`capabilities` field. Even setting it to `[]` would be useful
(declares "no capabilities advertised"). The omission means a
miner that strictly checks `response["capabilities"]` against a
known whitelist sees `undefined` and refuses to proceed.

**File:** `crates/rpc/src/types.rs:583-626`,
`crates/rpc/src/server.rs:4302-4326`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:895, 948`.

**Impact:** strict-checking miner SW errors out at template parse;
non-strict miner SW proceeds without negotiation (treating the
server as the lowest-capability-set baseline). Since rustoshi
doesn't actually implement proposal mode (BUG-7), advertising
`["proposal"]` would be wrong given the unimplemented dispatch —
the correct fix here is to implement proposal mode AND emit
`["proposal"]`. (Note Core also serves `"longpoll"` as an
implicit capability via `longpollid` field presence.)

---

## BUG-9 (P2) — `target` byte-order contract is implicit

**Severity:** P2 (type-contract / wire-format risk). Bitcoin Core
(mining.cpp:1003):

```cpp
arith_uint256 hashTarget = arith_uint256().SetCompact(block.nBits);
...
result.pushKV("target", hashTarget.GetHex());
```

`arith_uint256::GetHex` emits the target in **big-endian** (most-
significant-byte-first) hex, matching the display order of block
hashes. This is the same format as `getblockheader.target` and
`getmininginfo.target`. Pool stratum dispatchers slice this string
to compute share-difficulty targets and depend on the byte order.

rustoshi (server.rs:4312):

```rust
target: hex::encode(template.target),
```

`template.target` is `[u8; 32]` produced by
`BlockHeader::target()` (block_template.rs:521 calls
`header.target()`). The rustoshi convention for hashes is
little-endian internal (consistent with `Hash256` storing wire-byte-
order), but the `target()` helper's byte order is not enforced
by type. If `target()` returns LE-byte-order, the GBT field
emits LE-hex which a pool will interpret in BE and compute the
wrong share target.

There is no test in `tests/test_w108_gbt.rs` or
`tests/test_w123_mining_gbt.rs` that compares the emitted target
string against an expected Core string. The byte-order contract
is implicit and may diverge silently across refactors.

**File:** `crates/rpc/src/server.rs:4312`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1003`,
`arith_uint256::GetHex`.

**Impact:** if today's byte order is LE, every pool's share-target
math is off by a 32-byte reversal — typically the math fails
loudly (impossible target) but pools that tolerate "too easy"
targets credit miners for invalid shares. If today's byte order
happens to be BE (by inspection of `header.target()` we cannot
quickly confirm), the field is correct now but un-pinned against
regressions.

---

## BUG-10 (P2) — `signet_challenge` field missing from GBT response

**Severity:** P2. Bitcoin Core (mining.cpp:1024-1026):

```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

A signet template MUST carry the network's challenge script so the
miner can construct the block-signature output before submitting.
Without it, the miner cannot complete the block.

rustoshi's `BlockTemplateResult` (types.rs:583-626) has no
`signet_challenge` field. The signet-aware miner that explicitly
requested `rules: ["segwit", "signet"]` against a rustoshi signet
endpoint (which would also need BUG-6 fixed to be accepted) still
cannot complete the block because they have no challenge to splice.

**File:** `crates/rpc/src/types.rs:583-626`,
`crates/rpc/src/server.rs:4302-4326`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1024-1026`.

**Impact:** signet mining via rustoshi RPC is non-functional even
if BUG-6 (signet rule unenforced) and BUG-22 (signet challenge
absent from getmininginfo) were fixed in isolation.

---

## BUG-11 (P0-CDIV-MINER) — `default_witness_commitment` gated transitively on `has_witness` (W142 BUG-13 / W108 G11 / W123 G3 / W154 BUG-9 — fifth carry-forward)

**Severity:** P0-CDIV-MINER. **This is the FIFTH carry-forward
instance** of W142 BUG-13 (W108 G11 → W123 G3 → W154 BUG-9 → W155
BUG-11). W108 and W123 regression tests are ON DISK at
`tests/test_w108_gbt.rs:502` and `tests/test_w123_mining_gbt.rs`
with `#[ignore = "BUG G3 (P2-CDIV) — witness commitment omitted
when segwit active + no witness txs"]` — **ignored 6+ weeks**.

Bitcoin Core's `default_witness_commitment` is emitted whenever
SegWit is deployment-active at the next block height
(`DeploymentActiveAfter(pindexPrev, *this, DEPLOYMENT_SEGWIT)`).
The commitment itself is built deterministically by
`CHash256().Write(BlockWitnessMerkleRoot(block)).Write(nonce).Finalize()`
regardless of whether the template contains witness transactions —
an all-non-witness block at a segwit-active height STILL needs the
commitment output, set to the witness-merkle-root of an all-zero
witness list.

rustoshi (server.rs:4215-4231):

```rust
let default_witness_commitment = if state.params.is_segwit_active(new_height) {
    // The commitment output is at index 1; its script starts with the
    // 6-byte BIP-141 header 0x6a 0x24 0xaa 0x21 0xa9 0xed.
    template.coinbase_tx.outputs.get(1).and_then(|out| {
        if out.script_pubkey.len() == 38 && ... { Some(hex::encode(&out.script_pubkey)) }
        else { None }
    })
} else { None };
```

The gate looks right on its face — it correctly checks
`is_segwit_active`. The bug is upstream in `build_coinbase_tx`
(block_template.rs:586, 598):

```rust
let has_witness = selected_txs.iter().any(|tx| tx.has_witness());
...
if has_witness {
    let commitment = build_witness_commitment(selected_txs, &witness_nonce);
    outputs.push(TxOut { value: 0, script_pubkey: commitment });
}
```

The coinbase commitment is only added when at least one selected
transaction has witness data. On a segwit-active chain with an
empty mempool or all-non-witness mempool, `outputs.get(1)` is None,
and `default_witness_commitment = None`.

**Failure mode:** a miner that gets a `None`
`default_witness_commitment` (treating it as a regular pre-segwit
template) assembles a block without the commitment. Validation
rejects with `bad-witness-merkle-match`. The miner has burned PoW.

**File:** `crates/consensus/src/block_template.rs:586, 598`
(root cause); `crates/rpc/src/server.rs:4215-4231` (symptom).

**Core ref:** `bitcoin-core/src/node/miner.cpp` /
`bitcoin-core/src/validation.cpp:3997-4019`
(`GenerateCoinbaseCommitment`).

**Excerpt (rustoshi, gate cascade)**
```rust
// block_template.rs:586 — gating commitment construction on tx-witness presence
let has_witness = selected_txs.iter().any(|tx| tx.has_witness());

// server.rs:4215 — gating commitment EMISSION on segwit-active (correct)
let default_witness_commitment = if state.params.is_segwit_active(new_height) { ... };
// But the input to the emission gate, `template.coinbase_tx.outputs.get(1)`,
// was already gated on `has_witness` — the two gates are AND-ed, when only
// the latter should apply.
```

**Impact:** every empty-mempool segwit-active GBT call returns a
template that miners cannot mine without falling back to the
`generate_block` path (which constructs the commitment itself).
At segwit-active heights with sparse mempool churn, this is
common. Regression tests already exist (W108 G11, W123 G3) and
have been `#[ignore]`-d for 6+ weeks.

**Persistence:** 5th wave to flag this single bug. Each wave's
fix priority list includes it; no fix has landed.

---

## BUG-12 (P2) — `depends` array hardcoded to `[]` (W123 G11 / W154 BUG-11 carry-forward)

**Severity:** P2. Bitcoin Core (mining.cpp:917-923):

```cpp
UniValue deps(UniValue::VARR);
for (const CTxIn &in : tx.vin) {
    if (setTxIndex.contains(in.prevout.hash))
        deps.push_back(setTxIndex[in.prevout.hash]);
}
entry.pushKV("depends", std::move(deps));
```

Core walks each tx's inputs against an in-template index (`setTxIndex
[txid] = i`), so each entry's `depends` array contains the 1-based
template indices of every parent tx that's also in the template. Pool
schedulers use this to parallelise tx validation (chunks are
independent if neither depends on the other).

rustoshi (server.rs:4192) hardcodes `depends: vec![]` for every tx.

**File:** `crates/rpc/src/server.rs:4192`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:917-923`.

**Impact:** mining pools that exploit `depends` for parallel tx
validation see an all-leaves dependency graph and either fall back
to serial validation (slow) or assume the template is bogus (modern
strict-checking pools).

---

## BUG-13 (P1) — Per-tx `fee` hardcoded to `0` (W123 G8 / W154 BUG-8 carry-forward)

**Severity:** P1. Bitcoin Core (mining.cpp:926):

```cpp
entry.pushKV("fee", tx_fees.at(index_in_template));
```

Core's `BlockTemplate::getTxFees()` is a parallel vector to
`block.vtx` carrying the consensus-correct fee for each tx
(`input_sum - output_sum` from the mempool entry). Pool payout
math depends on this for proportional reward distribution.

rustoshi (server.rs:4193):

```rust
fee: 0, // would need to look up from mempool
```

The mempool entry IS in scope — `template.transactions[i].txid()`
maps directly to `mempool.get(txid).fee`. The "would need to look up
from mempool" comment is a **comment-as-confession** (fleet pattern,
8th distinct rustoshi instance per W154 tracking) admitting the
work was deferred.

**File:** `crates/rpc/src/server.rs:4193`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:926`.

**Impact:**
- pool payout math broken (every tx contributes 0 to the perceived
  fee pool — miners may underpay or overpay relative to actual
  fees).
- `coinbasevalue - sum(fees) ≠ subsidy` invariant cannot be
  checked client-side.
- This is the THIRD wave to flag the same bug (W123 G8 → W154 BUG-8
  → W155 BUG-13).

---

## BUG-14 (P1) — `mintime` missing BIP-94 timewarp clamp at retarget boundaries

**Severity:** P1. Bitcoin Core (`bitcoin-core/src/node/miner.cpp:36-47`):

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev,
                       const int64_t difficulty_adjustment_interval) {
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

At every retarget boundary (height % 2016 == 0), Core clamps
`min_time` to at least `prev_block.time - MAX_TIMEWARP` (600 s).
This is the **BIP-94 timewarp protection** (testnet4 + future
mainnet); Core applies it on all networks as a safety belt.

rustoshi (server.rs:4316):

```rust
mintime: (median_time_past + 1) as u32,
```

Only the MTP+1 floor is applied. On testnet4 (BIP-94 already
consensus-active), a template returned at a retarget boundary
with `MTP+1 < prev_block.time - MAX_TIMEWARP` advertises a
`mintime` that, when used by the miner as the block timestamp,
violates `time-timewarp-attack`
(validation.rs:88-89 / validation.rs:946).

**File:** `crates/rpc/src/server.rs:4316`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`,
`bitcoin-core/src/consensus/consensus.h:35` (`MAX_TIMEWARP=600`).

**Excerpt (rustoshi, missing clamp)**
```rust
let median_time_past = compute_prev_block_mtp(&store, &state.best_hash) as i64;
// ...
let result = BlockTemplateResult {
    ...
    mintime: (median_time_past + 1) as u32,
    // MISSING: at (new_height % 2016) == 0, clamp to
    //   max(median_time_past + 1, prev_block.timestamp - MAX_TIMEWARP)
    ...
};
```

**Impact:**
- testnet4 retarget blocks: miner-supplied template can be
  unmineable (a miner that sets `nTime = mintime` produces a block
  that fails `time-timewarp-attack`).
- mainnet pre-BIP-94: safety belt absent. When BIP-94 activates on
  mainnet, rustoshi-served templates at every retarget block become
  silently broken until rustoshi ships a fix.

---

## BUG-15 (P1) — `curtime` is raw `SystemTime::now()`; no `max(mintime, now)` clamp

**Severity:** P1. Bitcoin Core's `UpdateTime`
(`bitcoin-core/src/node/miner.cpp:49-65`):

```cpp
int64_t nNewTime{std::max<int64_t>(
    GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
    TicksSinceEpoch<std::chrono::seconds>(NodeClock::now())
)};
```

The block timestamp is `max(mintime, NodeClock::now())`. When the
node's wall clock is behind the parent's MTP, Core uses MTP+1 as
the timestamp. The `curtime` field reflects this clamp.

rustoshi (server.rs:4071-4074):

```rust
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
```

This `timestamp` is BOTH the GBT `curtime` field AND the
`block_template.rs:512` `BlockHeader.timestamp` actually written
to the assembled template. There is no clamp against `mintime`. A
node whose clock is even 1 second behind the parent's MTP+1
produces a template that:
1. Returns `curtime < mintime` (operator monitoring confusion).
2. Builds the block header with `timestamp = curtime`, then ships
   the template to the miner. The miner mines a block with that
   timestamp. Validation rejects with `time-too-old`.

Cross-cite BUG-14: a clock skew of `(prev.time - MTP)` seconds is
enough to trigger this on a retarget boundary.

**File:** `crates/rpc/src/server.rs:4071-4074, 4169-4178, 4322`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65`.

**Impact:** any system-clock-behind condition (NTP drift, VM
suspend/resume, container restart on a clock-warping host) produces
DOA templates. Mining ops have explicit monitoring for this on
Core (`getmininginfo.networkhashps` deviates); rustoshi has neither
the clamp nor the monitoring.

---

## BUG-16 (P0-CDIV) — `vbavailable` map permanently empty (W154 BUG-13 cross-cite)

**Severity:** P0-CDIV. Bitcoin Core (mining.cpp:965-983):

```cpp
UniValue vbavailable(UniValue::VOBJ);
const auto gbtstatus = chainman.m_versionbitscache.GBTStatus(*pindexPrev, consensusParams);
for (const auto& [name, info] : gbtstatus.signalling) {
    vbavailable.pushKV(gbt_rule_value(name, info.gbt_optional_rule), info.bit);
    ...
}
for (const auto& [name, info] : gbtstatus.locked_in) {
    block.nVersion |= info.mask;
    vbavailable.pushKV(gbt_rule_value(name, info.gbt_optional_rule), info.bit);
    ...
}
```

Core walks the versionbits cache with the actual chain tip
(`pindexPrev`), populating `vbavailable` with every STARTED or
LOCKED_IN deployment's name → bit mapping. Miners use this map to
know which BIP-9 / BIP-320 bits to signal in the next block they
mine.

rustoshi (server.rs:4284-4300):

```rust
let gbt_vbavailable: serde_json::Value = {
    let vb_deps = get_deployments(&state.params);
    let mut map = serde_json::Map::new();
    for (id, dep) in &vb_deps {
        let name = match id {
            DeploymentId::Csv | DeploymentId::Segwit | DeploymentId::Taproot => continue,
            DeploymentId::Custom(n) => format!("custom_{}", n),
        };
        if matches!(
            get_state_for::<NoBlock>(None, dep, None),  // <-- block=None
            ThresholdState::Started | ThresholdState::LockedIn
        ) {
            map.insert(name, serde_json::json!(dep.bit));
        }
    }
    serde_json::Value::Object(map)
};
```

The call `get_state_for::<NoBlock>(None, dep, None)` passes
`block=None`. `get_state_for` (versionbits.rs:298-302):

```rust
let block = match block {
    Some(b) => b,
    None => return ThresholdState::Defined,
};
```

returns `Defined` immediately when `block=None` for any deployment
with non-`ALWAYS_ACTIVE` / non-`NEVER_ACTIVE` start_time. Since
`Defined` is neither `Started` nor `LockedIn`, **the matches! arm
fires zero times** for any real deployment. `vbavailable` is
forever an empty map. Same issue affects `rules` array's BIP-9
active-set additions (server.rs:4267-4276, same `NoBlock` pattern).

**File:** `crates/rpc/src/server.rs:4284-4300, 4267-4276`;
`crates/consensus/src/versionbits.rs:298-302`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:965-983`.

**Impact:**
- Rustoshi miners never signal new soft-fork bits via BIP-9 /
  BIP-320 version-rolling. If a soft fork activates while rustoshi
  is in the fleet, rustoshi-served miners can NOT contribute to
  activation hashpower count (the soft fork activates *despite*
  rustoshi, not *with* it).
- Forever-empty `vbavailable` is a wire-shape divergence from
  Core that pool monitoring tooling picks up as "this server is
  versionbits-naive — do not route signaling-sensitive jobs here".

**Persistence:** 2nd wave to flag this (W154 BUG-13, W155 BUG-16);
~4 weeks open.

---

## BUG-17 (P0-CDIV) — `submit_block` does not run `UpdateUncommittedBlockStructures` pre-process

**Severity:** P0-CDIV. Bitcoin Core (mining.cpp:1083-1090):

```cpp
ChainstateManager& chainman = EnsureAnyChainman(request.context);
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
```

`UpdateUncommittedBlockStructures` (validation.cpp:3985-3995):

```cpp
void ChainstateManager::UpdateUncommittedBlockStructures(CBlock& block,
                                                        const CBlockIndex* pindexPrev) const {
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT
        && DeploymentActiveAfter(pindexPrev, *this, Consensus::DEPLOYMENT_SEGWIT)
        && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}
```

When a pool submits a block whose coinbase has a witness commitment
output but lacks the 32-zero scriptWitness stack[0] (a common
shape — the pool's templating layer strips the witness for
proof-of-work hashing efficiency, then submits the block as-is),
Core repairs the structure pre-validation so the block can be
accepted.

rustoshi's `submit_block` (server.rs:4331-4622) parses the block
and feeds it directly to `chain_state.process_block(...)` (line
4404). No pre-process. A block submitted with a stripped-witness
coinbase fails `bad-witness-nonce-size` (validation.rs).

**File:** `crates/rpc/src/server.rs:4374-4404`.

**Core ref:** `bitcoin-core/src/validation.cpp:3985-3995`;
`bitcoin-core/src/rpc/mining.cpp:1083-1090`.

**Impact:**
- Cross-pool divergence: a Core-served template, mined by a Core-
  format-emitting pool, submitted back to a rustoshi node, is
  rejected. The reverse (rustoshi-served, rustoshi-submitted)
  works only because rustoshi's GBT happens to construct the
  witness stack in `build_coinbase_tx` (block_template.rs:620-624)
  for the served template — but pool software typically rebuilds
  the coinbase to splice their address.
- Production mining-pool integrations test against Core's
  acceptance behavior; rustoshi's rejection of a Core-acceptable
  block is a CDIV.

---

## BUG-18 (P1) — `submitheader` RPC not implemented

**Severity:** P1. Bitcoin Core registers `submitheader`
(mining.cpp:1108-1146) as a mining-category RPC:

```cpp
{"mining", &submitheader},
```

It accepts a hex-encoded block header, looks up the prev hash to
confirm the parent is known, and calls
`chainman.ProcessNewBlockHeaders({{h}}, /*min_pow_checked=*/true, state)`.
On valid headers it returns `null`; on invalid it throws.

rustoshi has NO `submitheader` trait method (server.rs:436-448) and
NO handler implementation. The RPC dispatches to method-not-found.

**File:** `crates/rpc/src/server.rs:436-448`,
`crates/rpc/src/server.rs:7253` (help list omits it).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1146, 1156`.

**Impact:**
- Header-only sync tooling (light wallet servers, hashrate
  derivatives indexers, test harnesses) cannot push out-of-band
  headers to rustoshi for pre-warming the header chain.
- `bitcoind` test fixtures that use `submitheader` to seed a
  regtest node's header tree fail against rustoshi.

---

## BUG-19 (P1) — `getprioritisedtransactions` RPC not implemented

**Severity:** P1. Bitcoin Core (mining.cpp:547-583):

```cpp
static RPCHelpMan getprioritisedtransactions() {
    return RPCHelpMan{"getprioritisedtransactions", ...
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            CTxMemPool& mempool = EnsureAnyMemPool(request.context);
            UniValue rpc_result{UniValue::VOBJ};
            for (const auto& delta_info : mempool.GetPrioritisedTransactions()) {
                UniValue result_inner{UniValue::VOBJ};
                result_inner.pushKV("fee_delta", delta_info.delta);
                result_inner.pushKV("in_mempool", delta_info.in_mempool);
                if (delta_info.in_mempool) {
                    result_inner.pushKV("modified_fee", *delta_info.modified_fee);
                }
                rpc_result.pushKV(delta_info.txid.GetHex(), result_inner);
            }
            return rpc_result;
        }};
}
```

This RPC lets the operator inspect what fee deltas have been
applied via `prioritisetransaction`. Rustoshi has
`prioritise_transaction` (server.rs:7064) but no symmetric
`getprioritisedtransactions`. Once a delta is applied, it is
write-only — the operator cannot list active prioritisations
without scraping the mempool entry-by-entry.

**File:** `crates/rpc/src/server.rs:436-448` (RPC trait, no entry);
no handler exists.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:547-583, 1154`.

**Impact:** monitoring / debugging gap. Operators using
`prioritisetransaction` to give a stuck tx priority cannot enumerate
which txs currently have non-zero deltas; the rustoshi mempool's
`fee_delta` per-entry field is reachable only via
`getmempoolentry` per-txid loop.

---

## BUG-20 (P3) — `help` command omits `getnetworkhashps`, `submitheader`, `getprioritisedtransactions`

**Severity:** P3. `rustoshi`'s `help` command's "== Mining ==" group
(server.rs:7253):

```rust
"getblocktemplate", "getmininginfo", "prioritisetransaction", "submitblock",
```

Missing:
- `getnetworkhashps` — *IS* implemented (server.rs:8292) but not
  user-visible via help.
- `submitheader` — not implemented (BUG-18).
- `getprioritisedtransactions` — not implemented (BUG-19).

Bitcoin Core registers all four in
`RegisterMiningRPCCommands` (mining.cpp:1148-1167). The omission
from the help list compounds the "RPC doesn't exist" problem (BUG-18,
BUG-19): operators don't know the RPC is missing because the help
list doesn't advertise it as a Core-parity RPC name.

**File:** `crates/rpc/src/server.rs:7184-7274`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1148-1167`.

**Impact:** discoverability gap. UX problem only — the implemented
`getnetworkhashps` works when called directly.

---

## BUG-21 (P2) — `getmininginfo.networkhashps` hardcoded to `0.0` despite implementation existing

**Severity:** P2. Bitcoin Core (mining.cpp:472):

```cpp
obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));
```

Core delegates to the `getnetworkhashps` handler — same code path
the standalone RPC uses.

rustoshi (server.rs:4660):

```rust
networkhashps: 0.0, // would need to compute from recent blocks
```

The implementation that COULD compute this is right there in the
same impl block (`get_network_hash_ps` at server.rs:8292-8352). A
2-line patch would wire it up. The "would need to compute from
recent blocks" comment is another **comment-as-confession** (9th
distinct rustoshi instance) — admitting a known unfixed gap.

**File:** `crates/rpc/src/server.rs:4660`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:472`.

**Impact:** monitoring tooling that scrapes
`getmininginfo.networkhashps` sees permanent `0.0`. Operators
must scrape `getnetworkhashps` separately.

---

## BUG-22 (P2) — `getmininginfo` missing `currentblockweight` / `currentblocktx`

**Severity:** P2. Bitcoin Core (mining.cpp:467-468):

```cpp
if (BlockAssembler::m_last_block_weight)
    obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
if (BlockAssembler::m_last_block_num_txs)
    obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
```

Core caches the most recently assembled block's weight and tx-count
as static `optional<size_t>` fields. `getmininginfo` exposes them.
Mining-pool dashboards use these to monitor template fullness in
near-real-time.

rustoshi's `MiningInfo` (types.rs:547-568) lacks both fields.
There is no equivalent per-process counter (`build_block_template`
in block_template.rs:291-534 returns a fresh `BlockTemplate` and
doesn't update any static).

**File:** `crates/rpc/src/types.rs:547-568`,
`crates/consensus/src/block_template.rs:291-534`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:426-427, 467-468`;
`bitcoin-core/src/node/miner.h::m_last_block_weight`.

**Impact:** monitoring divergence; mining-pool dashboards lose
signal. (W123 G18 / W154 BUG-25 carry-forward, 3rd flag.)

---

## BUG-23 (P1) — `getmininginfo.blockmintxfee` is 1000× smaller than Core

**Severity:** P1. Bitcoin Core (mining.cpp:476):

```cpp
obj.pushKV("blockmintxfee",
           ValueFromAmount(assembler_options.blockMinFeeRate.GetFeePerK()));
```

`blockMinFeeRate.GetFeePerK()` returns the per-kvB fee rate (sats per
1000 vbytes). Core's `DEFAULT_BLOCK_MIN_TX_FEE = 1000` →
`CFeeRate(1000).GetFeePerK() = 1000` sat = `0.00001` BTC.

rustoshi (server.rs:4664):

```rust
blockmintxfee: BtcAmount::from_sats(1),  // 1 sat = 0.00000001 BTC
```

with comment: `// 1 sat/vB minimum = 0.00000001 BTC/vB = 0.00000001 BTC base fee. Core emits ValueFromAmount(1) = "0.00000001".`

The comment claims Core emits `0.00000001`, but Core actually emits
`ValueFromAmount(1000)` = `0.00001000`. Rustoshi's value is **1000×
smaller**.

Cross-cite W154 BUG-6: `BlockTemplateConfig::default::block_min_fee_rate
= 1.0` is also 1000× wrong (Core's CFeeRate constructor takes sat per
kvB, so `1.0` would represent 0.001 sat/vB, not 1 sat/vB). Both
bugs share the same root cause: confusion between sat/vB and sat/kvB
units. The two bugs partially cancel from the operator's perspective
(both are 1000× wrong in the same direction) but expose the fleet
divergence to monitoring tooling that compares rustoshi vs Core
directly.

**File:** `crates/rpc/src/server.rs:4660-4664` (comment-as-confession).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:476`,
`bitcoin-core/src/policy/feerate.h:41`.

**Impact:** monitoring shows rustoshi's `blockmintxfee` 1000× lower
than Core's. Pool tooling that auto-tunes "min fee rate to send a
tx" based on this field will route txs through rustoshi expecting
much cheaper inclusion than Core, then be surprised when the
mempool rejects them at the actual (1000× higher) admission gate
(W150 BUG cross-cite).

---

## BUG-24 (P2) — `MiningInfo.warnings` is `String`, Core 28+ emits `Vec<String>`

**Severity:** P2 (wire-schema divergence). Bitcoin Core (mining.cpp:443-450):

```cpp
(IsDeprecatedRPCEnabled("warnings") ?
    RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
    RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)", { ... }}
),
```

Core 28+ emits `warnings` as a `Vec<String>` by default; legacy
behaviour returns a single string only when `-deprecatedrpc=warnings`
is set. rustoshi (types.rs:567) defines it as `String`. JSON-shape
mismatch against modern Core.

Internal inconsistency: rustoshi's `getblockchaininfo.warnings`
(types.rs:1039) IS `Option<Vec<String>>` — so the same node returns
`warnings` as an array from `getblockchaininfo` and as a string from
`getmininginfo`.

**File:** `crates/rpc/src/types.rs:567` (`MiningInfo.warnings: String`),
`crates/rpc/src/types.rs:1039` (`BlockchainInfo.warnings: Option<Vec<String>>`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:443-450`.

**Impact:** tooling that strict-parses against Core 28+ schema
breaks on `getmininginfo`. Internal type inconsistency for the same
JSON key across two RPCs.

---

## BUG-25 (P2) — `getmininginfo` missing `signet_challenge` on signet

**Severity:** P2. Bitcoin Core (mining.cpp:435):

```cpp
{RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true,
 "The block challenge (aka. block script), in hexadecimal (only present if the current network is a signet)"},
```

`MiningInfo` (types.rs:547-568) has no `signet_challenge` field.
Cross-cite BUG-10 (also missing from GBT response). Signet operators
have no in-RPC way to read the network's signet challenge.

**File:** `crates/rpc/src/types.rs:547-568`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:435`.

**Impact:** signet-mining workflow blind to which challenge is in
play. Cross-cite BUG-6 (`signet` rule unenforced), BUG-10 (GBT
challenge missing).

---

## Summary

**Bug count:** 25 (BUG-1 through BUG-25).

**Severity distribution:**
- **P0-CDIV:** 7 (BUG-2, BUG-3, BUG-6, BUG-11, BUG-16, BUG-17 + BUG-11
  is P0-CDIV-MINER specifically)
- **P1:** 8 (BUG-1, BUG-5, BUG-13, BUG-14, BUG-15, BUG-18, BUG-19,
  BUG-23)
- **P2:** 9 (BUG-4, BUG-7, BUG-8, BUG-9, BUG-10, BUG-12, BUG-21,
  BUG-22, BUG-24, BUG-25)
- **P3:** 1 (BUG-20)

Total: 6 P0-CDIV + 1 P0-CDIV-MINER + 8 P1 + 9 P2 + 1 P3 = 25. (BUG-11
is single-counted under P0-CDIV-MINER which is a P0-CDIV variant.)

**Fleet patterns confirmed:**
- "carry-forward re-anchor" (5 instances this wave): BUG-3 (W108 G1
  / W154 BUG-15, 3rd flag); BUG-4 (W108 G3 / W154 BUG-17, 3rd flag);
  BUG-7 (W108 G4/G5 / W154 BUG-15, 3rd flag); BUG-8 (W123 G13 /
  W154 BUG-12, 3rd flag); **BUG-11 (W142 BUG-13 / W108 G11 / W123 G3
  / W154 BUG-9, 5TH flag — regression tests STILL `#[ignore]`-d 6+
  weeks)**; BUG-12 (W123 G11 / W154 BUG-11, 3rd flag); BUG-13 (W123
  G8 / W154 BUG-8, 3rd flag); BUG-22 (W123 G18 / W154 BUG-25, 3rd
  flag); BUG-16 (W154 BUG-13, 2nd flag).
- "comment-as-confession" (3 new instances this wave): BUG-13
  ("would need to look up from mempool"); BUG-21 ("would need to
  compute from recent blocks"); BUG-23 (comment claims Core emits
  `0.00000001` when Core actually emits `0.00001000`). Total ~11
  blockbrew/rustoshi instances across waves.
- "dead-data plumbing" (BUG-16): `vbavailable` always-empty due to
  `get_state_for::<NoBlock>(None, ...)` pattern; deployments are
  defined in `get_deployments(&state.params)` but never reachable
  with a real chain context in the GBT path.
- "dead parameter" (BUG-3, BUG-5, BUG-6, BUG-7): `_params:
  Option<serde_json::Value>` is a single dead parameter blocking
  4+ distinct BIP-22/BIP-23 features.
- "1000× unit confusion" (BUG-23 + cross-cite W154 BUG-6): both
  `block_min_fee_rate` (assembler) AND `blockmintxfee` (RPC) are
  1000× wrong in the same direction; partially-cancelling gap that
  exposes itself only on fleet comparison.
- "wiring-look-but-no-wire" (BUG-21): `getnetworkhashps` exists
  in-impl, `getmininginfo` could call it directly but hardcodes
  `0.0`.
- "asymmetric wire-shape" (BUG-24): `warnings` is `String` in
  `MiningInfo` but `Option<Vec<String>>` in `BlockchainInfo` — same
  node emits same field with different types depending on RPC.
- "missing pre-process compatibility" (BUG-17):
  `UpdateUncommittedBlockStructures` absent — Core-format submissions
  rejected.
- "two-pipeline guard" extension (BUG-15): GBT `curtime` from raw
  `SystemTime::now()` vs Core's `max(mintime, NodeClock::now())`
  clamp. Adjacent pipelines (assembler and RPC response) both lack
  the clamp.

**Top three findings:**

1. **BUG-11 (P0-CDIV-MINER) — `default_witness_commitment` gated on
   `has_witness` not `segwit_active`.** This is the **FIFTH
   carry-forward** of W142 BUG-13 (W108 G11 → W123 G3 → W154 BUG-9
   → W155 BUG-11), with regression tests `#[ignore]`-d in the repo
   for 6+ weeks. Empty-mempool segwit-active GBT returns templates
   miners cannot complete, then those blocks fail
   `bad-witness-merkle-match` on the wire. Fleet-wide note: the
   priority next-fix list across the last three quad-runs has
   included this same bug each time; it has not landed.

2. **BUG-2 + BUG-1 + BUG-6 cluster (P0-CDIV pre-template gating
   absent).** Three separate gates Core enforces — `!isTestChain &&
   GetNodeCount==0` (BUG-1, P1), `!isTestChain && isInitialBlockDownload`
   (BUG-2, P0-CDIV CVE-class), and `signet ∈ rules on signet chains`
   (BUG-6, P0-CDIV) — all silently bypassed. BUG-2 is the
   highest-impact: a fresh-IBD rustoshi node serves templates against
   stale tips, miners burn PoW on doomed blocks, and the
   `RPC_CLIENT_IN_INITIAL_DOWNLOAD` gate that Bitcoin Core PR #6571
   added in 2015 to prevent exactly this scenario is just absent
   in rustoshi. BUG-6 compounds with BUG-10 (signet_challenge
   missing from GBT) to leave signet mining via rustoshi
   structurally non-functional.

3. **BUG-3 + BUG-4 + BUG-7 + BUG-8 cluster (BIP-22/BIP-23
   wire-protocol gap, 5 distinct carry-forwards).** Single root
   cause: `_params: Option<serde_json::Value>` is a dead parameter
   on `get_block_template`. Long-poll never wired (BUG-3), longpollid
   format diverges (BUG-4), proposal mode not dispatched (BUG-7),
   capabilities array absent (BUG-8). Three of these (BUG-3, BUG-7,
   BUG-8) have been flagged in three consecutive waves
   (W108 / W154 / W155). The combined effect: rustoshi's GBT
   surface is a thin BIP-22 v0 implementation missing every feature
   added in BIP-23 and beyond.

**Carry-forward summary (5 distinct instances):**
- W142 BUG-13 → BUG-11 (5th wave, 6+ weeks open, regression tests
  on disk and `#[ignore]`-d)
- W108 G1 / W154 BUG-15 → BUG-3 (3rd wave)
- W108 G3 / W154 BUG-17 → BUG-4 (3rd wave)
- W108 G4 / W154 BUG-15 → BUG-7 (3rd wave)
- W123 G13 / W154 BUG-12 → BUG-8 (3rd wave)
- W123 G11 / W154 BUG-11 → BUG-12 (3rd wave)
- W123 G8 / W154 BUG-8 → BUG-13 (3rd wave)
- W123 G18 / W154 BUG-25 → BUG-22 (3rd wave)
- W154 BUG-13 → BUG-16 (2nd wave)

Recommended fix priority order (smallest LOC × highest blast radius):
1. **BUG-2** (P0-CDIV, ~3 LOC) — wire `state.is_ibd` check into GBT
   entry. Closes the CVE-class fresh-IBD gap.
2. **BUG-11** (P0-CDIV-MINER, ~3 LOC) — change
   `if has_witness {` to `if params.is_segwit_active(height) {` at
   block_template.rs:598. Closes 5-wave carry-forward.
3. **BUG-17** (P0-CDIV, ~15 LOC) — port
   `UpdateUncommittedBlockStructures` into `submit_block`. Closes
   Core-format submission rejection.
4. **BUG-21** (P2, ~2 LOC) — wire `get_network_hash_ps` into
   `getmininginfo`.
5. **BUG-23** (P1, ~1 LOC) — `BtcAmount::from_sats(1000)` instead
   of `from_sats(1)`.
6. **BUG-13** (P1, ~5 LOC) — populate per-tx `fee` from mempool.
7. **BUG-12** (P2, ~10 LOC) — populate per-tx `depends` array.
8. **BUG-14** (P1, ~5 LOC) — add BIP-94 timewarp clamp to mintime.
9. **BUG-16** (P0-CDIV, ~30 LOC) — plumb a real chain-tip context
   into `get_state_for` for the GBT-response `vbavailable` and
   `rules` builders.
