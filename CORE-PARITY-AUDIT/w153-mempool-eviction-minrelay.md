# W153 — Mempool eviction + tx-removed signals + min-relay fee (rustoshi)

**Wave:** W153 — `CTxMemPool::TrimToSize`, `CTxMemPool::Expire`,
`CTxMemPool::GetMinFee`, `CTxMemPool::trackPackageRemoved`,
`CTxMemPool::removeForReorg`, `CTxMemPool::removeForBlock`,
`CTxMemPool::removeRecursive`, `CTxMemPool::removeUnchecked`,
`CTxMemPool::RemoveStaged`, `MemPoolRemovalReason` enum
(EXPIRY/SIZELIMIT/REORG/BLOCK/CONFLICT/REPLACED), `LimitMempoolSize`
(validation.cpp:264), `MaybeUpdateMempoolForReorg`,
`m_opts.max_size_bytes` (`DEFAULT_MAX_MEMPOOL_SIZE_MB=300`),
`m_opts.expiry` (`DEFAULT_MEMPOOL_EXPIRY_HOURS=336` = 14 days),
`m_opts.min_relay_feerate` (`DEFAULT_MIN_RELAY_TX_FEE=100` sat/kvB),
`m_opts.incremental_relay_feerate` (`DEFAULT_INCREMENTAL_RELAY_FEE=100`
sat/kvB), `ROLLING_FEE_HALFLIFE=12h`, `rollingMinimumFeeRate` +
`blockSinceLastRollingFeeBump`, `MAX_REPLACEMENT_CANDIDATES=100`,
`TransactionRemovedFromMempool` / `TransactionAddedToMempool` signals →
fee-estimator + ZMQ `hashtx`/`rawtx`/`sequence` + REST `/rest/mempool/*`
+ tx-relay rebroadcast set, `prioritisetransaction` RPC,
`-minrelaytxfee` / `-incrementalrelayfee` / `-maxmempool` /
`-mempoolexpiry` CLI knobs.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txmempool.h:212` — `static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12;`
  (12 hours; public for tests).
- `bitcoin-core/src/txmempool.h:208, 452` — `CFeeRate GetMinFee(size_t sizelimit) const`
  and the no-arg overload `GetMinFee() { return GetMinFee(m_opts.max_size_bytes); }`.
- `bitcoin-core/src/txmempool.h:460` —
  `void TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining = nullptr)
   EXCLUSIVE_LOCKS_REQUIRED(cs);`
- `bitcoin-core/src/txmempool.h:584-590` —
  `void RemoveStaged(setEntries& stage, MemPoolRemovalReason reason)`,
  `removeRecursive`, `removeUnchecked` — all take a MemPoolRemovalReason.
- `bitcoin-core/src/txmempool.cpp:829-851` — `GetMinFee` definition:
  short-circuits on `!blockSinceLastRollingFeeBump || rollingMinimumFeeRate==0`,
  decays at most every 10s, halflife shrinks by 4× when usage<limit/4 and
  by 2× when usage<limit/2, zeros below `incremental_relay_feerate/2`,
  returns `max(rolling, incremental_relay_feerate)`.
- `bitcoin-core/src/txmempool.cpp:853-859` — `trackPackageRemoved(rate)`:
  if `rate.GetFeePerK() > rollingMinimumFeeRate` then bump and clear
  `blockSinceLastRollingFeeBump`.
- `bitcoin-core/src/txmempool.cpp:861-911` — `TrimToSize`: while usage>limit,
  find `GetWorstMainChunk()`, add `incremental_relay_feerate` to its rate,
  call `trackPackageRemoved`, then `removeUnchecked(MemPoolRemovalReason::SIZELIMIT)`
  for every entry in the chunk.
- `bitcoin-core/src/validation.cpp:264-278` — `LimitMempoolSize`:
  - `pool.Expire(GetTime<seconds>() - pool.m_opts.expiry)`,
  - then `pool.TrimToSize(pool.m_opts.max_size_bytes, &vNoSpendsRemaining)`,
  - then `coins_cache.Uncache(removed)` for the freed prevouts.
- `bitcoin-core/src/validation.cpp:1397` — called from `AcceptSingleTransaction`
  AFTER `Finalize` so every successful ATMP runs the limit pass.
- `bitcoin-core/src/validation.cpp:294-426` — `MaybeUpdateMempoolForReorg`:
  walks disconnected-block txs, calls `MemPoolAccept::AcceptSingleTransaction`
  on each (re-admission), then `LimitMempoolSize`, then
  `mempool.removeForReorg(active_chain, filter)` to drop any tx whose
  CSV/CLTV/coinbase-maturity is no longer satisfied at the NEW tip.
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-21` —
  `enum class MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG, BLOCK,
  CONFLICT, REPLACED };` + `RemovalReasonToString`.
- `bitcoin-core/src/kernel/mempool_options.h:19,23,40-44` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB{300}`,
  `DEFAULT_MEMPOOL_EXPIRY_HOURS{336}`,
  `max_size_bytes = 300 * 1'000'000` (SI MB, not MiB),
  `expiry = std::chrono::hours{336}`,
  `incremental_relay_feerate = CFeeRate(DEFAULT_INCREMENTAL_RELAY_FEE)`,
  `min_relay_feerate = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE)`.
- `bitcoin-core/src/policy/policy.h:48, 70` —
  `DEFAULT_INCREMENTAL_RELAY_FEE{100}` sat/kvB,
  `DEFAULT_MIN_RELAY_TX_FEE{100}` sat/kvB (i.e. 0.1 sat/vB; the
  10-year-stale `1000` number in pop articles is wrong since 2017's
  policy/policy.h refactor).
- `bitcoin-core/src/policy/feerate.h:31-48` — `class CFeeRate` constructs
  from sat/kvB; `CFeeRate(100)` = 100 sat per 1000 vbytes = 0.1 sat/vB.
- `bitcoin-core/src/wallet/wallet.h:124` —
  `WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB = 5 sat/vB (NOT 1000).
- `bitcoin-core/src/init.cpp:673, 685` — `-incrementalrelayfee` and
  `-minrelaytxfee` CLI flag registration, both ALLOW_ANY (settable to 0).
- `bitcoin-core/src/init.cpp::-maxmempool`, `-mempoolexpiry` operator knobs.
- `bitcoin-core/src/validation.cpp::CTxMemPool::removeForBlock` — called
  from `BlockConnected` with `MemPoolRemovalReason::BLOCK` for confirmed
  txs and `::CONFLICT` for in-mempool txs that double-spent against the
  block. Sets `blockSinceLastRollingFeeBump=true` so the rolling rate
  starts decaying.
- `bitcoin-core/src/kernel/notifications_interface.h` / `node/interfaces.cpp`
  — `MempoolNotifications`: `TransactionAddedToMempool` and
  `TransactionRemovedFromMempool(tx, reason, mempool_sequence)` fan-out to
  fee-estimator (`CBlockPolicyEstimator::removeTx`), ZMQ
  (`hashtx`/`rawtx`/`sequence`), REST `/rest/mempool/contents`, tx-relay
  rebroadcast tracker, wallet notifications.

**Files audited**
- `crates/consensus/src/mempool.rs` (10 753 LOC) — `Mempool` struct,
  `MempoolConfig` (`:674-749`, `Default` `:717-749` with
  `max_size_bytes = 300 * 1_000_000` ✓ SI MB,
  `expiry_seconds: DEFAULT_MEMPOOL_EXPIRY_SECONDS` ✓ 336h,
  `min_fee_rate: 1` ✗ sat/vB unit, 10× Core,
  `incremental_relay_fee: DEFAULT_INCREMENTAL_RELAY_FEE=100` ✓ but
  doc-comment lies about unit), `DEFAULT_INCREMENTAL_RELAY_FEE`
  (`:101` = 100 sat/kvB ✓ matches Core), `ROLLING_FEE_HALFLIFE`
  (`:105` = 60*60*12 ✓), `DEFAULT_MEMPOOL_EXPIRY_SECONDS` (`:603` =
  336*3600 ✓), rolling-fee state (`:1210-1223`
  `rolling_minimum_fee_rate`, `block_since_last_rolling_fee_bump`,
  `last_rolling_fee_update`; init `:1268-1270`),
  `track_package_removed` (`:2940-2945`),
  `get_min_fee` (`:2961-3010`),
  `trim_to_size` (`:3022-3061`),
  `expire` (`:2894-2931`),
  `remove_for_reorg` (`:3074-3112`),
  `notify_block_connected` (`:3122-3124`),
  `remove_for_block` (`:2247-2265`),
  `block_disconnected` (`:2294-2328`),
  `remove_single` (`:2171-2213`),
  `remove_transaction` (`:2077-…`),
  `prioritise_transaction` (`:3269-3287`),
  `clear_prioritisation` (`:3324-3326`),
  `apply_pending_delta` (`:3312-3318`),
  `notify_new_tip` (`:1299-1302`),
  pre-flight min-fee gate (`:1713-1718`).
- `crates/consensus/src/params.rs:113` —
  `pub const DEFAULT_MIN_RELAY_TX_FEE: u64 = 1_000;` ← 10× Core (100).
- `crates/network/src/relay.rs` — duplicate constants:
  `:66 DEFAULT_MIN_RELAY_FEE: u64 = 1000;` (10× Core),
  `:72 DEFAULT_INCREMENTAL_RELAY_FEE: u64 = 1000;` (10× Core,
  AND inconsistent with the consensus crate's own `100`!),
  `FeeFilterRounder` (`:150`), `pays_for_rbf` (`:296-326`),
  `get_fee` / `get_fee_rate` (`:333-347`),
  `FeeFilterState::maybe_send_feefilter` (`:211-266`,
  fee_filter_sent gate),
  `FeeFilterManager::new`/`set_min_relay_fee` (`:355-471`).
- `crates/network/src/peer_manager.rs:2220-2227` —
  `send_initial_feefilter` HARDCODES `100_000` sat/kvB (= 100 sat/vB,
  1000× Core's default 0.1 sat/vB) and ignores the mempool's
  `incremental_relay_fee` / `min_fee_rate` / `rolling_minimum_fee_rate`.
- `crates/consensus/src/mempool_persist.rs` (937 LOC) — `dump_mempool`
  (`:177-…`), `dump_mempool_with_key` (`:192-…`), `load_mempool`
  (`:286-…`). Load path accepts entries regardless of `time_seconds` age.
- `crates/consensus/src/fee_estimator.rs` (996 LOC) —
  `FeeEstimator::track_transaction` (`:410`), `process_block` (`:423`).
  No `remove_tx` / `on_remove` hook.
- `crates/rpc/src/server.rs` — RPC + reorg + submitblock plumbing,
  `sendrawtransaction` (`:3699-3736`, calls `track_transaction` ONLY on
  successful add, never on remove), `submitblock` (`:4404-4577`, calls
  `fee_estimator.process_block` BUT NOT `mempool.remove_for_block` or
  `mempool.notify_block_connected`), `mine_single_block` (`:9605-9609`,
  per-tx `remove_transaction` but no `block_spent_outpoints`),
  reorg path (`:1450-1481` + `:1825-1875`, calls `mempool.block_disconnected`
  but NOT `remove_for_reorg` and NOT `notify_block_connected`),
  `get_mempool_info` (`:3814-3838`, hardcoded `1000` mempoolminfee +
  hardcoded `300*1024*1024` MiB maxmempool — wrong unit),
  `prioritise_transaction` (`:7064-7082`).
- `crates/rpc/src/rest.rs:761-782` — `rest_mempool_info`
  (hardcoded `maxmempool=300_000_000`, `mempoolminfee=0.00001 BTC/kvB`).
- `crates/rpc/src/zmq.rs:191-340, 567-570, 1013` —
  `ZmqCommand::NotifyTransaction`, `ZmqPublisher::notify_transaction`.
  Zero production callsites.
- `rustoshi/src/main.rs:1915-1944` — startup load_mempool.
- `rustoshi/src/main.rs:4280-4294` — shutdown dump_mempool.

---

## Gate matrix (32 sub-gates / 10 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Per-tx pre-flight min-fee gate (Core PreChecks:948) | G1: rejects tx with feerate < `min_relay_feerate` | PARTIAL — pre-flight at `mempool.rs:1713-1718` checks `min_fee_rate` ONLY, never `rolling_minimum_fee_rate` (BUG-3) |
| 1 | … | G2: feerate compared on integer sat/kvB, not floor(sat/vB) | **BUG-1 (P0-CDIV)** — `(fee_rate as u64) < self.config.min_fee_rate` casts a fractional sat/vB to u64 (truncates 0.5 → 0) and compares to a sat/vB-unit config (`min_fee_rate: 1`). Any tx paying <1 sat/vB is rejected; Core's threshold is 0.1 sat/vB (10× looser) |
| 1 | … | G3: `bypass_limits` (reorg refill) skips the gate | PASS (`mempool.rs:1713`) |
| 2 | LimitMempoolSize (Expire + TrimToSize + Uncache) | G4: called from every successful ATMP | **BUG-2 (P0)** — `mempool.expire()` is implemented (`:2894-2931`) but has ZERO production callsites; the only callers are tests in the same file. `LimitMempoolSize` analogue does not exist |
| 2 | … | G5: `Expire(now - expiry_seconds)` reaps stale txs ≥14 days old | **BUG-2 cross-cite** — code exists, never invoked. Mempool retains txs indefinitely past the 336h horizon |
| 2 | … | G6: `TrimToSize(max_size_bytes)` after every ATMP | PARTIAL — `trim_to_size` is called only from inside `add_transaction_with_options` (`:1959, 4381`), and only when the *next* admission would push past the limit. Core runs it after EVERY ATMP (including ones below the limit) so the rolling-fee bumps propagate (BUG-2) |
| 2 | … | G7: Uncache(removed prevouts) from CoinsTip after trim | **BUG-4 (P1)** — `pvNoSpendsRemaining` analogue does not exist; no UTXO cache cleanup after trim. Cached coins for evicted txs' prevouts stay hot indefinitely |
| 3 | Rolling-min-fee admission gate | G8: incoming tx fee_rate compared against `get_min_fee()` | **BUG-3 (P0-CDIV) — DEAD SUBSYSTEM** — `get_min_fee()` has ZERO production callsites; only tests call it. `rolling_minimum_fee_rate` is read by no other production code. Bumping it in `trim_to_size` is dead state |
| 3 | … | G9: `notify_block_connected()` flips `block_since_last_rolling_fee_bump=true` | **BUG-5 (P0-CDIV) — DEAD SUBSYSTEM** — `notify_block_connected()` has ZERO production callsites. `submitblock` (`server.rs:4404+`), `mine_single_block` (`server.rs:9491+`), reorg paths (`server.rs:1450+/1825+`) all skip it. Rolling rate, even if it were checked, would never decay |
| 4 | Default constants vs Core | G10: `DEFAULT_MAX_MEMPOOL_SIZE_MB = 300` (SI MB) | PASS (`mempool.rs:722` `300 * 1_000_000`) |
| 4 | … | G11: `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336` (14d) | PASS (`mempool.rs:603, 723`) — value correct, but dead per BUG-2 |
| 4 | … | G12: `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB | **BUG-6 (P0-CDIV)** — rustoshi defines this in THREE places, all wrong: `params.rs:113 = 1_000` (10×), `network/relay.rs:66 = 1000` (10×), and the consensus `MempoolConfig::default().min_fee_rate = 1 sat/vB = 1000 sat/kvB` (10×). N-pipeline drift on the same constant |
| 4 | … | G13: `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB | **BUG-7 (P1)** — `consensus/mempool.rs:101 = 100` ✓ correct, but `network/relay.rs:72 = 1000` ✗ disagrees with the consensus crate. Two-pipeline guard 17th distinct extension within rustoshi |
| 4 | … | G14: `ROLLING_FEE_HALFLIFE = 12 * 3600` seconds | PASS (`mempool.rs:105`) — value correct, but dead per BUG-3/BUG-5 |
| 5 | MemPoolRemovalReason taxonomy | G15: enum present with EXPIRY/SIZELIMIT/REORG/BLOCK/CONFLICT/REPLACED | **BUG-8 (P0-CDIV)** — `MemPoolRemovalReason` enum DOES NOT EXIST anywhere in rustoshi. Every removal path (`remove_single`, `remove_transaction`, `remove_for_block`, `trim_to_size`, `expire`, `remove_for_reorg`, `block_disconnected`) takes no reason argument. Cross-referenced by an existing W120 test ignore-stub (`test_w120_mempool_rbf.rs:59,964,973`) |
| 5 | … | G16: removal callsites tag reason for ZMQ `sequence` event | **BUG-8 cross-cite** |
| 6 | TransactionRemovedFromMempool signal fan-out | G17: fee-estimator `removeTx(hash, in_block=false)` on RBF replacement | **BUG-9 (P0-CDIV)** — `fee_estimator.track_transaction(txid, fee_rate)` is the only mempool→estimator hook; called once per successful ATMP at `server.rs:3736`. There is no `fee_estimator.remove_tx` or `on_remove` callback. Cross-referenced by `test_w120_mempool_rbf.rs:723-733` ("BUG-12: fee estimator lacks on_remove hook; RBF-evicted txs linger in tracked map") |
| 6 | … | G18: ZMQ `hashtx`/`rawtx`/`sequence` published on remove | **BUG-10 (P0-CDIV)** — `crates/rpc/src/zmq.rs::notify_transaction` exists fully implemented (`:399, 567`) but has ZERO production callsites — only invoked from a unit test (`zmq.rs:1013`). Mempool `remove_single` / `trim_to_size` / `expire` emit nothing |
| 6 | … | G19: REST `/rest/mempool/contents` consistent with removals | PARTIAL — endpoint reads `state.mempool` directly (`rest.rs:787+`), so removals are reflected; but no event-stream hook (BUG-10 cross) and the `info.json` endpoint hardcodes constants (BUG-14) |
| 6 | … | G20: tx-relay rebroadcast / inflight tracker informed on remove | **BUG-11 (P1)** — no callback from mempool to `InventoryTrickle` / `m_recently_announced_invs` analogue (relay.rs unused in production per W152 BUG-4 — cross-cite). Eviction-then-rebroadcast races are silent |
| 7 | BlockConnected / BlockDisconnected hooks | G21: `mempool.remove_for_block(block_txids, spent_outpoints)` on submitblock | **BUG-12 (P0-CDIV)** — `submitblock` (`server.rs:4404-4577`) calls `fee_estimator.process_block` but NEVER `mempool.remove_for_block`. Mined txs remain in mempool indefinitely; subsequent submit/relay traffic re-sees them; getrawmempool keeps reporting them. `mine_single_block` (`server.rs:9605-9609`) uses per-tx `remove_transaction` instead — different semantics (no double-spend conflict catch) |
| 7 | … | G22: `mempool.notify_block_connected()` on submitblock | **BUG-5 cross-cite** |
| 7 | … | G23: `mempool.remove_for_reorg(filter)` after reorg target | **BUG-13 (P1)** — already documented as W148 BUG-19 / W101 G15: `remove_for_reorg` implemented (`:3074-3112`) with ZERO production callsites. Reorg path (`server.rs:1450-1478`) calls `block_disconnected` (re-admit) but no post-tip filter for CSV/CLTV/coinbase-maturity-invalid txs |
| 8 | Operator knobs (Core init.cpp) | G24: `-minrelaytxfee` CLI flag | **BUG-14 (P1)** — cross-ref W150 BUG-8; no `-minrelaytxfee`, `-incrementalrelayfee`, `-maxmempool`, `-mempoolexpiry` CLI flags in `parseFlags` |
| 8 | … | G25: `-maxmempool` overrides `max_size_bytes` | **BUG-14 cross-cite** |
| 8 | … | G26: `-mempoolexpiry` overrides `expiry_seconds` | **BUG-14 cross-cite** |
| 9 | mempool.dat persistence | G27: shutdown dump | PASS (`main.rs:4280-4294`) |
| 9 | … | G28: startup load | PASS (`main.rs:1915-1944`) |
| 9 | … | G29: load drops txs older than `expiry_seconds` (Core: LoadMempool refuses `nTime < now - expiry`) | **BUG-15 (P1)** — `mempool_persist::load_mempool` (`:286-374`) admits every tx unconditionally regardless of `time_seconds` age. A node restarted after a 30-day offline window would re-admit 30-day-old txs (Core would skip them) |
| 10 | prioritisetransaction RPC + getmempoolinfo | G30: delta updates affect rolling-min comparison | **BUG-16 (P1)** — `prioritise_transaction` (`mempool.rs:3269-3287`) updates `entry.fee_delta` but NOT the rolling-min comparison (which doesn't run anyway per BUG-3). Ancestor `ancestor_fees`/`descendant_fees` are not refreshed either |
| 10 | … | G31: `clear_prioritisation(txid)` called on block confirm | **BUG-17 (P1)** — `clear_prioritisation` (`mempool.rs:3324-3326`) defined but never invoked. Map deltas persist across confirmations; reappearing txid (e.g. via mempool refill on reorg) silently re-applies the stale delta |
| 10 | … | G32: getmempoolinfo / REST `info.json` report live `mempoolminfee` / `maxmempool` | **BUG-18 (P0-CDIV)** — `get_mempool_info` (`server.rs:3814-3838`) HARDCODES `min_fee_rate_sats: u64 = 1000`, `maxmempool: 300 * 1024 * 1024` (MiB, intra-impl mismatch with the config's SI MB), `incrementalrelayfee: 1000` (10× the config's 100). REST `/rest/mempool/info.json` (`rest.rs:761-782`) hardcodes the same wrong values. Both endpoints ignore `state.mempool.config.*` and `rolling_minimum_fee_rate` |

---

## BUG-1 (P0-CDIV) — Min-fee gate compares u64-cast sat/vB to sat/vB constant; 10× too strict + truncation-to-zero

**Severity:** P0-CDIV. Bitcoin Core's `MemPoolAccept::PreChecks` calls
`CheckFeeRate(vsize, modified_fee, ::nMinRelayTxFee)` where
`nMinRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE=100)` = 100 sat/kvB =
0.1 sat/vB. The comparison runs on `CFeeRate` arithmetic (sat * 1000 /
vsize) so a 0.5 sat/vB tx (500 sat/kvB) passes.

rustoshi's pre-flight (`mempool.rs:1705, 1713-1718`):

```rust
let fee_rate = fee as f64 / vsize as f64;
// ...
if !bypass_limits && (fee_rate as u64) < self.config.min_fee_rate {
    return Err(MempoolError::InsufficientFee(
        fee_rate,
        self.config.min_fee_rate,
    ));
}
```

Two compounding bugs in one expression:

1. **Unit mismatch.** `fee_rate` is `fee / vsize` = sat/vB.
   `self.config.min_fee_rate` defaults to `1` and the comment at
   `mempool.rs:683` says "satoshis per virtual byte" (so the literal
   "1" means "1 sat/vB" = 1000 sat/kvB). Core's default is 100 sat/kvB
   = 0.1 sat/vB. **Rustoshi is 10× stricter than Core out of the box.**
2. **Cast truncation.** `(fee_rate as u64)` converts a sub-integer
   sat/vB to an integer. A tx paying 0.7 sat/vB (700 sat/kvB,
   well above Core's 100 sat/kvB floor) becomes `0u64`, fails the
   `0 < 1` check, and is rejected with `InsufficientFee(0.70, 1)`.
   **Every tx in (0, 1) sat/vB is rejected** even when `min_fee_rate`
   is correctly set to 0.

Both bugs hide each other. Fixing the cast (to integer sat/kvB math)
exposes the 10× config, and vice versa.

**Carry-forward.** This is the W150 BUG-8 mention reported by the user
("10× too-strict min-relay-fee"), now anchored to the exact line. W150
BUG-8 framed it as a missing CLI knob; this audit shows the underlying
DEFAULT itself is wrong AND the comparison code is broken even at the
default value.

**File:** `crates/consensus/src/mempool.rs:683, 705-749` (config doc-comment + default),
`crates/consensus/src/mempool.rs:1700-1718` (pre-flight check).

**Core ref:** `bitcoin-core/src/validation.cpp:948` (PreChecks fee gate
via `CheckFeeRate(vsize, modified_fees, ::nMinRelayTxFee)`),
`bitcoin-core/src/policy/policy.h:70`
(`DEFAULT_MIN_RELAY_TX_FEE{100}` sat/kvB).

**Impact:**
- Standard fee-conservative txs (0.1–0.99 sat/vB) silently rejected by
  rustoshi mempool. Wallets, RBF bumps, and CPFP children calibrated
  against Core's floor look like they were rate-limit dropped or
  network-stalled.
- Cross-fleet relay: a rustoshi node receives a 0.5 sat/vB tx from a
  Core peer, drops it, never re-broadcasts. The tx propagates
  everywhere EXCEPT rustoshi.

---

## BUG-2 (P0) — `expire()` and `LimitMempoolSize` analogue absent; mempool retains txs past 336h horizon AND across every ATMP boundary

**Severity:** P0 (DoS amplification: mempool grows past max_size_bytes
between any two trim calls, expired txs sit forever as ancestor anchors
for new admissions).

Bitcoin Core's `LimitMempoolSize` (`validation.cpp:264-278`) runs at
every successful ATMP (line 1397, inside `Finalize`) and at every
`MaybeUpdateMempoolForReorg`. It does TWO things:

```cpp
int expired = pool.Expire(GetTime<seconds>() - pool.m_opts.expiry);
pool.TrimToSize(pool.m_opts.max_size_bytes, &vNoSpendsRemaining);
```

rustoshi has both primitives:
- `mempool::expire(cutoff_secs)` at `:2894-2931`,
- `mempool::trim_to_size(sizelimit)` at `:3022-3061`.

But **`expire` has ZERO production callsites** (grep
`expire(` in `crates/{rpc,network,consensus}/src/` excluding mempool.rs
itself and tests: only `orphanage.expire_orphans`, `peer_manager.expire_bans`,
`rest.evict_expired_offers` — all unrelated subsystems). **`trim_to_size`
runs only as a fast-path inside `add_transaction_with_options`
(`:1959, 4381`) when the next admission would push past the limit** —
never independently, never on the rolling-fee-bump cadence Core requires.

Consequences:
- **Mempool retains txs past the 14-day expiry forever.** A tx admitted
  at t=0 with vsize=1000 and fee=1 sat (`min_fee_rate=0` config in tests
  / `bypass_limits` admission) stays in the index, in `parents`/`children`
  graphs, in `cluster` structures, and contributes to ancestor counts
  for OTHER txs' admission rates — for the life of the process.
- **Rolling-min-fee bumps don't propagate.** Core's `LimitMempoolSize`
  fires the expire-pass + trim-pass together; the trim bumps
  `rolling_minimum_fee_rate` via `track_package_removed`. rustoshi only
  trims when forced, so the rolling-min state is updated infrequently
  even when correctly wired (which it isn't, per BUG-3 / BUG-5).
- **Per-ATMP cleanup absent.** Core trims after every ATMP so the rolling
  rate stays current; rustoshi only trims at the threshold boundary, so
  a series of 1000 admissions each under the limit never triggers a
  bump. Combined with BUG-3 this is dead-code-on-dead-data, but if BUG-3
  were fixed alone (rolling rate consulted on admission), this would
  still under-bump.

**File:** `crates/consensus/src/mempool.rs:2894` (expire definition),
`crates/consensus/src/mempool.rs:3022` (trim_to_size definition),
`crates/consensus/src/mempool.rs:1959, 4381` (only callers, both inside
add_transaction).

**Core ref:** `bitcoin-core/src/validation.cpp:264-278` (LimitMempoolSize),
`bitcoin-core/src/validation.cpp:1397` (Finalize → LimitMempoolSize).

**Impact:** unbounded retention of expired txs; memory leak per
2-week-old admission; rolling-fee gate (when fixed) would still
under-bump.

---

## BUG-3 (P0-CDIV) — `rolling_minimum_fee_rate` is dead data; `get_min_fee()` has zero production callers; admission ignores the rolling floor

**Severity:** P0-CDIV ("dead-data plumbing" fleet pattern, ~5th distinct
rustoshi instance; first rolling-fee instance fleet-wide).

The rolling-min-fee subsystem (state at `mempool.rs:1210-1223`, bump
logic at `:2940-2945`, decay at `:2961-3010`, mutation in trim_to_size
at `:3044-3046`) is **all five components present and unit-tested**
(tests `:9943, 10003, 10020, 10048, 10076`).

But the admission pre-flight at `:1713-1718` checks ONLY
`self.config.min_fee_rate` — a static config value. Grep for
`get_min_fee()` callsites in `crates/{rpc,network,consensus}/src/`
excluding mempool.rs and tests returns zero hits. Grep for
`rolling_minimum_fee_rate` outside mempool.rs returns zero hits.

The result: `trim_to_size` correctly bumps `rolling_minimum_fee_rate`
each time it evicts a chunk, but no incoming-tx admission path ever
consults the bumped value. **A loaded mempool that just evicted at
5 sat/vB will happily admit the next tx at 1 sat/vB.** Core's behaviour
is to reject it with `mempool min fee not met`.

Cross-cite to BUG-2: even if admission DID consult `get_min_fee`, the
rolling rate would rarely be bumped because `trim_to_size` rarely runs
(only on the exact admission that crosses the limit).

**File:** `crates/consensus/src/mempool.rs:1713-1718` (admission gate
missing the rolling check), `:2961-3010` (get_min_fee — never called),
`:1210-1223` (state — never read by consumer).

**Core ref:** `bitcoin-core/src/txmempool.cpp:829-851` (GetMinFee),
`bitcoin-core/src/validation.cpp::CheckFeeRate` (admission gate
consults `pool.GetMinFee()` as well as `nMinRelayTxFee`).

**Excerpt (rustoshi, gate missing rolling check)**
```rust
// :1713 — only static config consulted
if !bypass_limits && (fee_rate as u64) < self.config.min_fee_rate {
    return Err(MempoolError::InsufficientFee(...));
}
// MISSING: let mempool_min = self.get_min_fee();
//          if !bypass_limits && fee_rate_sat_kvb < mempool_min {
//              return Err(MempoolError::InsufficientFee(...));
//          }
```

**Impact:** rolling-min-fee gate completely absent; DoS surface widened
during mempool pressure events (mempool fills, evicts at 50 sat/vB,
then accepts 1 sat/vB txs that immediately get re-evicted, forming a
slot-thrashing loop). The W149 "Lua-double precision echo" pattern
applies in reverse: the decay math is correct, just nobody consults it.

---

## BUG-4 (P1) — `pvNoSpendsRemaining` Uncache absent after trim; CoinsTip leaks cached prevouts

**Severity:** P1. Bitcoin Core's `LimitMempoolSize` (`validation.cpp:276-277`)
passes `&vNoSpendsRemaining` to `TrimToSize`, then calls
`coins_cache.Uncache(removed)` for every prevout that was held in the
hot UTXO cache only because a now-evicted mempool tx spent it. This
matters for IBD where the CoinsTip cache is bounded.

rustoshi's `trim_to_size` (`:3022-3061`) has no parameter for
"prevouts no longer spent by anything in the mempool". `remove_single`
(`:2171-2213`) clears `self.spent_outpoints` (the in-mempool
spent-outpoint map) but never signals up to the UTXO cache.

There is no `coins_cache.Uncache` analogue in `crates/storage` or
`crates/consensus`, but there IS a UTXO cache layer (`utxo_view`,
`flush()`) — it just doesn't expose an `Uncache` API for hot prevouts.

**File:** `crates/consensus/src/mempool.rs:3022-3061` (TrimToSize without
prevout-out param); cross-file gap to `crates/storage/src/utxo_view.rs`
(no Uncache API).

**Core ref:** `bitcoin-core/src/validation.cpp:264-278`
(`LimitMempoolSize` → `coins_cache.Uncache(removed)`).

**Impact:** UTXO cache bloat after mempool churn; correctness-neutral
but degrades IBD-recovery performance on a tx-heavy node post-restart.

---

## BUG-5 (P0-CDIV) — `notify_block_connected()` never called; `block_since_last_rolling_fee_bump` stuck false; even fixing BUG-3 wouldn't decay the rolling rate

**Severity:** P0-CDIV ("dead-helper-at-call-site" — Core W141 fleet
pattern echo). `mempool.rs:3122-3124`:

```rust
pub fn notify_block_connected(&mut self) {
    self.block_since_last_rolling_fee_bump = true;
}
```

This is the **only** mutator that flips `block_since_last_rolling_fee_bump`
from false to true; `track_package_removed` only flips it back to false.
`get_min_fee` short-circuits at line 2965 on
`!block_since_last_rolling_fee_bump`, so until this method runs, the
decay logic at line 2983-3003 is never reached.

But `notify_block_connected()` has **zero production callsites**.
Grep across `crates/{rpc,network,consensus}/src/` excluding mempool.rs
and tests: not found. The block-connect callsite in
`crates/rpc/src/server.rs:4404-4577` (submitblock) updates
`state.best_height`, persists, calls `fee_estimator.process_block`,
but does not call `state.mempool.notify_block_connected()`.

So even if BUG-3 were closed (admission consults `get_min_fee`), the
rolling rate, once bumped by a trim, would **never decay** because the
short-circuit always fires. The "comment-as-confession" at `:3119`
("implicit via the connected-block path") is incorrect — there is no
connected-block path in rustoshi that wires this.

**File:** `crates/consensus/src/mempool.rs:3122-3124` (defined never
called); `crates/rpc/src/server.rs:4404-4577` (submitblock — should call);
`crates/rpc/src/server.rs:9491-…` (mine_single_block — also should
call); reorg paths `server.rs:1450, 1825`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::removeForBlock`
(implicitly flips `blockSinceLastRollingFeeBump = true` via the
connected-block path).

**Impact:** rolling-fee decay non-functional independently of BUG-3.
Once both are closed, this becomes the load-bearing constant; today
it's dead.

---

## BUG-6 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE` defined in 3 places, all 10× too strict; N-pipeline drift on a single value

**Severity:** P0-CDIV (cross-fleet relay divergence; N-pipeline drift
fleet pattern, 4th distinct instance — extends from the W142
"three-pipeline drift" cluster).

Three independent definitions of the SAME constant in rustoshi, ALL
disagreeing with Core's `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB:

| Site | Symbol | Value | Unit | Core value | Drift |
|------|--------|-------|------|-----------|-------|
| `consensus/params.rs:113` | `DEFAULT_MIN_RELAY_TX_FEE` | `1_000` | sat/kvB (comment) | 100 sat/kvB | **10× too strict** |
| `network/relay.rs:66` | `DEFAULT_MIN_RELAY_FEE` | `1000` | sat/kvB (comment) | 100 sat/kvB | **10× too strict** |
| `consensus/mempool.rs::MempoolConfig::default().min_fee_rate` | `1` | sat/vB (comment) | 100 sat/kvB = 0.1 sat/vB | **10× too strict** |

The `params.rs` value is never read (defined-but-not-consulted — DEAD
DATA). The `network/relay.rs` value is consumed by
`FeeFilterManager`, which is itself dead per W152 BUG-4. The
`MempoolConfig::default()` value IS the live one — and it's wrong, as
explained in BUG-1.

This is a perfect "comment-as-confession" amplifier: three sites all
documenting the value as Core-compatible while disagreeing with Core
AND each other. The unit string differs across the three sites (sat/kvB
vs sat/vB) which makes the drift hard to see without cross-referencing.

**File:** `crates/consensus/src/params.rs:113`,
`crates/network/src/relay.rs:66, 1274, 1422, 1487, 1516`,
`crates/consensus/src/mempool.rs:683, 724`.

**Core ref:** `bitcoin-core/src/policy/policy.h:70`,
`bitcoin-core/src/init.cpp:685` (`-minrelaytxfee` default).

**Impact:** rustoshi's relay floor is 10× stricter than Core; tx-relay
divergence on the wire (rustoshi will not relay sub-1 sat/vB txs that
Core relays freely). Cross-cite W150 BUG-8 (no `-minrelaytxfee` CLI
knob to fix it operationally).

---

## BUG-7 (P1) — `DEFAULT_INCREMENTAL_RELAY_FEE` differs between consensus crate (correct) and network crate (10× too strict); two-pipeline guard 17th distinct extension

**Severity:** P1 ("two-pipeline guard 17th distinct extension" —
extends from W148 pattern tracker; first time the SAME-named
constant disagrees across crates).

- `consensus/mempool.rs:101` —
  `pub const DEFAULT_INCREMENTAL_RELAY_FEE: u64 = 100;` ✓ matches Core.
- `network/relay.rs:72` —
  `pub const DEFAULT_INCREMENTAL_RELAY_FEE: u64 = 1000;` ✗ disagrees
  with Core AND with the consensus crate's own definition.

Both constants are exported under the same name. They are consumed by
different subsystems (relay layer vs mempool admission) and they
disagree. Code that imports one and reasons about the other gets the
math wrong without compile-time signal.

Cross-fleet relay impact mirrors BUG-6 for incremental-relay-fee
specifically: the FeeFilterRounder constructed from the network
constant computes wrong buckets, but it's behind the W152 BUG-4 dead
FeeFilterManager so it doesn't bite production today.

**File:** `crates/consensus/src/mempool.rs:101` (correct),
`crates/network/src/relay.rs:72` (10× wrong).

**Core ref:** `bitcoin-core/src/policy/policy.h:48`.

**Impact:** when the relay subsystem is eventually wired (closing
W152 BUG-4), the FeeFilterManager will advertise a 10× wrong filter to
peers. Operator-debugging will see "rustoshi advertises 1 sat/vB
feefilter while its own mempool admits at 1 sat/vB" — coherent looking
but jointly 10× off.

---

## BUG-8 (P0-CDIV) — `MemPoolRemovalReason` enum entirely absent; no removal-reason taxonomy

**Severity:** P0-CDIV (signal fan-out blocker; observable wire
divergence on every ZMQ `sequence` event).

Bitcoin Core defines `MemPoolRemovalReason` (kernel/mempool_removal_reason.h)
with six variants — EXPIRY, SIZELIMIT, REORG, BLOCK, CONFLICT, REPLACED.
Every removal function takes the reason as a parameter:

```cpp
void removeUnchecked(txiter entry, MemPoolRemovalReason reason);
void RemoveStaged(setEntries& stage, MemPoolRemovalReason reason);
void removeRecursive(const CTransaction& tx, MemPoolRemovalReason reason);
```

The reason fans out to:
- `CBlockPolicyEstimator::removeTx(hash, in_block)` (in_block=true for
  BLOCK, false for everything else),
- ZMQ `sequence` topic event-label (`R` for removed, plus the reason
  string),
- REST `/rest/mempool/contents` streaming notifications,
- wallet's `TransactionRemovedFromMempool(tx, reason, mempool_seq)`,
- tx-relay rebroadcast tracker (clear from `m_relay_to_set` on REPLACED
  but not on BLOCK),
- mempool-sequence counter increment (signals tx index gap to
  consumers).

rustoshi: **the enum does not exist anywhere**. Grep
`MemPoolRemovalReason` across `crates/`: only `test_w120_mempool_rbf.rs`
mentions it as a known-absent feature (BUG-15 in that test file's
header doc). `remove_single`, `remove_transaction`, `remove_for_block`,
`trim_to_size`, `expire`, `remove_for_reorg`, `block_disconnected` are
all reason-less — they remove silently.

Consequence: every removal looks identical to every downstream
consumer (which itself doesn't exist per BUG-9/BUG-10/BUG-11, so the
gap is currently hidden, but the bug-cascade unwinds in that order).

**File:** absent. Should be defined in
`crates/consensus/src/mempool.rs` near the error enum at `:870-`.

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h`.

**Impact:** blocks BUG-9, BUG-10, BUG-11 from being fixable
correctly. ZMQ + REST consumers cannot distinguish "evicted for size"
from "confirmed in block" from "RBF-replaced".

---

## BUG-9 (P0-CDIV) — Fee estimator has no `on_remove` hook; RBF / eviction / expiry tracked txs linger in estimator state forever

**Severity:** P0-CDIV (silent fee-estimation skew on every RBF/eviction
event).

Bitcoin Core's `CBlockPolicyEstimator` overrides
`TransactionRemovedFromMempool(tx, reason, mempool_seq)` (policy/fees/block_policy_estimator.cpp:586)
and calls `removeTx(tx->GetHash(), /*inBlock=*/false)` for every
non-BLOCK removal. This evicts the tx from the per-bucket tracked map
so its non-confirmation isn't held against the estimator's confirmation
ratio.

rustoshi's `FeeEstimator` (`crates/consensus/src/fee_estimator.rs`)
has exactly one mempool-derived input: `track_transaction(txid, fee_rate)`
called at `crates/rpc/src/server.rs:3736` — once per successful
`sendrawtransaction`. There is no `remove_tx`, no `on_remove`, no
`TransactionRemovedFromMempool` callback. RBF-evicted, expiry-evicted,
SIZELIMIT-evicted, REORG-invalidated txs **stay in the estimator's
tracked map** and skew its conf-ratio downward forever (they "never
confirm" from the estimator's POV even though they were intentionally
dropped).

Cross-referenced by an existing test stub
(`tests/test_w120_mempool_rbf.rs:723-733`) which panics with:

> "BUG-12: fee estimator lacks on_remove hook; RBF-evicted txs linger
> in tracked map."

That stub is W120's discovery of the same gap; W153 lifts it to a
named bug here and ties it to the missing MemPoolRemovalReason taxonomy
(BUG-8).

**File:** `crates/consensus/src/fee_estimator.rs:410-460` (no remove
hook); `crates/rpc/src/server.rs:3736` (track-only callsite);
`crates/consensus/src/mempool.rs:2171-2213` (remove path with no
callback).

**Core ref:** `bitcoin-core/src/policy/fees/block_policy_estimator.cpp:586`
(`TransactionRemovedFromMempool` → `removeTx(hash, in_block=false)`).

**Impact:** fee estimator's bucket-decay math operates on inflated tx
populations; `estimatesmartfee` returns under-estimates after any
RBF-heavy or mempool-pressure period; cross-impl divergence vs Core
estimates.

---

## BUG-10 (P0-CDIV) — ZMQ `hashtx` / `rawtx` / `sequence` publishers are fully implemented but never invoked from production mempool paths

**Severity:** P0-CDIV (interop break with every electrs / fulcrum /
mempool.space / nbxplorer instance that consumes ZMQ).

`crates/rpc/src/zmq.rs:191-340, 567-570` defines:
- `ZmqCommand::NotifyTransaction { txid, raw_tx }` (line 191),
- `ZmqPublisher::notify_transaction(&self, tx: &Transaction)`
  (line 567 — public API, sends a command across the channel).

The internal handler `notify_transaction(&mut self, txid: &Hash256,
raw_tx: &[u8])` (line 399) dispatches to the configured topics
(`hashtx`, `rawtx`, `sequence`).

But grep `notify_transaction` / `NotifyTransaction` /
`ZmqCommand::Notify*` across `crates/` excluding `src/zmq.rs` and tests
finds **zero callsites**. The only invocation is a unit test at
`zmq.rs:1013`.

The mempool removal paths (`remove_single`, `trim_to_size`, `expire`,
`block_disconnected`, etc.) emit nothing. The admission path
(`add_transaction_with_options`) emits nothing. The block-connect
path (`submitblock`) emits nothing.

A node configured with `-zmqpubhashtx=tcp://...`,
`-zmqpubrawtx=...`, `-zmqpubsequence=...` opens the sockets, accepts
subscriber connections, and **never sends a single message after
startup**. Every downstream indexer that depends on rustoshi-fed ZMQ
silently stops receiving tx events.

Cross-cite W141 BUG-class (hashtx per-tx fan-out missing on
BlockConnected — fleet-wide pattern). Cross-cite BUG-8 (no
`MemPoolRemovalReason` to populate the `sequence` event label).

**File:** `crates/rpc/src/zmq.rs:191, 399, 567` (defined),
zero callers across the codebase.

**Core ref:** `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`
(`TransactionAddedToMempool` / `TransactionRemovedFromMempool` /
`BlockConnected` all publish to ZMQ).

**Impact:** ZMQ pub-sub is effectively dead; W141 BUG-class still
open as a fleet-wide gap.

---

## BUG-11 (P1) — Tx-relay rebroadcast tracker not informed on mempool eviction; W152 BUG-4 cross-cite

**Severity:** P1 (cross-cite W152 BUG-4 — InventoryTrickle dead
subsystem). The `InventoryTrickle` / `m_recently_announced_invs` /
`m_tx_inventory_to_send` analogue in `crates/network/src/relay.rs`
is unused in production per W152 BUG-4. So even if mempool removal
emitted events, there'd be no consumer.

The shape-match: same "fully-implemented and tested but never wired"
pattern as the rolling-fee subsystem (BUG-3/BUG-5) and the ZMQ
publisher (BUG-10). This is the FOURTH distinct rustoshi instance of
"dead subsystem" within the mempool-eviction blast radius.

**File:** `crates/network/src/relay.rs` (FeeFilterManager,
InventoryTrickle, PeerRelayState — all defined, all tested, no
production wiring).

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction` +
`SendMessages` rebroadcast loop.

**Impact:** rustoshi can never advertise evicted txs as "no longer
available" to peers that asked for them via INV; mempool sync between
rustoshi and Core peers drifts after every eviction event.

---

## BUG-12 (P0-CDIV) — `submitblock` does not call `mempool.remove_for_block`; confirmed txs linger in mempool indefinitely; two-pipeline guard 18th distinct extension

**Severity:** P0-CDIV. The block-connect path forks across two
implementations with divergent mempool semantics:

1. **`submitblock` (`server.rs:4404-4577`)** — the canonical block
   submission RPC. After successful `chain_state.process_block`, it:
   - persists header + block + height index + undo,
   - updates `state.best_height`/`best_hash`,
   - calls `state.fee_estimator.process_block(new_height, &non_cb_txids)`,
   - logs "submitblock: accepted block".

   **It NEVER calls `state.mempool.remove_for_block(block_txids,
   block_spent_outpoints)`.** Every tx in the block stays in the
   mempool's `transactions` map, `parents`/`children` graph, cluster
   structures, fee/mining-score indices, and continues to show up in
   `getrawmempool` AS IF unconfirmed. The next admission will see
   the confirmed tx as an in-mempool parent and admit children
   against the stale state.

2. **`mine_single_block` (`server.rs:9605-9609`)** — the
   `generatetoaddress`/`generate` path. Uses per-tx
   `state.mempool.remove_transaction(&tx.txid(), false)` — different
   API, no `block_spent_outpoints` parameter, so it **misses
   double-spend conflicts** (txs in the mempool that conflict with a
   confirmed block tx via shared inputs are NOT evicted — they
   linger as ghost double-spends until they're re-evaluated or
   evicted by trim).

So the same node, fed the same block via the same chain manager, ends
up in a different mempool state depending on which RPC delivered the
block. This is a "two-pipeline guard 18th distinct extension" within
rustoshi (each W14x quad-audit run has added at least one).

**File:** `crates/rpc/src/server.rs:4404-4577` (submitblock — no
mempool removal); `crates/rpc/src/server.rs:9605-9609` (mine_single_block
— per-tx remove without conflict catch).

**Core ref:** `bitcoin-core/src/validation.cpp::BlockConnected` →
`mempool.removeForBlock(block.vtx, ::BLOCK)` →
`removeConflicts(block.vtx)` (CONFLICT path).

**Impact:**
- `getrawmempool` size grows unboundedly during mining (txs never
  drained except by trim or `remove_transaction` from `mine_single_block`).
- Mining selection (`get_sorted_for_mining`) re-includes confirmed
  txs in block templates — duplicate-tx-id rejection at mine time
  if/when caught (depends on the mining pipeline's own dedup).
- Cross-impl divergence: a tx flagged as "in mempool" by rustoshi
  after a 10-block burst will show as "confirmed" by every other
  hashhog node and Core.

---

## BUG-13 (P1) — `remove_for_reorg` defined never called; CSV/CLTV-invalid txs survive across reorg target switches (W148 BUG-19 cross-cite)

**Severity:** P1 (already filed as W148 BUG-19 / W101 G15; logged here
for taxonomy completeness within W153). `mempool::remove_for_reorg`
(`:3074-3112`) implements the Core semantics: filter mempool entries
against a caller-provided predicate (typically "non-final at new tip"
or "spends now-immature coinbase"), cascade descendants, remove.

Zero production callsites. The reorg path
(`crates/rpc/src/server.rs:1450-1478`) calls `block_disconnected`
(re-admit non-coinbase txs from rolled-off blocks) but never calls
`remove_for_reorg(...)` afterwards. So a tx whose CSV / CLTV /
coinbase-maturity gate WAS satisfied at the pre-reorg tip but is NOT
satisfied at the post-reorg tip stays in the mempool and gets
re-broadcast as if valid.

Listed here for completeness within the W153 audit and to note its
interaction with BUG-12 (re-admitted block_disconnected txs landing in
a mempool with pre-existing stale entries from BUG-12 → ancestor
graphs corrupted).

**File:** `crates/consensus/src/mempool.rs:3074-3112` (definition,
no callers); `crates/rpc/src/server.rs:1450-1478` (reorg path,
missing call).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
→ `mempool.removeForReorg(active_chain, filter)`.

**Impact:** see W148 BUG-19. W153 anchors the cross-cite.

---

## BUG-14 (P1) — `-minrelaytxfee`, `-incrementalrelayfee`, `-maxmempool`, `-mempoolexpiry` CLI knobs absent; W150 BUG-8 carry-forward

**Severity:** P1 ("operator-knob absence" fleet pattern, cross-cite
W150 BUG-8 + W151 BUG-10). Bitcoin Core registers all four via
`init.cpp`. rustoshi's `parseFlags` (`rustoshi/src/main.rs:55-300+`)
does not. The values are baked in at `MempoolConfig::default()` and
cannot be overridden without recompiling.

Combined with BUG-1 + BUG-6, this means **there is no operator path
to fix rustoshi's 10× stricter min-relay floor without a code patch**.
Combined with BUG-2, there is no path to extend / shorten the mempool
expiry. Combined with BUG-3, there is no path to disable the (currently
dead but otherwise mandatory) rolling-min-fee gate.

The W150 BUG-8 doc-comment carry-forward: at
`crates/consensus/src/mempool.rs:680`, the doc-comment on
`expiry_seconds` reads "Default: 336 hours (2 weeks). Mirrors Bitcoin
Core -mempoolexpiry." This promises an absent operator knob — the
"absent operator knob promised by doc-comment" pattern is now its
own fleet category (`incremental_relay_fee` doc at `:696`,
`min_fee_rate` doc at `:682`, `expiry_seconds` doc at `:680` —
three instances in one struct).

**File:** `rustoshi/src/main.rs:55-300+` (parseFlags, missing flags);
`crates/consensus/src/mempool.rs:680, 682, 696` (doc-as-confession).

**Core ref:** `bitcoin-core/src/init.cpp:673, 685` + maxmempool +
mempoolexpiry argument registration.

**Impact:** operator-recovery dead-end for any fee-floor /
mempool-size / expiry tuning need; carries across W150 + W151 + W153.

---

## BUG-15 (P1) — `load_mempool` admits expired txs unconditionally; Core's age-filter absent

**Severity:** P1. Bitcoin Core's `LoadMempool` (`node/mempool_persist.cpp`)
filters every entry on `nTime >= now - pool.m_opts.expiry` BEFORE
calling `AcceptToMemoryPool`. Stale entries from a long-offline node
are dropped at load time.

rustoshi's `load_mempool` (`crates/consensus/src/mempool_persist.rs:286-374`)
reads `time_seconds` and `fee_delta`, calls `mempool.add_transaction`,
then `mempool.set_entry_time_seconds(&txid, time_seconds)`. There is
no filter against `mempool.config.expiry_seconds`. A node restarted
after 30 days offline will admit 30-day-old txs from disk; subsequent
re-broadcast pushes them to the network.

The cross-cite to BUG-2 (expire never called) means even after load,
the stale txs will never be reaped.

**File:** `crates/consensus/src/mempool_persist.rs:343-374`
(load loop, no age filter).

**Core ref:** `bitcoin-core/src/node/mempool_persist.cpp::LoadMempool`
(filters `nTime < now - expiry`).

**Impact:** stale-tx re-injection after long downtime; mild relay-spam
on cold restart.

---

## BUG-16 (P1) — `prioritise_transaction` does not refresh `ancestor_fees` / `descendant_fees`; modified-fee math leaks

**Severity:** P1. `mempool.rs:3269-3287` updates `entry.fee_delta` and
the standalone `map_deltas` entry but does NOT walk ancestors /
descendants to refresh `ancestor_fees` / `descendant_fees`. The
mining-selection code at `:2340-2358` uses `get_modified_fee` (which
folds in the delta) as a lone-entry rank but uses raw `ancestor_fees`
for the multi-ancestor branch — so a prioritised mid-package tx does
not bubble its delta up to its parent's ancestor-fee aggregate.

Cross-cite W120 BUG-9 / FIX-72: that fix folded the delta into the
single-entry rank but explicitly left the ancestor aggregation as a
follow-up (W106 G8). W153 confirms the follow-up is still open.

**File:** `crates/consensus/src/mempool.rs:3269-3287`
(prioritise_transaction); `:2348-2356` (multi-ancestor branch uses
raw ancestor_fees).

**Core ref:** `bitcoin-core/src/txmempool.cpp::PrioritiseTransaction`
+ `UpdateModifiedFee` cascade through ancestors.

**Impact:** under-counts modified fees for prioritised mid-package txs;
mining selection mis-orders by tens of sat/vB in worst case.

---

## BUG-17 (P1) — `clear_prioritisation()` defined never called; map_deltas leaks across confirmations

**Severity:** P1. `mempool.rs:3324-3326` defines:

```rust
pub fn clear_prioritisation(&mut self, txid: &Hash256) {
    self.map_deltas.remove(txid);
}
```

Zero callers. Core (`txmempool.cpp:667-671 ClearPrioritisation`) is
invoked from `removeUnchecked` ONLY for `MemPoolRemovalReason::BLOCK`
(so a confirmed tx that later reappears in a reorg-disconnect refill
doesn't silently re-apply the user's old prioritise delta).

Without this, an operator who `prioritisetransaction txid 1000` against
a tx that then confirms will see the delta silently re-apply if/when
the same txid re-appears in mempool (reorg refill, or a tx with the
same txid because rustoshi doesn't enforce txid uniqueness across
non-witness-equal admissions). That re-application can flip a
borderline-rejected tx into accepted with cumulative delta.

**File:** `crates/consensus/src/mempool.rs:3324-3326` (no callers);
should be invoked from `remove_for_block` (BUG-12 path, also broken).

**Core ref:** `bitcoin-core/src/txmempool.cpp:667-671`
(ClearPrioritisation called from removeUnchecked on BLOCK reason).

**Impact:** stale-delta replay across confirmations.

---

## BUG-18 (P0-CDIV) — `getmempoolinfo` and REST `/rest/mempool/info.json` hardcode constants; ignore live mempool state; intra-impl unit mismatch (MB vs MiB)

**Severity:** P0-CDIV (monitoring divergence — every observer of these
endpoints sees fixed values that lie about live state).

`crates/rpc/src/server.rs:3814-3838` (`get_mempool_info`):

```rust
let min_fee_rate_sats: u64 = 1000; // 1 sat/vB = 0.00001000 BTC/kvB

Ok(MempoolInfo {
    ...
    maxmempool: 300 * 1024 * 1024, // 300 MB    <-- COMMENT WRONG: this is MiB
    mempoolminfee: BtcAmount::from_sats(min_fee_rate_sats),
    minrelaytxfee: BtcAmount::from_sats(min_fee_rate_sats),
    incrementalrelayfee: BtcAmount::from_sats(min_fee_rate_sats),  // 10× config!
    ...
})
```

`crates/rpc/src/rest.rs:761-782` (REST analogue) hardcodes
`maxmempool: 300_000_000` (correct SI MB — but disagrees with the RPC),
`mempoolminfee: 0.00001`, `minrelaytxfee: 0.00001`.

Three independent bugs in one block:

1. **`mempoolminfee` HARDCODED** — should reflect
   `max(get_min_fee(), config.min_fee_rate)` per Core. Currently always
   returns `1000` sat/kvB regardless of mempool state. Rolling-fee
   pressure is invisible to operators.

2. **`maxmempool` UNIT MISMATCH** — RPC returns 300 × 1024 × 1024 =
   314_572_800 (MiB convention). REST returns 300_000_000 (SI MB).
   `MempoolConfig::default().max_size_bytes = 300 × 1_000_000` =
   300_000_000 (SI MB, matches REST and Core).
   **`getmempoolinfo` over-reports the limit by 4.5% (14.5 MiB).**
   An operator scaling alerts to "95% of maxmempool" will set the
   threshold above the actual limit.

3. **`incrementalrelayfee = 1000` sat/kvB** — but
   `MempoolConfig::default().incremental_relay_fee = 100` sat/kvB
   (correctly mirrors Core). So `getmempoolinfo` returns a value 10×
   higher than the actual constant used in RBF arithmetic.
   **The RPC lies by 10× about the value RBF arithmetic uses.**

Combined: monitoring tooling, RBF probes, and operator dashboards all
see hardcoded misleading numbers.

**File:** `crates/rpc/src/server.rs:3823, 3831-3834` (getmempoolinfo);
`crates/rpc/src/rest.rs:775-777` (REST info.json).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
(consults `mempool.GetMinFee()`, `mempool.m_opts.max_size_bytes`,
`mempool.m_opts.incremental_relay_feerate`, `mempool.m_opts.min_relay_feerate`).

**Impact:** every monitoring scraper gets wrong numbers regardless of
mempool state; RBF tooling that introspects `incrementalrelayfee` over-pays
by 10×; threshold-alert thresholds drift by 4.5 % from the actual limit.

---

## BUG-19 (P1) — `send_initial_feefilter` hardcodes 100_000 sat/kvB (100 sat/vB, 1000× Core); peer feefilter advertisement ignores mempool state

**Severity:** P1 ("comment-as-confession" 4th distinct rustoshi
instance; cross-cite W141 BUG-class "FeeFilterManager unused" from W152
BUG-4).

`crates/network/src/peer_manager.rs:2220-2227`:

```rust
/// Without mempool, we set a high fee rate (100 sat/vbyte = 100000 sat/kvB)
/// to discourage transaction relay.
pub async fn send_initial_feefilter(&mut self, peer_id: PeerId) {
    // 100 sat/vbyte = 100,000 sat/kvB (sat per 1000 virtual bytes)
    let fee_rate: u64 = 100_000;
    let _ = self.send_to_peer(peer_id, NetworkMessage::FeeFilter(fee_rate)).await;
}
```

The doc-comment confesses the bug: "Without mempool, we set a high fee
rate" — but `peer_manager` HAS access to the mempool through
the rest of `state`, and the function is called unconditionally at
`peer_manager.rs:1998` ("Send initial feefilter after handshake"). The
100_000 sat/kvB value is sent to **every** new peer regardless of
mempool state and regardless of whether the mempool's
`incremental_relay_fee` (100 sat/kvB), `min_fee_rate` (1000 sat/kvB
per config), or `rolling_minimum_fee_rate` would suggest a different
filter.

Core advertises `max(MIN_RELAY_FEE, mempool.GetMinFee())` per
`net_processing.cpp::SendMessages` feefilter handler. That's typically
100 sat/kvB on idle, more under mempool pressure. **rustoshi advertises
100_000 sat/kvB = 1000× too strict on idle, telling peers "don't
relay txs to me unless fee >= 100 sat/vB"** — which means rustoshi
receives ZERO low-fee tx INVs from peers that honour BIP-133.

Cross-cite W152 BUG-4: even if `send_initial_feefilter` were correct,
the `FeeFilterManager` rebroadcast loop is dead, so updates to the
rolling rate would never reach peers. Both bugs together: rustoshi
sends one hardcoded 100 sat/vB filter at handshake and is silent
forever after.

**File:** `crates/network/src/peer_manager.rs:2220-2227` (handcoded
filter); `crates/network/src/peer_manager.rs:1998` (initial-send
callsite).

**Core ref:** `bitcoin-core/src/net_processing.cpp::SendMessages`
(feefilter handler → `max(MIN_RELAY_FEE, pool.GetMinFee())`).

**Impact:** rustoshi peers receive a 1000× too-strict filter and stop
relaying typical-fee txs to rustoshi. Combined with BUG-3 (rustoshi
doesn't consult rolling-min anyway) this manifests as a one-way relay
gap.

---

## BUG-20 (P1) — Reject token wire-format divergence: `"fee rate too low: ..."` vs Core's `"min relay fee not met"`

**Severity:** P1 ("reject-string wire-parity slippage" fleet pattern,
cross-cite W125 + W145 fleet sweep).

`MempoolError::InsufficientFee` formats as
`"fee rate too low: {fee_rate:.2} sat/vB (minimum: {min_fee_rate})"`
(`mempool.rs:876-877`). `MempoolError::MempoolFull` formats as
`"mempool full"` (`:879-880`). Other errors use free-form English
similarly.

Bitcoin Core's BIP-22-style reject tokens for the same conditions are:
- `min relay fee not met` (CheckFeeRate failure),
- `mempool full` (TrimToSize couldn't free space).

Indexers / explorers / wallets / cross-impl test harnesses pattern-match
on Core's exact strings. Rustoshi's are close but not byte-equal.
`getmempoolentry` / `sendrawtransaction` error responses leak the
divergence to JSON-RPC consumers.

Plus the format includes `:.2` precision and the actual unit
(`sat/vB`) — Core's reject strings don't include numeric values; they
go in the JSON `data` field separately.

**File:** `crates/consensus/src/mempool.rs:874-895` (error strings).

**Core ref:** `bitcoin-core/src/policy/policy.cpp::CheckFeeRate`
(reject token "min relay fee not met").

**Impact:** test-suite cross-impl assertions that pattern-match Core's
exact reject token will skip rustoshi-emitted errors; monitoring
parsers will not classify rustoshi rejections correctly.

---

## BUG-21 (P2) — `min_fee_rate` is a single integer; no separate `min_relay_feerate` vs `dust_relay_feerate` field

**Severity:** P2. Bitcoin Core's mempool options carry separate
`min_relay_feerate` and `dust_relay_feerate` (`dust_relay_feerate`
defaults to 3000 sat/kvB and is used inside `IsDust`). rustoshi's
`MempoolConfig` has a single `min_fee_rate` that conflates the two; the
dust threshold is computed inside `is_dust` from a different constant
(`params.rs:116 DUST_RELAY_TX_FEE = 3000`).

Cosmetic / type-tightness; the current code does the right math, but
the field name doesn't signal the conflation. An operator who lowers
`-minrelaytxfee` (if it existed per BUG-14) and expects dust to follow
would be surprised.

**File:** `crates/consensus/src/mempool.rs:682-683` (config field);
`:5028-5063` (is_dust uses separate constant).

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h:42-45`
(distinct `min_relay_feerate` and `dust_relay_feerate`).

**Impact:** type-naming clarity; no behaviour bug today.

---

## BUG-22 (P1) — `mempool.dat` schema lacks `unbroadcast` set persistence + `mempool_sequence` counter; partial Core-compat

**Severity:** P1. `mempool_persist.rs` advertises Core-format-compat
(load + dump). The format includes `num_unbroadcast` and a counter
field that Core uses to identify the next sequence id on restart
(`mempool_sequence` for ZMQ `sequence` topic). The rustoshi load path
reads `n_unbroadcast` (`load_mempool` near line 408) but I'm not seeing
a corresponding in-memory `unbroadcast_set` consumed by anything. The
dump-side similarly writes `0` for unbroadcast count
(visible from earlier read of dump_mempool at `:191-…`).

Combined with BUG-10 (ZMQ unwired) and BUG-9 (fee estimator no-remove),
this is part of the same "signal fan-out absent" cluster.

**File:** `crates/consensus/src/mempool_persist.rs:408-`
(read but discarded?); `:177-…` (dump-side).

**Core ref:** `bitcoin-core/src/node/mempool_persist.cpp::DumpMempool`
+ `LoadMempool` (unbroadcast list driven by
`m_unbroadcast_txids` set).

**Impact:** mempool.dat round-trips lose the unbroadcast-set
membership; restart-after-shutdown forgets which txs were submitted
locally and need active rebroadcast.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 10 (BUG-1, BUG-3, BUG-5, BUG-6, BUG-8, BUG-9, BUG-10, BUG-12, BUG-18, BUG-19[reclassified to P1] → 9 actually; recount: BUG-1, BUG-3, BUG-5, BUG-6, BUG-8, BUG-9, BUG-10, BUG-12, BUG-18 = **9 P0-CDIV**)
- **P0:** 1 (BUG-2)
- **P1:** 11 (BUG-4, BUG-7, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-22)
- **P2:** 1 (BUG-21)

Total: 9 + 1 + 11 + 1 = **22** ✓.

**Top three findings:**

1. **BUG-3 + BUG-5 (P0-CDIV "dead-rolling-fee-subsystem")** — every
   component of the rolling-min-fee floor exists, is tested, and is
   wired correctly internally. `get_min_fee()` has zero production
   callsites; `notify_block_connected()` has zero production callsites.
   Net effect: rustoshi has NO dynamic mempool-pressure fee floor.
   Bumping the rate in `trim_to_size` is dead state. This is the
   pattern echo the task description called out ("rolling-min-fee
   floor present but decay function missing/wrong") — in rustoshi it's
   the OPPOSITE end: decay logic is correct, the floor isn't checked
   anywhere AND the trigger to start decaying isn't fired anywhere.

2. **BUG-1 + BUG-6 + BUG-18 (P0-CDIV "10× too-strict fee floor in three
   places")** — N-pipeline drift on `DEFAULT_MIN_RELAY_TX_FEE`:
   `consensus/params.rs:113 = 1_000`, `network/relay.rs:66 = 1000`,
   `consensus/mempool.rs MempoolConfig.min_fee_rate = 1 sat/vB` (=
   1000 sat/kvB). All three are 10× Core's `100 sat/kvB`. Pre-flight
   gate's cast-to-u64 truncation amplifies the issue: any tx below 1
   sat/vB is rejected even when the constant is correct. Plus
   `get_mempool_info` RPC and `/rest/mempool/info.json` hardcode the
   wrong values AND disagree about whether maxmempool is MB or MiB
   (intra-impl unit drift).

3. **BUG-2 + BUG-8 + BUG-9 + BUG-10 + BUG-12 cluster (P0/P0-CDIV
   "signal-fan-out blast radius")** — five interrelated bugs around
   the absence of a removal signal:
   - `expire()` never called (BUG-2),
   - `MemPoolRemovalReason` enum doesn't exist (BUG-8),
   - fee estimator has no `on_remove` hook (BUG-9),
   - ZMQ publisher fully implemented but never invoked (BUG-10),
   - `submitblock` doesn't call `remove_for_block` (BUG-12).

   Closing any one of these doesn't help until they're closed together
   — until the removal signal exists, there's nothing for consumers to
   subscribe to; until consumers exist, emitting the signal does
   nothing.

**Fleet patterns confirmed:**

- **"dead-data plumbing"** (BUG-3, BUG-5, BUG-10, BUG-11) — 4 distinct
  rustoshi instances in this single audit (rolling-fee state,
  notify_block_connected, ZMQ notify_transaction, InventoryTrickle);
  cumulative count across W138-W153 now ~12.
- **"dead-subsystem fully tested"** (BUG-3, BUG-10, BUG-11) — three
  subsystems with 100% test coverage and 0 production wiring. This is
  the W148 BUG-8 / W152 BUG-4 / W141 fleet pattern (FIFTH rustoshi
  instance).
- **"N-pipeline drift on a single constant"** (BUG-6 with 3 sites; BUG-7
  with 2 sites) — extends from W142 "three-pipeline drift"; first
  time the SAME constant exists 3 times in rustoshi all wrong, plus
  the SAME constant exists 2 times disagreeing on the value.
- **"two-pipeline guard 17th + 18th + 19th distinct extension"** (BUG-7
  cross-crate constant disagreement, BUG-12 submitblock vs mine_single_block
  remove path, BUG-18 RPC vs REST endpoint hardcoded values).
- **"comment-as-confession"** (BUG-1 unit doc-comment "sat/vB" vs
  implementation in sat/kvB; BUG-5 `:3119` "implicit via the
  connected-block path" — there isn't one; BUG-14 three doc-comments
  promising absent operator knobs; BUG-19 doc-comment confessing
  "Without mempool, we set a high fee rate"; BUG-18 wrong-unit
  comment on maxmempool). **5 distinct comment-as-confession
  instances in one audit**, beating the previous wave high of 4
  (W138).
- **"hardcoded constant should be config-driven"** (BUG-18 RPC + REST
  ignore mempool.config; BUG-19 hardcoded peer feefilter).
- **"unit-mismatch on fee rate"** — the W150 BUG-8 carry-forward the
  task mentioned, now anchored: BUG-1 + BUG-6 + BUG-18 form the same
  pattern across mempool admission, three constant definitions, and
  three RPC/REST endpoints. Plus BUG-19 hardcodes the unit MEANING in
  a comment that confesses the bug.
- **"operator-knob absence"** (BUG-14) — cross-cite W150 BUG-8 + W151
  BUG-10; the rustoshi parseFlags surface is the smallest in the fleet
  on the fee-tuning axis.
- **"signal-fan-out blast radius"** (BUG-2 + BUG-8 + BUG-9 + BUG-10 +
  BUG-12) — first wave-level cluster of this shape; analogous to W140
  "compounding-security stack" but on the observability axis instead
  of the auth axis.
- **"intra-impl unit drift"** (BUG-18 RPC = MiB vs REST = MB vs config
  = MB) — first wave instance in rustoshi of TWO RPC layers disagreeing
  on the same on-disk value's unit; fleet category extension.
- **"reject-string wire-parity slippage"** (BUG-20) — 6+ distinct
  rustoshi instances tracked across W125 / W145 / W153.

**Carry-forward catches:**

- **W150 BUG-8** ("10× too-strict min-relay-fee + missing CLI knob") —
  now anchored to BUG-1 (cast-truncation gate bug), BUG-6 (3 wrong
  constants), BUG-14 (no CLI), BUG-18 (RPC hardcodes wrong value).
  4× the original site count.
- **W150 BUG-10** ("absent operator knob promised by doc-comment") —
  BUG-14 confirms three more doc-comments (`min_fee_rate`,
  `incremental_relay_fee`, `expiry_seconds`).
- **W151 BUG-8** (wallet `INCREMENTAL_FEE_RATE` constant) — verified
  still absent in `crates/wallet/`; no new finding here, just
  confirmation.
- **W152 BUG-4** (`InventoryTrickle` / `FeeFilterManager` /
  `PeerRelayState` dead subsystem) — exact-shape pattern repeats in
  BUG-3 + BUG-5 + BUG-10. SAME ARCHITECTURAL PATTERN now confirmed in
  FOUR distinct rustoshi subsystems: the fleet "dead-subsystem fully
  tested" category is graduating from "occasional finding" to "systemic
  rustoshi failure mode" — every wave finds a new instance.

**P0-CDIV concentration:** 9 P0-CDIV in W153 ties W144 (rustoshi 22
bugs / 3 P0-CDIV) and approaches W142 levels (rustoshi 22 / multiple
P0-CONS). The "10×-too-strict + dead-rolling-fee + absent-removal-signal"
cluster is the highest-density mempool-shape finding in any wave.

**Priority next fix waves from this audit:**

1. **BUG-6 + BUG-1 fleet-wide** — fix `DEFAULT_MIN_RELAY_TX_FEE`
   constants (3 sites in rustoshi) + replace cast-truncation gate with
   integer sat/kvB math. ~10 LOC. Restores Core-parity relay floor.
2. **BUG-5 wire `notify_block_connected()` into submitblock +
   mine_single_block + reorg paths** — 4 callsites, 1 LOC each.
3. **BUG-12 wire `mempool.remove_for_block()` into submitblock** —
   1 callsite, ~10 LOC (compute spent_outpoints from block.vtx).
4. **BUG-2 add a `LimitMempoolSize` helper + wire into post-ATMP +
   post-block-connect paths** — ~20 LOC.
5. **BUG-8 + BUG-9 + BUG-10 cluster (signal-fan-out)** — define
   `MemPoolRemovalReason` enum + thread through remove paths + wire
   to fee estimator + ZMQ + REST. ~100 LOC across 5 files; multi-fix
   wave because all 5 must land together.
6. **BUG-18 fix `getmempoolinfo` and REST endpoint to consult
   `mempool.config` and `get_min_fee()`** — ~15 LOC across 2 files.
7. **BUG-13 wire `mempool.remove_for_reorg(filter)` into reorg path**
   (already filed as W148 BUG-19, not closed) — ~30 LOC including
   the predicate.
8. **BUG-15 add age filter in load_mempool** — 3 LOC.
9. **BUG-19 replace hardcoded `100_000` in `send_initial_feefilter`
   with `state.mempool.get_min_fee().max(state.mempool.config.incremental_relay_fee)`**
   — 3 LOC, depends on BUG-3 being closed.

**Cross-cites (pending fixes that interact with W153):**

- W148 BUG-19 (mempool.remove_for_reorg) — BUG-13 anchor.
- W141 BUG-class (ZMQ hashtx fan-out) — BUG-10 / BUG-22.
- W150 BUG-8 (CLI flag absence) — BUG-14.
- W150 BUG-10 (doc-comment promises) — BUG-14.
- W151 BUG-8 (wallet INCREMENTAL_FEE_RATE) — see references; not a
  W153 finding.
- W152 BUG-4 (InventoryTrickle dead) — BUG-11.
- W120 BUG-9/-10/-12/-15 (mempool RBF taxonomy gaps) — BUG-8 / BUG-9 /
  BUG-16 / BUG-17 anchors and elaborates.
