# W149 — Pruning + assumevalid + minimumchainwork audit (rustoshi)

**Wave:** W149 — `-prune` coordinator, `-assumevalid` skip-gate,
`nMinimumChainWork` enforcement (DISCOVERY).

**Date:** 2026-05-18

**Audit subject:** the rustoshi pruning + assumed-valid + minimum-chain-work
surface — the three Core init-time levers that together govern (a) how much
on-disk block/undo data is retained, (b) how much script verification work
is skipped during IBD, and (c) when the node will commit to a downloaded
chain. These three subsystems are deeply intertwined in Core
(`validation.cpp::ConnectBlock` reads `m_chainman.AssumedValidBlock()`,
`m_chainman.MinimumChainWork()`, and `m_chainman.m_best_header->nChainWork`
all in the same skip-gate; `node/blockstorage.cpp::FindFilesToPrune` reads
the assumeutxo base height as a floor; `IsInitialBlockDownload` reads
`MinimumChainWork()` to latch IBD off). The rustoshi parity of all three
is shallow and partially dead-data.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp::FindFilesToPrune` — auto-prune
  size-target loop (oldest→newest file iter, `MIN_BLOCKS_TO_KEEP=288` keep
  window, prune target byte comparison).
- `bitcoin-core/src/node/blockstorage.cpp::FindFilesToPruneManual` /
  `PruneBlockFilesManual` — manual-prune driven by `pruneblockchain` RPC.
- `bitcoin-core/src/node/blockstorage.cpp::UnlinkPrunedFiles` —
  on-disk file deletion, called after metadata cleanup.
- `bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile` — per-file
  metadata clear + iterate the block index dropping `BLOCK_HAVE_DATA` /
  `BLOCK_HAVE_UNDO` bits.
- `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain` — accepts a
  height **OR** a UNIX timestamp (dual-mode parse: `heightParam > 1e9`
  reinterprets as timestamp via `FindEarliestAtLeast(heightParam -
  TIMESTAMP_WINDOW, 0)`).
- `bitcoin-core/src/init.cpp:485-490` — `-prune=<n>` arg parse,
  `nPruneTarget`, `MIN_DISK_SPACE_FOR_BLOCK_FILES`,
  manual-mode (`-prune=1`) sentinel.
- `bitcoin-core/src/init.cpp:487` — `-assumevalid=<hex>` arg parse;
  `0` disables (always-verify), default is per-network from
  `defaultAssumeValid`.
- `bitcoin-core/src/init.cpp:863, 1368-1370, 1947-1952` —
  `g_local_services` starts as `NODE_NETWORK_LIMITED | NODE_WITNESS`;
  `NODE_NETWORK` is **added** only when `!IsPruneMode()`. Reverse of
  what rustoshi does.
- `bitcoin-core/src/validation.cpp:2345-2383` — `ConnectBlock`
  assumevalid skip-gate (5 preconditions: hash-present-in-index +
  ancestor-of-pindex + on-best-header-chain + best-header above
  MinimumChainWork + GetBlockProofEquivalentTime > 2 weeks).
- `bitcoin-core/src/validation.cpp:2494-2515` — `fScriptChecks` only
  skips signature verification work (`CScriptCheck` queue +
  `tx.IsCoinBase() && fScriptChecks` gate). All other ConnectBlock
  invariants (BIP-30/34, BIP-68, MoneyRange, coinbase maturity,
  sigops cap, subsidy cap) still execute.
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291, 4280` —
  `IsInitialBlockDownload`/`UpdateIBDStatus` reads `MinimumChainWork()`
  to latch IBD off; `m_best_header->nChainWork >= MinimumChainWork()`
  used in `HEADERS_DOWNLOAD_BUFFER` gate.
- `bitcoin-core/src/kernel/chainparams.cpp:109-110, 232-233, 332-333,
  423-424, 435-436, 557-558` — `consensus.nMinimumChainWork` and
  `consensus.defaultAssumeValid` per network (mainnet / testnet3 /
  testnet4 / signet-default / signet-empty / regtest).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum with **ordered**
  validity ladder (`BLOCK_VALID_RESERVED=1`..`BLOCK_VALID_SCRIPTS=5`)
  masked by `BLOCK_VALID_MASK = BLOCK_VALID_RESERVED | TREE |
  TRANSACTIONS | CHAIN | SCRIPTS` (bits 0-2 only). `RawIsValid(nUpTo)`
  uses `(nStatus & BLOCK_VALID_MASK) >= nUpTo`, NOT a bit-set test.
  Also defines `BLOCK_ASSUMED_VALID` (bit 8) for assumeutxo blocks.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.
- `bitcoin-core/src/node/chainstate.cpp` — `LoadChainstate` minimum
  chain-work gate, `VerifyLoadedChainstate`.

**Files audited**
- `crates/storage/src/prune.rs` — `PruneCoordConfig`, `PRUNE_MANUAL_SENTINEL`,
  `auto_prune`, `manual_prune_to_height`, `from_mib`.
- `crates/storage/src/block_store.rs:700-815` — `prune_block`,
  `prune_active_chain_range`, `get/set_prune_height`. RocksDB-key-granular
  prune (rustoshi's actual production path).
- `crates/storage/src/blockstore.rs:308-336, 670-870` — `PruneConfig`,
  `FlatBlockStore`, `find_files_to_prune`, `find_files_to_prune_manual`,
  `prune_one_block_file`, `unlink_pruned_files`. **All flat-file prune
  helpers DEAD in production** (cross-cite W146 BUG-1).
- `crates/storage/src/block_store.rs:15-75` — `BlockStatus` bit
  definitions and `has()` / `set()` / `clear()` helpers.
- `crates/consensus/src/chain_manager.rs:13-80` — **parallel**
  `block_status` module + `BlockMeta::has_valid_transactions()`
  (two-pipeline-guard with `storage::block_store::BlockStatus`).
- `crates/consensus/src/params.rs:526-958` — `ChainParams`,
  `assumed_valid_block`, `assumed_valid_height`, `minimum_chain_work`
  per-network setters.
- `crates/consensus/src/validation.rs:1018-1039` —
  `accept_block_header_chain_work` (header-side MinimumChainWork gate).
- `crates/consensus/src/validation.rs:1539-1819` —
  `connect_block_with_sequence_locks`, `skip_scripts` gate at L1553-1557.
- `crates/network/src/peer_manager.rs:140-251, 1122-1140` —
  `prune_mode`, `local_services()`, NODE_NETWORK / NODE_NETWORK_LIMITED.
- `crates/network/src/block_download.rs:425-432` — `is_ibd_complete()`
  (no `MinimumChainWork()` consultation).
- `crates/network/src/headers_presync.rs` — `HeadersPresyncState`,
  `minimum_required_work`, `current_chain_work` / `redownload_chain_work`.
- `crates/rpc/src/server.rs:511-512, 5137-5206, 2910-2952` —
  `pruneblockchain` RPC handler + `getblockchaininfo` prune-fields.
- `crates/rpc/src/types.rs:200-220` — `BlockchainInfo` (`pruned`,
  `pruneheight`, `prune_target_size`).
- `rustoshi/src/main.rs:155-160, 1258-1262, 1630-1650, 1954-1972,
  2456-2469, 3016-3026` — `--prune` CLI arg, `prune_target_bytes`
  derivation, `PruneCoordConfig` build, `auto_prune` connect-loop
  trigger.

---

## Gate matrix (30 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` CLI arg parse | G1: `prune=0` → disabled | PASS (`main.rs:1640-1641`) |
| 1 | … | G2: `prune=1` → manual-only sentinel | PASS (`main.rs:1642`, `prune.rs:71`) |
| 1 | … | G3: `prune=2..549` → reject below `MIN_DISK_SPACE_FOR_BLOCK_FILES` | **BUG-1 (P1)** sub-minimum sizes silently collapse to manual-only instead of rejecting at parse time (`main.rs:1643`, `prune.rs:72`) |
| 1 | … | G4: `prune≥550` → `target_bytes = N * MiB` | PASS (`main.rs:1644`, `prune.rs:73`) |
| 1 | … | G5: `--prune` value is parsed from `bitcoin.conf` when not on CLI | PASS (`main.rs:1258-1262`) |
| 2 | `auto_prune` keep-window | G6: never delete height 0 | PASS (`block_store.rs:801-803`) |
| 2 | … | G7: never delete height ≥ `tip - MIN_BLOCKS_TO_KEEP` | PASS (`prune.rs:134-140`) |
| 2 | … | G8: never delete height ≥ assumeutxo activation | PASS (`prune.rs:143-145`) |
| 2 | … | G9: trigger fires on actual disk-usage exceeding `prune_target` | **BUG-2 (P0)** `auto_prune` ignores `target_bytes` entirely — drops everything below the keep window whenever called. Comment-as-confession at `prune.rs:108-116` admits the gap ("we don't measure on-disk usage against the byte target here"). |
| 2 | … | G10: triggered after each ConnectBlock under Core's `FlushStateToDisk(PERIODIC)` | **BUG-3 (P1)** rustoshi's connect-block loop calls `auto_prune` every 100 blocks, NOT after `FlushStateToDisk` — and BEFORE the UTXO cache flush (`main.rs:2456-2469`). Core orders flush-then-prune to avoid deleting block data still required for rollback of an unflushed UTXO change. |
| 3 | `manual_prune_to_height` | G11: respects `MIN_BLOCKS_TO_KEEP` ceiling | PASS (`prune.rs:193-194`) |
| 3 | … | G12: respects assumeutxo floor | PASS (`prune.rs:195-197`) |
| 3 | … | G13: fires under `-prune=1` manual-only mode | PASS (`prune.rs:189-192`, RPC `server.rs:5143-5148` rejects when disabled) |
| 3 | … | G14: watermark advances monotonically | PASS (`block_store.rs:807-812`) |
| 4 | `pruneblockchain` RPC | G15: rejects when `prune_mode=false` | PASS (`server.rs:5143-5148`) |
| 4 | … | G16: rejects height > `tip - MIN_BLOCKS_TO_KEEP` | PASS (`server.rs:5152-5162`) |
| 4 | … | G17: accepts `heightParam > 1e9` as UNIX timestamp (dual-mode) | **BUG-4 (P0-CDIV)** RPC signature is `prune_blockchain(height: u32)` — never converts a >1e9 value into a timestamp lookup via `FindEarliestAtLeast(ts - TIMESTAMP_WINDOW, 0)`. RPC contract divergence (`server.rs:511-512`, comment-as-confession at `prune.rs:179-182` documents the gap). |
| 4 | … | G18: returns the post-pass last-pruned height | PASS (`server.rs:5205`) |
| 5 | `-assumevalid` CLI | G19: `-assumevalid=<hex>` operator override | **BUG-5 (P0)** NO CLI arg exists — `--prune` is the only init-time lever; `assumed_valid_block` is locked to chainparams compile-time hardcode (`main.rs:155-160` no assumevalid field). |
| 5 | … | G20: `-assumevalid=0` to always-verify | **BUG-5 cross-cite** unreachable; operator must recompile to disable. |
| 5 | … | G21: per-network `defaultAssumeValid` populated | PARTIAL — mainnet+testnet4 set, **testnet3+signet `None`** despite Core having values `000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` (height 4842348) and `00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329` (height 293175) respectively (`params.rs:770-771,909-910` vs `kernel/chainparams.cpp:233,424`). **BUG-6 (P1)**. |
| 6 | `assumevalid` skip-gate at ConnectBlock | G22: skip only sig verification, never any other invariant | PASS for the inline skip flag (`validation.rs:1803-1819` only gates `verify_script`) — but see G23-G26. |
| 6 | … | G23: precondition #1 — assumevalid hash actually exists in the block index | **BUG-7 (P0-CDIV)** rustoshi reads ONLY `params.assumed_valid_height` (`validation.rs:1554-1557`); never resolves `assumed_valid_block` to look up the index entry and verify it's on the chain we're connecting. `assumed_valid_block` is **dead data** — defined per-network in chainparams, read by zero production paths. |
| 6 | … | G24: precondition #2 — pindex is an ancestor of the assumed-valid pindex | **BUG-7 cross-cite** missing — height-only comparison is a side-branch oracle. A reorg onto a side-chain at height ≤ av_height will silently skip script verification on the side-branch even though it's NOT the assume-valid chain. |
| 6 | … | G25: precondition #3 — best_header has chain_work ≥ MinimumChainWork | **BUG-7 cross-cite** missing — `validation.cpp:2362-2363` |
| 6 | … | G26: precondition #4 — `GetBlockProofEquivalentTime` > 2 weeks | **BUG-7 cross-cite** missing — `validation.cpp:2364-2365` (2-weeks DoS guard against forced-assume-valid attack documented in Core). |
| 7 | `nMinimumChainWork` enforcement | G27: header-side gate in `AcceptBlockHeader` | PASS (`validation.rs:1018-1039`) — but caller threads `min_pow_checked=true` from PRESYNC and rustoshi PRESYNC is dead code (cross-cite W148-class) — see G29. |
| 7 | … | G28: per-network value present and matches Core | PASS for mainnet/testnet3/testnet4/signet (verified against `kernel/chainparams.cpp` 109,232,332,423); regtest `[0u8; 32]` matches Core's `uint256{}`. |
| 7 | … | G29: HeadersPresyncState wired into production header receive path | **BUG-8 (P0)** `HeadersPresyncState::new` has **zero non-test callers** (grep'd `crates/network/src/`, `crates/network/src/peer*.rs`, `rustoshi/src/`). The entire PRESYNC anti-DoS subsystem is defined-and-tested but production headers bypass it. `redownload_chain_work` / `current_chain_work` / `minimum_required_work` accumulators all dead. |
| 8 | IBD latch + MinimumChainWork | G30: `IsInitialBlockDownload` exit reads MinimumChainWork | PASS (`server.rs:1167-1177`, `should_exit_ibd`). |
| 8 | … | G31: `is_ibd_complete` in block_download also consults MinimumChainWork | **BUG-9 (P1)** `block_download.rs:427-432` defines IBD-complete as "validated_tip_height >= best_header_height AND queues empty" — entirely structural, no chainwork consultation. Two-pipeline-guard with `should_exit_ibd`. |
| 9 | `BlockStatus` flag semantics | G32: validity ladder is ORDERED (mask + ≥-comparison), not bit-set | **BUG-10 (P0-CDIV)** `BlockStatus::VALID_HEADER=1, VALID_TREE=2, VALID_TRANSACTIONS=3, VALID_CHAIN=4, VALID_SCRIPTS=5` (`block_store.rs:24-37`) but `has(flag)` uses `(self.0 & flag) != 0` (`block_store.rs:57-59`). So `set(VALID_SCRIPTS)=5` sets bits 0+2 only (NOT bit 4 = VALID_CHAIN), AND `has(VALID_TRANSACTIONS=3)` returns true whenever EITHER bit 0 OR bit 1 is set — including blocks that are only `VALID_HEADER`. Core uses `(nStatus & BLOCK_VALID_MASK) >= nUpTo` (`chain.h:254-257`). |
| 9 | … | G33: `BLOCK_ASSUMED_VALID` (bit 8) flag exists | **BUG-11 (P1)** missing entirely from `BlockStatus` enum — assumeutxo-loaded blocks cannot be distinguished from fully-validated blocks via the status field (`chain.h:80`). |
| 9 | … | G34: status definition lives in ONE place (no two-pipeline drift) | **BUG-12 (P0-CDIV)** `consensus/chain_manager.rs:13-23` defines a **parallel** `block_status` module duplicating the constants AND using the same broken bit-set check (`has_valid_transactions: (status & 3) != 0`, line 73). 2nd consumer of the broken `VALID_TRANSACTIONS=3` semantics. |
| 10 | NODE_NETWORK_LIMITED advertisement | G35: NODE_NETWORK removed when prune_mode=true | **BUG-13 (P0-CDIV)** rustoshi ADDS `NODE_NETWORK_LIMITED` on top of `NODE_NETWORK` when prune is on (`peer_manager.rs:1122-1129`) — Core REMOVES `NODE_NETWORK` and keeps only `NODE_NETWORK_LIMITED` (`init.cpp:863, 1947-1952`: `g_local_services = NODE_NETWORK_LIMITED | NODE_WITNESS`, then `|= NODE_NETWORK` only when `!IsPruneMode()`). Pruned rustoshi nodes lie to peers about being able to serve historical blocks → peers waste `getdata` round-trips. |
| 11 | `pruneblockchain`/`getblockchaininfo` parity | G36: `getblockchaininfo.size_on_disk` reports actual bytes | **BUG-14 (P1)** hardcoded `0` (`server.rs:2945`, comment-as-confession "would need filesystem stat"). Wallets / explorers / monitoring tools that condition prune-eviction on this number get garbage. |
| 11 | … | G37: `getblockchaininfo.automatic_pruning` boolean present | **BUG-15 (P0-CDIV)** missing field — Core gates `prune_target_size` to be present ONLY when `automatic_pruning=true` (`bitcoin-core/src/rpc/blockchain.cpp:1452-1454`). rustoshi's `BlockchainInfo` type (`types.rs:200-220`) lacks the field entirely. |

---

## BUG-1 (P1) — `-prune=2..549` silently collapses to manual-only instead of erroring

**Severity:** P1. Bitcoin Core's `-prune` parse rejects sub-minimum sizes
at init with `InitError("Prune configured below the minimum of %d MiB.
Please use a higher number.")` (`bitcoin-core/src/init.cpp:1147-1149`).
rustoshi's `from_mib` quietly turns any value in `2..550` into the
manual-only sentinel — the operator who typed `--prune=540` thinks they
have a 540 MiB auto-prune target, but in fact pruning never fires unless
they also call `pruneblockchain` RPC.

**File:** `crates/storage/src/prune.rs:67-79`, `rustoshi/src/main.rs:1640-1645`

**Core ref:** `bitcoin-core/src/init.cpp:1147-1149`,
`bitcoin-core/src/node/blockstorage.h::PRUNE_TARGET_MANUAL`

**Excerpt (rustoshi)**
```rust
pub fn from_mib(prune_mib: Option<u64>, assumeutxo_height: u32) -> Self {
    let target_bytes = match prune_mib {
        None | Some(0) => 0,
        Some(1) => PRUNE_MANUAL_SENTINEL,
        Some(n) if n < 550 => PRUNE_MANUAL_SENTINEL,   // silent collapse
        Some(n) => n.saturating_mul(1024 * 1024),
    };
```

**Impact:** Operator misconfiguration — node ships full block data
forever despite `-prune=540`, hits disk-full, dies. Core surfaces this
to stderr at init; rustoshi swallows it.

---

## BUG-2 (P0) — `auto_prune` ignores `target_bytes` (no disk-usage measurement)

**Severity:** P0. Bitcoin Core's `FindFilesToPrune`
(`node/blockstorage.cpp::FindFilesToPrune`) iterates files oldest→newest
and stops when `nCurrentUsage - nBytesToPrune + nBuffer < target`. It
also computes a chain-work-adjusted last-allowed-prune-height. rustoshi
ignores both — `auto_prune` (`prune.rs:124-170`) deletes everything below
`tip - MIN_BLOCKS_TO_KEEP` every time it fires, regardless of whether
the keep-window itself is already under the configured target.

The defensive comment (`prune.rs:108-116`) is a comment-as-confession:

> "We don't measure on-disk usage against the byte target here (RocksDB
> doesn't expose a per-CF byte count cheaply); instead we drop everything
> below the keep window every time the trigger fires. That's safe because:
>  - the keep window itself bounds storage growth at ~288 * avg block
>    (~432 MiB worst case), which is below the 550 MiB Core minimum"

This is wrong: (a) "below the 550 MiB Core minimum" is only true for
mainnet pre-segwit avg ~1.5 MiB blocks — post-segwit blocks up to 4 MB
of weight push 288 blocks to ~1.15 GiB; (b) the operator who chose
`--prune=10000` (10 GiB target) gets the SAME aggressive 288-block
keep behavior as the operator who chose `--prune=550`. The byte target
is dead-data.

**File:** `crates/storage/src/prune.rs:124-170`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::FindFilesToPrune`

**Impact:** Larger `--prune=N` settings are silently downgraded to the
minimum. Operators who paid for 100 GiB of NVMe to retain 100 GiB of
historical blocks find the node keeps only ~432 MiB.

---

## BUG-3 (P1) — `auto_prune` fires before UTXO flush; wrong order vs Core's FlushStateToDisk

**Severity:** P1. Core's `FlushStateToDisk(PERIODIC)`
(`validation.cpp:2702-2822`) is the **single** entry point for periodic
maintenance: it computes `fFlushForPrune` from
`FindFilesToPrune`, then **writes UTXO + chain state to disk FIRST**
(line 2786-2796), then performs the prune unlinks (line 2799-2806).
rustoshi's connect-block loop (`main.rs:2456-2469, 3016-3026`) calls
`auto_prune` directly after `chain_state.process_block` succeeds — the
UTXO writes in the same iteration are still in the
`BlockStoreUtxoView` in-memory cache and have NOT yet been flushed to
RocksDB. A crash between auto-prune and the next cache flush leaves
the UTXO set inconsistent with the pruned block index (block bodies
deleted that would be needed to replay the lost UTXO mutations on
restart).

**File:** `rustoshi/src/main.rs:2456-2469`, `3016-3026`

**Core ref:** `bitcoin-core/src/validation.cpp::FlushStateToDisk:2702-2822`

**Impact:** Crash-recovery hazard. Mitigated by the fact that
`BlockStoreUtxoView::flush_if_needed` typically fires more often than
the every-100-blocks prune trigger, but the invariant ordering is the
opposite of Core's — flush-then-prune in Core, prune-then-(maybe-flush)
in rustoshi.

---

## BUG-4 (P0-CDIV) — `pruneblockchain` RPC missing dual-mode height/timestamp parse

**Severity:** P0-CDIV. Bitcoin Core's `pruneblockchain`
(`bitcoin-core/src/rpc/blockchain.cpp:908-950`) accepts a single integer
parameter that is interpreted as a **block height when ≤ 1e9** and as a
**UNIX timestamp when > 1e9**, with the timestamp resolved via
`active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0)`.
This is documented in the RPC help string: "Attempts to delete block and
undo data up to a specified height or timestamp". rustoshi's trait method
is typed `prune_blockchain(height: u32)` — passing a UNIX timestamp
(e.g. `1700000000`) overflows `u32` and the JSON-RPC layer rejects the
call with a deserialize error rather than treating it as a timestamp.

The corresponding comment at `prune.rs:179-182` is a comment-as-confession:

> "Caller (the RPC handler) is responsible for converting the
>  'Unix epoch timestamp vs height' overload [...]. rustoshi's RPC
>  surface only takes a height here."

…but the RPC handler at `server.rs:5137` also does no conversion.

**File:** `crates/rpc/src/server.rs:511-512, 5137-5206`,
`crates/storage/src/prune.rs:179-182`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:908-950`

**Impact:** Drop-in scripts that pass a UNIX timestamp to
`pruneblockchain` (a common pattern: "prune everything older than 30
days ago") fail against rustoshi. Wallet middleware (BTCPay-Server,
mempool.space exporters) breaks.

---

## BUG-5 (P0) — No `-assumevalid` CLI argument; chainparams hardcode is the only setting

**Severity:** P0. Bitcoin Core's `-assumevalid=<hex>` arg
(`bitcoin-core/src/init.cpp:487`) lets the operator (a) override the
default with a more-recent block they've personally verified, or (b)
set `-assumevalid=0` to disable the skip entirely (always-verify mode).
The default per network is well-published in the arg's help string and
in the source. rustoshi's `Cli` struct (`rustoshi/src/main.rs:155-160`,
`--prune` and `--metrics-port` and `--import-blocks` and `--daemon` —
no `--assumevalid`) ships NO operator-facing knob.

Operators who want to audit the skip — security-conscious node
operators, exchange custody, anyone evaluating a contentious chainsplit
— have to recompile to disable assumevalid. Cross-impl: this is the
"operator-knob absence" pattern flagged W134 (BIP-37) G6, W135 G6.

**File:** `rustoshi/src/main.rs:155-160`

**Core ref:** `bitcoin-core/src/init.cpp:487`

**Impact:** Operator-knob absence; recompile required to flip
always-verify or to update the hash. Stale chainparams becomes the
operator's only recourse.

---

## BUG-6 (P1) — `assumed_valid_block` set to `None` on testnet3 and signet (Core has values)

**Severity:** P1. Core's `kernel/chainparams.cpp` ships
`defaultAssumeValid` for testnet3 (line 233:
`000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` at
height 4842348) and for default-signet (line 424:
`00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329` at
height 293175). rustoshi's testnet3 and signet entries (`params.rs:770-771,
909-910`) set both `assumed_valid_block` and `assumed_valid_height` to
`None`. The signet entry is plausibly intentional (rustoshi may target
"empty signet" which Core also leaves blank at line 558), but testnet3
is just an unforced regression — a fresh testnet3 IBD verifies every
signature back to 2012 instead of skipping ~4.8M blocks.

**File:** `crates/consensus/src/params.rs:770-771, 909-910`

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:233, 424`

**Impact:** Testnet3 IBD is ~10x slower than Core. Signet effectiveness
depends on whether rustoshi means default signet or empty signet (no
operator-facing flag to distinguish; cross-cite BUG-5).

---

## BUG-7 (P0-CDIV) — `skip_scripts` gate is height-only; missing 4 of Core's 5 preconditions; `assumed_valid_block` hash is dead data

**Severity:** P0-CDIV. **The headline finding of this audit.** Bitcoin
Core's assumevalid skip-gate at `ConnectBlock` (validation.cpp:2345-2383)
runs five preconditions before deciding to skip script verification:

```cpp
const char* script_check_reason;
if (m_chainman.AssumedValidBlock().IsNull()) {
    script_check_reason = "assumevalid=0 (always verify)";
} else {
    BlockMap::const_iterator it{m_blockman.m_block_index.find(m_chainman.AssumedValidBlock())};
    if (it == m_blockman.m_block_index.end()) {
        script_check_reason = "assumevalid hash not in headers";       // (1)
    } else if (it->second.GetAncestor(pindex->nHeight) != pindex) {
        script_check_reason = "block not in assumevalid chain";        // (2)
    } else if (m_chainman.m_best_header->GetAncestor(pindex->nHeight) != pindex) {
        script_check_reason = "block not in best header chain";        // (3)
    } else if (m_chainman.m_best_header->nChainWork < m_chainman.MinimumChainWork()) {
        script_check_reason = "best header chainwork below minimumchainwork"; // (4)
    } else if (GetBlockProofEquivalentTime(*m_chainman.m_best_header, *pindex, *m_chainman.m_best_header, params.GetConsensus()) <= TWO_WEEKS_IN_SECONDS) {
        script_check_reason = "block too recent relative to best header";     // (5)
    } else {
        script_check_reason = nullptr;  // SKIP
    }
}
const bool fScriptChecks{!!script_check_reason};
```

The 2-week (5) check is explicitly there to prevent the
"forced-assumevalid" attack documented in the comment block immediately
following: "The equivalent time check discourages hash power from
extorting the network via DOS attack into accepting an invalid block
through telling users they must manually set assumevalid."

rustoshi's gate (`validation.rs:1553-1557`):

```rust
let skip_scripts = match params.assumed_valid_height {
    Some(av_height) => height <= av_height,
    None => false,
};
```

This is **1 of 5** preconditions and the weakest of the bunch. The
`assumed_valid_block` hash (chainparams.assumed_valid_block) is
**dead data** — grep shows zero callers in production code. Concretely:

- A reorg onto a side-chain at height ≤ av_height silently skips
  script verification on the side-branch.
- A peer who feeds us 100k headers that lie below av_height but are NOT
  on the assume-valid chain (different fork) bypasses signature
  verification entirely.
- The minimum-chain-work + best-header sanity checks (Core's
  preconditions 3-4) are missing — a malicious peer who races us to
  fill the best-header chain with stuff just below av_height bypasses
  the bar.
- The 2-week DoS guard (precondition 5) is absent — the attack Core
  explicitly documents is open against rustoshi.

This is the **"Assume-valid scope creep" inverse**: hotbuns W145 BUG-2
folded extra invariants INTO the assumevalid skip; rustoshi DROPS the
gating invariants that should be checked BEFORE the skip. Both classes
land in the wrong place relative to Core's "skip sig only, after
verifying the chain context" contract.

**File:** `crates/consensus/src/validation.rs:1553-1557`,
`crates/consensus/src/params.rs:529` (dead field).

**Core ref:** `bitcoin-core/src/validation.cpp:2345-2383`

**Impact:** P0-CDIV chain-split candidate under a side-branch attack at
heights below av_height. Also defeats the 2-week DoS guard that Core
specifically engineered to prevent extortion-based malicious-skip
attacks. Cross-cite hotbuns W145 BUG-2-6 cluster (the symmetric "scope
creep" pattern).

---

## BUG-8 (P0) — `HeadersPresyncState` has zero production callers (anti-DoS subsystem entirely dead)

**Severity:** P0. The PRESYNC/REDOWNLOAD anti-DoS pipeline
(`crates/network/src/headers_presync.rs`) implements the full Core
algorithm: `current_chain_work`, `redownload_chain_work`, commit-offset
randomization, `minimum_required_work` accumulators, MTP-anchored
max_commitments. It is comprehensively tested
(20+ unit tests at the bottom of the file). And it is called by
**zero production code paths**. Grep:

```
grep -rn "HeadersPresyncState::new" \
    crates/network/src/peer*.rs \
    crates/network/src/header_sync.rs \
    rustoshi/src/
# (no matches outside tests)
```

`accept_block_header_chain_work` (`validation.rs:1018-1039`, header-side
chain-work gate) takes a `min_pow_checked` boolean that is supposed to
be threaded from PRESYNC — but the production callers all pass
`false` (no PRESYNC ran), which means the gate fires correctly but
the more-sophisticated chain-work-during-headers-sync state machine
that Core uses (BIP-130 + PR#25717 headers-sync state machine) is
absent.

Cross-cite from the source itself (`validation.rs:1004-1008`):

> "`min_pow_checked` — `true` when the PRESYNC/REDOWNLOAD pipeline has
> already validated that the chain has sufficient work. Callers that go
> through the PRESYNC anti-DoS pipeline pass `true`."

…but no caller goes through that pipeline.

**File:** `crates/network/src/headers_presync.rs` (entire module),
`crates/consensus/src/validation.rs:1018-1039` (caller-side stub).

**Core ref:** `bitcoin-core/src/headerssync.cpp` (entire file),
PR #25717.

**Impact:** Memory-bomb DoS open via header floods: a peer can send 8
GB of headers with valid PoW but invalid chain-work chain, and rustoshi
will allocate `BlockNode` for every one before discovering the
chain-work shortfall. Core's PRESYNC commits to a chain-work bar before
storing any block index entries; rustoshi commits to nothing.

---

## BUG-9 (P1) — `is_ibd_complete` ignores chain_work (two-pipeline-guard with `should_exit_ibd`)

**Severity:** P1. Two definitions of "IBD complete" coexist:

1. `crates/rpc/src/server.rs:1156-1217` — `should_exit_ibd` reads
   `state.params.minimum_chain_work` and `compare_chain_work` against
   tip chain_work (correct, mirrors Core's `UpdateIBDStatus`).
2. `crates/network/src/block_download.rs:425-432` — `is_ibd_complete`
   is purely structural:
   ```rust
   pub fn is_ibd_complete(&self) -> bool {
       self.validated_tip_height >= self.best_header_height
           && self.download_queue.is_empty()
           && self.in_flight.is_empty()
           && self.received_blocks.is_empty()
   }
   ```

A node that has downloaded all known headers from a malicious peer but
whose chain has less than `minimum_chain_work` would have
`is_ibd_complete() == true` (structural) but `should_exit_ibd() == false`
(chain-work). Different IBD entry points see different truths. This is
the same two-pipeline-guard pattern as the W128 banman 8/10 fleet finding.

**File:** `crates/network/src/block_download.rs:427-432`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
the chain-work check is part of the SINGLE `m_cached_is_ibd` latch.

**Impact:** Block-download orchestration can think IBD is complete and
start `getdata`-ing transactions / serving inv / accepting compact
blocks while the chain-work gate is still failing. Cross-impl
two-pipeline-guard extension (16th distinct instance).

---

## BUG-10 (P0-CDIV) — `BlockStatus` validity ladder uses bit-set check on non-power-of-two values

**Severity:** P0-CDIV. Core's `BlockStatus` (`chain.h:42-86`) is an
**ordered** ladder: `BLOCK_VALID_RESERVED=1`, `BLOCK_VALID_TREE=2`,
`BLOCK_VALID_TRANSACTIONS=3`, `BLOCK_VALID_CHAIN=4`,
`BLOCK_VALID_SCRIPTS=5`, gated through `BLOCK_VALID_MASK = 0b111` and
checked via:

```cpp
bool RawIsValid(enum BlockStatus nUpTo) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    assert(!(nUpTo & ~BLOCK_VALID_MASK));
    if (nStatus & BLOCK_FAILED_VALID) return false;
    return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
}
```

The 3-bit mask + `>=` comparison gives the level: status 0b011 means
"valid up to TRANSACTIONS (3)"; status 0b101 means "valid up to
SCRIPTS (5)" — which **also** satisfies "valid up to TRANSACTIONS" by
the `>=` check.

rustoshi's `BlockStatus` (`block_store.rs:24-37`) uses the same numeric
values (1, 2, 3, 4, 5) — but the check is a **bit-set**:

```rust
pub fn has(&self, flag: u32) -> bool {
    self.0 & flag != 0
}
```

Concrete consequences:
- `set(VALID_SCRIPTS = 5)` → `self.0 |= 5` → sets bits 0 and 2 → bit
  4 (= `VALID_CHAIN`) is NEVER set by setting VALID_SCRIPTS.
- `has(VALID_CHAIN = 4)` on a `VALID_SCRIPTS` block returns `(0b101 &
  0b100) != 0` = `true` — happens to work by accident.
- `has(VALID_TRANSACTIONS = 3)` on a `VALID_HEADER`-only block returns
  `(0b001 & 0b011) != 0` = `true` — **wrong** (returns "valid
  transactions" for a header-only entry).
- `has(VALID_CHAIN = 4)` on a `VALID_TREE`-only block returns `(0b010 &
  0b100) != 0` = `false` — accidentally correct.
- `has(VALID_TRANSACTIONS = 3)` on a `VALID_TREE`-only block returns
  `(0b010 & 0b011) != 0` = `true` — **wrong** (returns "valid
  transactions" for a parse-only entry).

In practice rustoshi only ever sets `VALID_SCRIPTS` (full-validate) or
nothing, so the bug manifests only in the lower-ladder transition
cases — but BLOCK_VALID_TRANSACTIONS is exactly the
gate Core checks before considering a block for `setBlockIndexCandidates`,
and `has_valid_transactions` is the gate rustoshi reads in
`chain_manager.rs:71-74`.

**File:** `crates/storage/src/block_store.rs:24-75`

**Core ref:** `bitcoin-core/src/chain.h:42-86, 250-260` (`RawIsValid`).

**Impact:** Status-bitfield ordering invariants violated. Lower-ladder
blocks can be miscategorized as having higher-ladder validity. Cross-cite
blockbrew W148 BUG-9 (same pattern: power-of-two collapse of Core's 5-level
ordered ladder). Cross-cite W109 G6.

---

## BUG-11 (P1) — `BLOCK_ASSUMED_VALID` flag absent from `BlockStatus`

**Severity:** P1. Core defines `BLOCK_ASSUMED_VALID = 128`
(`chain.h:84`) to mark blocks whose `nChainTx` was populated from the
assumeUTXO snapshot rather than from full historical sync. Assumeutxo
introduces a "background validation" chain that catches up and clears
the flag once each block is fully verified. rustoshi's `BlockStatus`
enum (`block_store.rs:24-49`) defines only `VALID_*` + `HAVE_*` +
`FAILED_*` — no `ASSUMED_VALID`. The assumeUTXO subsystem
(`storage/src/snapshot.rs`, W102/W138 audits) writes blocks marked as
fully-valid even though they were never sig-verified.

**File:** `crates/storage/src/block_store.rs:24-49`

**Core ref:** `bitcoin-core/src/chain.h:80-84`

**Impact:** `getblock`, `getchaintips`, `getblockchaininfo` cannot
distinguish "verified from genesis" blocks from "trusted via snapshot"
blocks. Background-validation status invisible in RPC. Cross-cite
W102 / W138 dead-data fleet pattern.

---

## BUG-12 (P0-CDIV) — Parallel `block_status` module in `chain_manager.rs` duplicates AND re-broken bit-set check

**Severity:** P0-CDIV. `crates/consensus/src/chain_manager.rs:13-23`
defines:

```rust
pub mod block_status {
    pub const FAILED_VALIDITY: u32 = 32;
    pub const FAILED_CHILD: u32 = 64;
    pub const VALID_TRANSACTIONS: u32 = 3;
    pub const HAVE_DATA: u32 = 8;
}
```

…with the comment "matching storage::BlockStatus". Two-pipeline-guard
17th distinct fleet instance: this module re-defines the constants in
a way that is **byte-identical to the storage definitions**, and then
implements `has_valid_transactions` (line 71-74) using the same broken
bit-set check `(self.status & block_status::VALID_TRANSACTIONS) != 0`,
which inherits BUG-10's semantics-bug — a `VALID_HEADER`-only block
returns `has_valid_transactions() == true`. Two consumers of the same
broken semantics; fixing only one leaves the other latent.

**File:** `crates/consensus/src/chain_manager.rs:13-80`

**Core ref:** `bitcoin-core/src/chain.h:42-86`

**Impact:** Two-pipeline-guard for the status enum itself. Any future
fix to `storage::BlockStatus::has` (e.g. to make it the masked `>=`
semantics Core uses) must also fix `consensus::chain_manager::BlockMeta`
or the chain-management path will silently disagree with the storage
path on validity classification.

---

## BUG-13 (P0-CDIV) — NODE_NETWORK is NOT removed when prune is on (Core removes; rustoshi keeps both bits)

**Severity:** P0-CDIV. Core's `g_local_services` starts as
`NODE_NETWORK_LIMITED | NODE_WITNESS` (`init.cpp:863`) and adds
`NODE_NETWORK` only when `!IsPruneMode()` (`init.cpp:1947-1952`):

```cpp
if (!chainman.m_blockman.IsPruneMode()) {
    LogInfo("Setting NODE_NETWORK in non-prune mode");
    g_local_services = ServiceFlags(g_local_services | NODE_NETWORK);
} else {
    LogInfo("Running node in NODE_NETWORK_LIMITED mode until snapshot background sync completes");
}
```

rustoshi's `local_services()` (`peer_manager.rs:1122-1140`):

```rust
let mut s = NODE_NETWORK | NODE_WITNESS;     // ALWAYS sets NODE_NETWORK
// ...
if self.config.prune_mode {
    s |= NODE_NETWORK_LIMITED;               // ADDS LIMITED on top
}
```

A pruned rustoshi node advertises `NODE_NETWORK | NODE_NETWORK_LIMITED |
NODE_WITNESS` — the `NODE_NETWORK` bit promises peers that we serve the
entire historical chain, which is precisely the promise BIP-159 is
designed to retract. Peers will `getdata` historical blocks
indiscriminately, get `notfound` responses, may disconnect or
misbehave-score us.

**File:** `crates/network/src/peer_manager.rs:1122-1140`

**Core ref:** `bitcoin-core/src/init.cpp:863, 1947-1952`

**Impact:** BIP-159 contract violation. Peer misbehavior scoring and
disconnect risk. Pruned nodes lie about their service offering.

---

## BUG-14 (P1) — `getblockchaininfo.size_on_disk` hardcoded to 0

**Severity:** P1. `crates/rpc/src/server.rs:2945`:

```rust
size_on_disk: 0,           // would need filesystem stat
```

Core's `getblockchaininfo` returns the actual byte count of block + undo
files (`rpc/blockchain.cpp:1456-1459`). Tools that condition prune
decisions on this value (BTCPay-Server, Mempool.space exporters,
monitoring dashboards, custom rebalancer scripts) get a permanent zero
from rustoshi → conclude there's no data to prune → don't fire the
prune RPC → disk fills.

**File:** `crates/rpc/src/server.rs:2945`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:1456-1459`

**Impact:** Operator monitoring breakage; integration with external
tools degraded. Comment-as-confession at the bug site documents the
gap.

---

## BUG-15 (P0-CDIV) — `getblockchaininfo.automatic_pruning` field missing entirely

**Severity:** P0-CDIV. Core's `getblockchaininfo`
(`rpc/blockchain.cpp:1452-1454`) returns:

```cpp
const bool automatic_pruning{chainman.m_blockman.GetPruneTarget() != BlockManager::PRUNE_TARGET_MANUAL};
obj.pushKV("automatic_pruning",  automatic_pruning);
if (automatic_pruning) {
    obj.pushKV("prune_target_size",  m_blockman.GetPruneTarget());
}
```

The field is `optional=true` in the help schema but is ALWAYS present
when pruning is enabled. The shape-contract is "prune_target_size
present iff automatic_pruning=true". rustoshi's `BlockchainInfo` type
(`crates/rpc/src/types.rs:200-220`) defines no `automatic_pruning`
field at all, and always emits `prune_target_size` when `prune_mode`
is set (regardless of manual-only mode). A client that does
`json.get("automatic_pruning")` against rustoshi gets `KeyError`; a
client that treats `prune_target_size` presence as "auto-prune is
configured" gets `True` even under `-prune=1` manual-only.

**File:** `crates/rpc/src/types.rs:200-220`, `server.rs:2920-2930`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:1452-1454`

**Impact:** Wire-format / RPC-shape divergence. Cross-impl monitoring,
wallets that introspect blockchain info, BIP-159-aware clients get
wrong answers.

---

## BUG-16 (P1) — `FlatBlockStore` prune helpers entirely dead (cross-cite W146 BUG-1)

**Severity:** P1. `crates/storage/src/blockstore.rs:670-870` ships
`find_files_to_prune`, `find_files_to_prune_manual`,
`prune_one_block_file`, `unlink_pruned_files` — the full per-flat-file
prune surface (the closer mirror to Core's
`node/blockstorage.cpp::FindFilesToPrune`). These are dead in
production: `grep -rn FlatBlockStore rustoshi/src/ crates/consensus/`
returns empty. Production uses the RocksDB-key-granular `prune.rs`
path. The dead helpers add ~200 LOC of test surface and constant maintenance
burden without contributing to any active code path.

Cross-cite W146 BUG-1 for the underlying dead-class diagnosis. This is
the per-subsystem instance for the prune helpers specifically — auto-prune,
manual-prune, find_files_to_prune all share the same "implemented as a
mock of Core's flat-file flow but never invoked" treatment.

**File:** `crates/storage/src/blockstore.rs:670-870`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::FindFilesToPrune`,
etc.

**Impact:** Maintenance overhead; risk of code-rot finding (next refactor
breaks the dead helpers, nobody notices because nothing calls them).
Same dead-class fleet pattern as W138 (ChainstateManager dead in 9 of
10 impls).

---

## BUG-17 (P1) — `auto_prune` trigger cadence (`height % 100`) is not based on disk pressure

**Severity:** P1. Core fires prune from `FlushStateToDisk(PERIODIC)`
which is called by `MaybeFlushFromGenericChainstateManager` — the
period is based on chainstate cache pressure + bytes-since-last-flush,
NOT on a fixed block-count modulo. rustoshi's connect-block loop
(`main.rs:2456-2469`):

```rust
if prune_cfg.auto_prune_enabled()
    && (height.is_multiple_of(100) || height == prune_cfg.assumeutxo_height)
{
    if let Err(e) = rustoshi_storage::auto_prune(&block_store, &prune_cfg, height) {
```

The modulo-100 cadence misses the "deleted N MB this last batch, now
under target" feedback — under a high-throughput sync, the prune
trigger fires LESS often than under a slow sync (same disk usage per
unit wall-time). Compounds BUG-2's "ignore target_bytes" by removing
even the implicit "disk-pressure" signal.

**File:** `rustoshi/src/main.rs:2456-2469, 3016-3026`

**Core ref:** `bitcoin-core/src/validation.cpp::FlushStateToDisk:2702-2822`

**Impact:** Indirect — once BUG-2 is fixed and `auto_prune` respects
the byte target, this becomes the relevant operational lever.
Currently masked.

---

## BUG-18 (P1) — `manual_prune_to_height` silently returns success when called with `prune_mode=false` (defense-in-depth absent at API)

**Severity:** P1. `crates/storage/src/prune.rs:188-192`:

```rust
pub fn manual_prune_to_height(
    store: &BlockStore<'_>,
    config: &PruneCoordConfig,
    tip_height: u32,
    requested_height: u32,
) -> Result<PruneOutcome, StorageError> {
    if !config.is_prune_mode() {
        // Caller should already have rejected; defense in depth.
        return Ok(PruneOutcome::default());
    }
```

The RPC handler at `server.rs:5143-5148` correctly returns
`RPC_MISC_ERROR` when `state.prune_mode == false` — so the
defense-in-depth path is only relevant for non-RPC callers (tests,
future direct invocation). But: returning `Ok(default)` silently
discards the "was-pruned" signal. A caller programmatically invoking
the helper to gate a downstream operation ("did anything actually get
pruned?") cannot distinguish "no pruning configured" from "nothing
prunable in range". Should be an `Err` variant
(`StorageError::PruneNotEnabled` or similar).

**File:** `crates/storage/src/prune.rs:188-192`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain`
returns the error string `"Cannot prune blocks because node is not in
prune mode."` at the same shape boundary.

**Impact:** Programmatic callers cannot distinguish "no prune mode" from
"no-op prune". RPC layer is fine; internal helpers are not.

---

## BUG-19 (P1) — `set_have_pruned` (legacy flat-file plumbing) never set even when RocksDB prune fires

**Severity:** P1. `FlatBlockStore::have_pruned`
(`crates/storage/src/blockstore.rs:357-415`) tracks whether pruning
has ever run — used by Core's `m_have_pruned` to short-circuit certain
init-time block-availability questions. rustoshi's RocksDB-keyed
prune path (`block_store.rs::prune_active_chain_range`) does NOT
write this flag because it doesn't use `FlatBlockStore` at all. So
even on a node where pruning has dropped 99% of historical bodies,
any code path that queries `FlatBlockStore::have_pruned()` returns
`false`.

This compounds BUG-16: not only are the flat-file helpers dead in
production, but the persistent-state flag that's meant to bridge
restart-time logic is also stale.

**File:** `crates/storage/src/blockstore.rs:357-415`,
`block_store.rs::prune_active_chain_range:781-814` (writer, but does
NOT update flat-file flag).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::m_have_pruned`

**Impact:** Latent — currently no code path reads `have_pruned()`, but
the moment one does (e.g. a future `CheckBlockIndex`-equivalent that
relaxes BLOCK_HAVE_DATA invariants when `m_have_pruned`), the answer
will be wrong on every pruned rustoshi node.

---

## BUG-20 (P1) — `prune_block` does NOT clear `BLOCK_HAVE_UNDO` even when undo CF delete succeeds for a missing-entry block

**Severity:** P1. `crates/storage/src/block_store.rs:727-741`:

```rust
pub fn prune_block(&self, hash: &Hash256) -> Result<(), StorageError> {
    self.db.delete_cf(CF_BLOCKS, hash.as_bytes())?;
    self.db.delete_cf(CF_UNDO, hash.as_bytes())?;
    if let Some(mut entry) = self.get_block_index(hash)? {
        entry.status.clear(BlockStatus::HAVE_DATA);
        entry.status.clear(BlockStatus::HAVE_UNDO);
        self.put_block_index(hash, &entry)?;
    }
    Ok(())
}
```

Edge case: the block body + undo are deleted from the column families
unconditionally, but the index entry is updated **only if present**
(`if let Some(mut entry)`). If a block is partially-pruned (body
delete succeeded last pass, but flag-clear failed before
`put_block_index` due to a write fault), the index entry retains
`HAVE_DATA | HAVE_UNDO` set, and on next prune pass: `if let Some` →
update succeeds, but `delete_cf` is a no-op on the already-empty key
— so the flag state heals. The opposite race (flag-cleared first,
body delete crashed) leaves an orphan body in CF_BLOCKS until next
prune. This isn't a bug per se but it's NOT atomic — there is no
RocksDB WriteBatch around the three operations. Core uses
`m_block_tree_db->WriteBatchSync` for the same triad.

**File:** `crates/storage/src/block_store.rs:727-741`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile`
+ `LevelDBBatch`.

**Impact:** Crash-window inconsistency between CF_BLOCKS / CF_UNDO /
CF_BLOCK_INDEX. Heals on next prune pass for the
flag-not-cleared case but not for the orphan-body case.

---

## BUG-21 (P1) — `prune_active_chain_range` walks heights serially without RocksDB batching

**Severity:** P1. `prune_active_chain_range` (`block_store.rs:781-814`)
iterates `for h in from_height..=to_height` and calls `prune_block` for
each — which itself issues 2 `delete_cf` calls plus a
`get_block_index` + `put_block_index` round-trip per block. A manual
prune of 100k blocks fires 400k RocksDB ops with no batching, no
WriteBatch, no atomicity. Core's flat-file path is bulk: one unlink per
128 MiB file (`unlink_pruned_files`). rustoshi's per-key granularity is
the right tradeoff for RocksDB but should be batched: a single
`WriteBatch` of N delete + N put is one fsync vs N fsyncs.

**File:** `crates/storage/src/block_store.rs:781-814`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::UnlinkPrunedFiles`

**Impact:** Throughput — manual prune of a long range takes O(N) write
amplification. Crash mid-range = partial state. Should batch.

---

## BUG-22 (P0-CDIV) — `accept_block_header_chain_work` short-circuits when `min_pow_checked=true` but is never called with the result of a real PRESYNC

**Severity:** P0-CDIV. `validation.rs:1018-1039`:

```rust
pub fn accept_block_header_chain_work(
    header_chain_work: &[u8; 32],
    min_pow_checked: bool,
    params: &ChainParams,
) -> Result<(), ValidationError> {
    if min_pow_checked {
        // PRESYNC/REDOWNLOAD already validated accumulated work — skip.
        return Ok(());
    }
    if header_chain_work < &params.minimum_chain_work {
        return Err(ValidationError::TooLittleChainwork);
    }
    Ok(())
}
```

The function's contract is "trust the caller's claim that PRESYNC
already validated the chain". Combined with BUG-8 (PRESYNC dead), this
becomes: every caller passes either `min_pow_checked = true`
(skipping the gate, trusting a PRESYNC that never ran) or
`min_pow_checked = false` (gate fires once per header). The fast-path
of "trust PRESYNC to have done the heavy lifting once" is unreachable
— but the API surface invites future regressions where a caller
sets `true` for performance and the gate is silently bypassed.

**File:** `crates/consensus/src/validation.rs:1018-1039`

**Core ref:** `bitcoin-core/src/validation.cpp:4229-4231`

**Impact:** Architectural — gate-bypass API is wired but the upstream
producer doesn't exist. Any future caller that flips the flag without
also building the PRESYNC machinery silently disables the
chain-work bar. Cross-cite BUG-8.

---

## Cross-impl patterns this audit confirms

1. **Two-pipeline-guard, 16th-17th distinct extensions** —
   `BlockStatus` defined twice (BUG-10, BUG-12), `is_ibd_complete` vs
   `should_exit_ibd` (BUG-9).
2. **Dead-data plumbing** — `assumed_valid_block` hash (BUG-7),
   `HeadersPresyncState` entire subsystem (BUG-8), `FlatBlockStore`
   prune helpers (BUG-16), `set_have_pruned` (BUG-19).
3. **Operator-knob absence** — `-assumevalid` CLI missing (BUG-5);
   companion to W134 G6, W135 G6, W148 G15.
4. **Comment-as-confession** — `prune.rs:108-116` "we don't measure on-disk
   usage" (BUG-2), `prune.rs:179-182` "RPC surface only takes a height"
   (BUG-4), `server.rs:2945` "would need filesystem stat" (BUG-14).
5. **Wire-format/RPC-shape divergence** — `pruneblockchain` dual-mode
   missing (BUG-4), `automatic_pruning` field missing (BUG-15),
   NODE_NETWORK/NODE_NETWORK_LIMITED inverted (BUG-13).
6. **Assume-valid mis-scope** — rustoshi DROPS preconditions Core
   checks BEFORE the skip (BUG-7); symmetric inverse of hotbuns W145
   "Assume-valid scope creep" which ADDED invariants INTO the skip.
7. **Sub-minimum prune accepted as manual** (BUG-1) — parse-time
   silent collapse; same shape as W144 "shape-gated NOT flag-gated"
   (lunarblock).

---

## Summary

**22 BUGs catalogued.** Severity breakdown:
- **P0 / P0-CDIV: 8** (BUG-2, BUG-4, BUG-5, BUG-7, BUG-8, BUG-10,
  BUG-12, BUG-13, BUG-15, BUG-22) — **10 if we count P0-CDIV separately**.
  Headline: BUG-7 (assumevalid 4 of 5 preconditions missing —
  P0-CDIV chain-split candidate under side-branch attack at heights
  below av_height); BUG-8 (PRESYNC dead — memory-bomb DoS open);
  BUG-13 (NODE_NETWORK/NODE_NETWORK_LIMITED inverted — pruned nodes
  lie about service offering).
- **P1: 12** — operational / shape / fleet-pattern issues.

**Top 3 findings:**
1. **BUG-7** — `assumed_valid_block` is dead data; rustoshi's
   `skip_scripts` gate has 1 of Core's 5 preconditions; the 2-week DoS
   guard Core specifically engineered against forced-assumevalid
   extortion is absent.
2. **BUG-8** — Entire `HeadersPresyncState` anti-DoS pipeline is
   defined-and-tested but has zero production callers; memory-bomb
   DoS open against header floods.
3. **BUG-13** — Pruned rustoshi nodes advertise `NODE_NETWORK |
   NODE_NETWORK_LIMITED` instead of Core's `NODE_NETWORK_LIMITED`-only;
   BIP-159 contract violation; peers will `getdata` historical blocks
   we cannot serve, then `notfound`/misbehavior-score us.

End of W149 rustoshi audit.
