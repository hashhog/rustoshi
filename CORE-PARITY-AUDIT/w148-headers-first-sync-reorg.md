# W148 — Headers-first sync + chain selection + reorg audit (rustoshi)

**Wave:** W148 — Headers-first sync + chain selection + reorg (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi headers-first IBD pipeline, the
`ProcessNewBlockHeaders` / `ActivateBestChain` / `ConnectTip` /
`DisconnectTip` / `FindMostWorkChain` surface, the `CChain` / `CBlockIndex`
in-memory state, MAX_REORG_DEPTH-style depth gates, and the BLOCK_VALID_*
validity bitfield semantics.

**Files audited:**
- `crates/consensus/src/chain_state.rs` — `ChainState::process_block`
  (395-533), `process_block_at_height` (413), `process_block_inner`
  (424-533), `set_tip` (357-361), `reorganize` (553-713),
  `disconnect_block` (740-795), `compute_mtp` (806-838),
  `compute_mtp_via_get_block` (855-878), `ChainStateNullSeqContext` (946-952).
- `crates/consensus/src/chain_manager.rs` — `block_status` (14-23),
  `BlockMeta` (50-80), `compare_chain_work` (143-152),
  `compare_chain_work_with_tiebreak` (165-180), `is_ancestor` (185-216),
  `get_ancestor` (222-249), `find_descendants` (280-307),
  `ChainManagerState::assign_precious_sequence` (115-136).
- `crates/consensus/src/validation.rs` — `accept_block_header_chain_work`
  (1018-1039), `contextual_check_block_header` (mentioned in
  `lib.rs:62` re-export but dead in production), `contextual_check_block`
  (1079-1102), `BlockIndexEntry` (869-881), `ChainContext` trait (884-901),
  `StubChainContext` (1109-1127).
- `crates/storage/src/block_store.rs` — `BlockStatus` (21-75; `VALID_HEADER=1`,
  `VALID_TREE=2`, `VALID_TRANSACTIONS=3`, `VALID_CHAIN=4`, `VALID_SCRIPTS=5`,
  `HAVE_DATA=8`, `HAVE_UNDO=16`, `FAILED_VALIDITY=32`, `FAILED_CHILD=64`),
  `BlockIndexEntry` (86-105), `put_block_index` (223), `is_block_invalid`
  (615-641), `mark_block_invalid` (around 555-630).
- `crates/network/src/header_sync.rs` — `HeaderSync` (48-62),
  `process_headers` (250-372), `best_sync_peer` (138-144),
  `build_block_locator` (159-189), `make_getheaders` (195-204),
  `start_sync` (213-227), `note_unconnecting_headers` (115-119),
  `MAX_HEADERS_PER_REQUEST=2000` (18),
  `MAX_NUM_UNCONNECTING_HEADERS_MSGS=10` (25).
- `crates/network/src/headers_presync.rs` — `PresyncState` (66-75),
  `COMMITMENT_PERIOD=600` (56), `REDOWNLOAD_BUFFER_SIZE=14304` (63).
- `crates/network/src/block_download.rs` — `BlockDownloader` (102-123),
  `MAX_BLOCKS_IN_FLIGHT_PER_PEER=16` (24), `MAX_BLOCKS_IN_FLIGHT=128` (28),
  `DOWNLOAD_WINDOW_SIZE=1024` (44), `MAX_RECEIVED_BLOCKS=512` (56),
  `next_block_to_validate` (357).
- `crates/rpc/src/server.rs` — `MAX_REORG_DEPTH=100` (1286 — wrong value),
  `disconnect_to` (1300-1480), `try_attach_and_reorg` (1495-1849),
  `submit_block` (4331-4622), `invalidate_block` (~5476), `reconsider_block`
  (~5889), `dumptxoutset rollback` log line (9193 — comment-as-confession).
- `rustoshi/src/main.rs` — header-arrival handler (2544-2750),
  validation_interval block-acceptance loop (2327-2495), snapshot
  activation (1838-1900).

**Bitcoin Core references:**
- `bitcoin-core/src/validation.cpp`:
  - `ProcessNewBlockHeaders` (4242-4270) — for-loop over headers, each
    calls `AcceptBlockHeader`; `NotifyHeaderTip()` fires on `m_best_header`
    advancement.
  - `ActivateBestChain` (3323-3488) — outer loop releasing `cs_main`
    between iterations.
  - `ActivateBestChainStep` (3191-3274) — disconnect-then-connect with
    32-block chunking (`nTargetHeight = nHeight + 32`).
  - `FindMostWorkChain` (3114-3171) — pops max from
    `setBlockIndexCandidates`, walks back skipping `BLOCK_FAILED_VALID` /
    missing-`HAVE_DATA` ancestors.
  - `ConnectTip` (3005-3110) — reads block, calls `ConnectBlock`,
    `m_chain.SetTip`, fires `BlockConnected` signal.
  - `DisconnectTip` (2929-2992) — reads block, calls `DisconnectBlock`,
    saves disconnected txs to `DisconnectedBlockTransactions`,
    `m_chain.SetTip(pprev)`, fires `BlockDisconnected` signal.
  - `fTooFarAhead` (4325) — `pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP`
    where `MIN_BLOCKS_TO_KEEP = 288` (validation.h:76).
  - `InvalidateBlock` (3521-3697) — descendant marking with
    `BLOCK_FAILED_VALID`.
- `bitcoin-core/src/chain.h`:
  - `BLOCK_VALID_*` (42-86) — ordinal levels 1..5 stored in the low 3 bits
    + flag bits (8=HAVE_DATA, 16=HAVE_UNDO, 32=FAILED_VALID, 64=FAILED_CHILD,
    128=OPT_WITNESS, 256=STATUS_RESERVED).
  - `BLOCK_VALID_MASK = 1|2|3|4|5 = 7` (72-73) — the ordinal mask.
  - `CBlockIndex::IsValid(nUpTo)` (254-258) — checks
    `(nStatus & BLOCK_VALID_MASK) >= nUpTo`, NOT a bitwise test.
  - `CBlockIndex::RaiseValidity(nUpTo)` (265-271) — monotonic state
    transition: `nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo` if
    new level exceeds the current.
  - `nSequenceId` (149) — insertion-order sequence used as primary
    tiebreak.
  - `m_chain_tx_count` (125-129) — cumulative tx count populated at
    VALID_TRANSACTIONS.
  - `nTimeMax` (152) — max timestamp of self + ancestors.
- `bitcoin-core/src/node/blockstorage.cpp`:
  - `CBlockIndexWorkComparator::operator()` (around line 19) — tiebreak
    order: chainwork DESC → nSequenceId ASC → pointer address ASC.

**BIPs / specs covered:** BIP-30 (duplicate coinbase, on disconnect side),
BIP-34 (BIP-34 height activation tightens header acceptance), BIP-113
(MTP-as-locktime / parent-MTP gating), BIP-130 (sendheaders),
[BIP-300 reorg-depth conventions, informal].

**Production code changes:** 0 (pure audit).

## Why this matters

Headers-first sync + chain selection + reorg is the **outer control
loop** of every Bitcoin full node. A bug at this layer means:

1. **Silent chain split** — node accepts/rejects blocks Core would not,
   diverging at a difficulty retarget or invalid-block boundary.
2. **Wedge / livelock** — node refuses to advance past a side-branch
   it should have switched to (W101 G1-G5 pattern: earlier higher-work
   chain in disk, no `setBlockIndexCandidates` reconsideration).
3. **DoS** — peer pushes a long invalid header chain; the node
   stores all headers without bounding chain-work or commitment
   verification, OOMing.
4. **Persistent corruption** — partial reorg leaves the on-disk UTXO
   set inconsistent with the tip pointer; restart pulls a non-valid
   tip from `best-block` meta and silently advances onto it.

Three failure modes recur in rustoshi and all three are fleet
patterns documented in MEMORY.md:

1. **Two-pipeline guard.** `chain_state::process_block`,
   `try_attach_and_reorg` (rpc/server.rs:1495), and the
   `validation_interval` IBD loop (main.rs:2327) are three independent
   block-acceptance pipelines, each writing the tip + UTXO + block-index
   + tx-index in slightly different orders. submit_block's non-atomic
   path (4407-4544) writes header, block, height-index, undo, block-index,
   tx-index, UTXO, then best-block pointer as **separate `put_*` calls**,
   while the IBD loop writes via a different code path (main.rs:2339-2434)
   and `try_attach_and_reorg` is the only one that uses a single
   `WriteBatch`. The atomicity guarantee Pattern D was meant to fix is
   only present in the reorg path.

2. **Dead module.** `chain_manager::ChainManagerState` exists (lines 83-137,
   tracks `nSequenceId`-style sequence counters for `preciousblock`) but
   `compare_chain_work_with_tiebreak` (lines 165-180) uses **block hash**
   as the tiebreak, not `nSequenceId` from `ChainManagerState`. The
   sequence-counter state is wired but never consulted in the comparator
   that would use it. (See BUG-9.)

3. **Comment-as-confession.** `dumptxoutset rollback`'s failure log
   (server.rs:9193) literally says *"restart node to recover via
   ActivateBestChain"* — but rustoshi has **NO** `ActivateBestChain`
   function. The restart recovery path does not exist; on restart the
   chain loads the last-flushed tip pointer and proceeds from there
   with no candidate-set re-evaluation. (See BUG-1.)

## Audit framework (30 gates / 24 BUGS catalogued)

Gate legend:
- **PASS** — behaviour matches Core (regression pin).
- **BUG-N** — divergence, gap, or arithmetic-safety hazard.

| #   | Behaviour                                                                                       | Status |
|-----|--------------------------------------------------------------------------------------------------|--------|
| G1  | `ActivateBestChain` exists as the outer control loop                                             | BUG-1 (missing) |
| G2  | `setBlockIndexCandidates` sorted candidate set exists                                            | BUG-2 (missing) |
| G3  | `FindMostWorkChain` scans candidates skipping FAILED/missing-DATA ancestors                       | BUG-3 (missing) |
| G4  | `ConnectTip` extracted as a discrete primitive (vs inline `process_block`)                       | BUG-4 (inline-only) |
| G5  | `DisconnectTip` extracted as a discrete primitive (vs inline `reorganize`)                       | BUG-5 (inline-only) |
| G6  | `MAX_REORG_DEPTH` matches Core's effective `MIN_BLOCKS_TO_KEEP=288`                              | BUG-6 (set to 100) |
| G7  | `BlockStatus::VALID_*` are ordinal levels stored in the low 3 bits (Core layout)                 | BUG-7 (used as bitflags) |
| G8  | `IsValid(nUpTo)` uses `(nStatus & MASK) >= nUpTo`, not bitwise `has(flag)`                       | BUG-8 (W109 G21 cross-cite) |
| G9  | `RaiseValidity(nUpTo)` is monotonic + replaces the ordinal in low bits                           | BUG-9 (`set` is unconditional OR; cross-cite W109 G22) |
| G10 | Chain candidates tie-broken by `nSequenceId` (Core), not block hash                              | BUG-10 (hash-based tiebreak) |
| G11 | `m_chain_tx_count` (nChainTx) cumulative counter on `BlockIndexEntry`                            | BUG-11 (absent; cross-cite W109 G10) |
| G12 | `nTimeMax` (max-timestamp-self-and-ancestors) on `BlockIndexEntry`                               | BUG-12 (absent) |
| G13 | `accept_block_header_chain_work` invoked from production header path                             | BUG-13 (dead code; cross-cite W97 G7) |
| G14 | `contextual_check_block_header` (full BIP-113 + version-bits) invoked from header path           | BUG-14 (dead code; cross-cite W97 G7) |
| G15 | `BlockIndexEntry` is persisted at HEADER-acceptance time (Core's `AcceptBlockHeader`)            | BUG-15 (only persisted post-validation; cross-cite W109 G3) |
| G16 | `m_best_header` pointer distinct from chain tip, advanced on header arrival                       | PASS (`header_sync::best_header_height`) |
| G17 | `ProcessNewBlockHeaders` runs PoW + MTP **before** block download begins                         | PASS (header_sync.rs:334 + main.rs:2581) |
| G18 | Headers-first downloads release the main lock between iterations (Core `cs_main` chunking)       | BUG-16 (cross-cite W101 G13) |
| G19 | `fInvalidFound` retry loop falls back to next-best chain on ConnectBlock failure                 | BUG-17 (cross-cite W101 G10) |
| G20 | `InvalidateBlock` marks descendants `BLOCK_FAILED_VALID` (not `BLOCK_FAILED_CHILD`)              | PASS (W101 G17 was fixed) |
| G21 | `setBlockIndexCandidates.erase(invalidated)` keeps candidate set consistent                       | BUG-18 (no candidate set; cross-cite W101 G18) |
| G22 | `MaybeUpdateMempoolForReorg` / `removeForReorg` runs post-reorg                                  | BUG-19 (cross-cite W101 G15) |
| G23 | `BlockConnected` / `BlockDisconnected` signals fire AFTER `cs_main` released                     | BUG-20 (no ValidationInterface; cross-cite W101 G14) |
| G24 | `MAX_DISCONNECTED_TX_POOL_BYTES` cap on disconnect-pool RAM during reorg                         | BUG-21 (cap absent) |
| G25 | Reorg walk uses skip-pointer (`pskip`) for O(log n) ancestor traversal                            | BUG-22 (linear walk via `prev_hash`; cross-cite W109 G4/G7) |
| G26 | Headers-first PRESYNC writes nothing to disk (memory-only commitments)                            | PASS (headers_presync.rs design) |
| G27 | After REDOWNLOAD the headers-presync-anchored chain-work is enforced via `accept_block_header_chain_work` | BUG-13 |
| G28 | `BLOCK_OPT_WITNESS=128` / `BLOCK_STATUS_RESERVED=256` flags present                              | BUG-23 (absent) |
| G29 | Disconnect-tip block-data persisted (so re-connect / re-validate works on reorg-back)            | PASS (try_attach_and_reorg keeps blocks/undo on disk) |
| G30 | `submit_block` path is atomic-on-disk (single `WriteBatch` for header+block+UTXO+tip)            | BUG-24 (8 separate non-atomic writes) |

Additional findings outside the gate matrix:
- **Hash byte-order check:** All locator + chain-walk code paths use
  `prev_block_hash` consistently. No byte-order divergence detected.
- **`HaveNumChainTxs` equivalent absent.** Core's `FindMostWorkChain`
  asserts `pindexTest->HaveNumChainTxs() || pindexTest->nHeight == 0`;
  rustoshi has no `n_chain_tx` counter so a missing-data candidate is
  not even detectable at the candidate-set level.

## BUGS

### BUG-1 — No `ActivateBestChain` function; chain advancement is split across three independent pipelines, none of which can re-evaluate side-branches after the tip changes

**Severity:** P0-CDIV
**File:** `rustoshi/src/main.rs:2327-2495` (validation_interval loop);
`crates/rpc/src/server.rs:1495-1849` (`try_attach_and_reorg`);
`crates/rpc/src/server.rs:4404-4577` (submit_block direct-connect path).
**Core ref:** `bitcoin-core/src/validation.cpp:3323-3488` —
`Chainstate::ActivateBestChain` is the **single** outer loop that
re-runs `FindMostWorkChain` each iteration, advancing the tip until no
better candidate exists. It releases `cs_main` between iterations so
RPC / P2P / wallet threads can make progress.

**Description:**
rustoshi has no `ActivateBestChain`. Block acceptance flows through
three pipelines, each with its own bespoke tip-advance code:

1. **IBD downloader (`main.rs:2327`)** — `validation_interval.tick()`
   pops a block from `block_downloader.next_block_to_validate()`,
   calls `chain_state.process_block`, writes block-index entry +
   tx-index + height-index + UTXO + tip pointer **non-atomically**
   (separate `put_*` calls).
2. **`submit_block` RPC (`server.rs:4404`)** — calls
   `chain_state.process_block` for the parent-is-tip case, falls back
   to `try_attach_and_reorg` on `PrevBlockNotFound`. Writes 8 separate
   keys non-atomically.
3. **`try_attach_and_reorg` (`server.rs:1495`)** — the only path that
   uses a single `WriteBatch`. Re-runs `ChainState::reorganize` to
   advance onto the side-branch.

None of these paths re-evaluates blocks **already on disk** when the
tip changes. If a higher-work side-branch was submitted earlier (and
its blocks are on disk), then the active tip later changed, the
side-branch is **never reconsidered for activation** unless the user
calls `reconsiderblock` or re-submits the side-branch tip. W101 G1-G5
documents this as MISSING SUBSYSTEM (`setBlockIndexCandidates` absent).

**Excerpt — three pipelines doing the same job:**
```rust
// main.rs:2363 — IBD downloader
match cs.process_block(&block, &mut utxo_view, prev_block_mtp, true) {
    Ok((undo, _fees)) => Some(undo),
    Err(e) => { tracing::warn!(...); None }
}

// server.rs:4404 — submitblock direct path
match chain_state.process_block(&block, &mut utxo_view, prev_block_mtp, false) {
    Ok((undo_data, _fees)) => { ... 8 separate put_* calls ... }
    Err(PrevBlockNotFound(_)) => try_attach_and_reorg(...),
    Err(e) => Ok(Some(e.bip22_string())),
}

// server.rs:1670 — try_attach_and_reorg (the only batched path)
chain_state.reorganize(*block_hash, &get_block, &get_undo, ...)?;
// ... build batch, write_batch atomically ...
```

**Impact:**
Three-pipeline guard fleet pattern. A new code path that should
trigger `ActivateBestChain` (e.g. `reconsiderblock`) silently no-ops
because rustoshi has nowhere to centrally call. The
"restart node to recover via ActivateBestChain" log message in
`dumptxoutset rollback` (server.rs:9193) refers to a function that
doesn't exist — on restart, the tip is reloaded from the on-disk
`best_block` meta and chain advancement resumes via the IBD downloader,
which has no candidate-set logic.

---

### BUG-2 — `setBlockIndexCandidates` sorted candidate set absent; earlier-submitted higher-work side branches never become activation candidates

**Severity:** P0-CDIV
**File:** Nowhere (missing data structure).
**Core ref:** `bitcoin-core/src/validation.h:683` —
`std::set<CBlockIndex*, node::CBlockIndexWorkComparator> setBlockIndexCandidates;`
populated by `AcceptBlockHeader` + `AcceptBlock`; consumed by
`FindMostWorkChain`.

**Description:**
Cross-cite W101 G1-G5. rustoshi has no in-memory candidate set. The
only candidate-set-equivalent state is implicit: the on-disk
`BlockIndexEntry` for each block, with `chain_work` recorded. To find
the best candidate, rustoshi would need to scan every entry in the
block index — a full DB scan — which is never done.

`try_attach_and_reorg` compares **only the single just-submitted block's
chainwork against the current tip**. A side-branch B3 (work=3) that
was submitted before A2 (work=2, current tip) is on disk with
`HAVE_DATA` + correct `chain_work`, but it is never re-evaluated as
a tip candidate when A2 fails or is invalidated.

**Excerpt:**
```rust
// server.rs:1565 — try_attach_and_reorg
if !rustoshi_consensus::chain_manager::compare_chain_work(&this_work.0, &tip_work_bytes)
    .is_gt()
{
    return Ok(false);   // only the JUST-submitted block is compared
}
```

**Impact:**
CONSENSUS-DIVERGENT. A peer or RPC caller who submits a heavier
side-branch before knowing about the lighter active tip can lose to
the lighter chain. Pattern Y bug (see comments at server.rs:4443
referencing the 2026-05-05 closure). The current closure landed only
the storage-side fix; the candidate-set re-evaluation is still absent.

---

### BUG-3 — `FindMostWorkChain` function absent; no logic for skipping FAILED-or-missing-DATA ancestors during chain selection

**Severity:** P0-CDIV
**File:** Nowhere (missing function).
**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171` —
`FindMostWorkChain` walks back from a candidate tip and, if any
ancestor has `BLOCK_FAILED_VALID` or lacks `BLOCK_HAVE_DATA`, marks
the entire chain as ineligible (sets `BLOCK_FAILED_VALID` on every
descendant) and **continues the do-while loop to try the next-best
candidate**.

**Description:**
Without `FindMostWorkChain`, rustoshi has no way to express *"this
candidate is the best, but its parent is FAILED, so try the next
candidate"*. The closest substitute is `try_attach_and_reorg`, which
compares only one block at a time. The result: if rustoshi rejects
a block via `ConnectBlock` (sets FAILED_VALIDITY), the candidate
status of descendants is never re-evaluated, so the next side-branch
submission may not be considered.

**Excerpt — Core's retry loop:**
```cpp
// bitcoin-core/src/validation.cpp:3117
do {
    CBlockIndex *pindexNew = nullptr;
    {
        std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
        if (it == setBlockIndexCandidates.rend()) return nullptr;
        pindexNew = *it;
    }

    CBlockIndex *pindexTest = pindexNew;
    bool fInvalidAncestor = false;
    while (pindexTest && !m_chain.Contains(pindexTest)) {
        bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_VALID;
        bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
        if (fFailedChain || fMissingData) {
            // ... mark the whole chain ineligible, remove from candidates ...
            fInvalidAncestor = true;
            break;
        }
        pindexTest = pindexTest->pprev;
    }
    if (!fInvalidAncestor) return pindexNew;
} while(true);
```

**Impact:**
A side-branch with one FAILED block in the middle of its history
cannot be activated, but rustoshi never even tries the next-best
candidate (cross-cite BUG-2). Combined with BUG-17 (`fInvalidFound`
retry absent), rustoshi will sit on the active tip even when a
clean alternative exists on disk.

---

### BUG-4 — `ConnectTip` is not a discrete primitive; block-connection logic is interleaved with index-write + UTXO-flush + tx-index + best-block bookkeeping across `chain_state::process_block`, `submit_block`, `validation_interval`, and `try_attach_and_reorg`

**Severity:** P1
**File:** `crates/consensus/src/chain_state.rs:395-533` (`process_block`),
`crates/rpc/src/server.rs:4404-4577` (`submit_block`),
`rustoshi/src/main.rs:2353-2455` (IBD loop).
**Core ref:** `bitcoin-core/src/validation.cpp:3005-3110` —
`Chainstate::ConnectTip` is a single function that reads the block,
calls `ConnectBlock`, flushes the view, advances `m_chain`, and
fires `BlockConnected`. It is the ONLY tip-advance primitive.

**Description:**
rustoshi's `process_block` (chain_state.rs:395) advances `tip_hash` +
`tip_height`, but does NOT:
- write the `BlockIndexEntry` (each caller does this separately
  with slightly different code — see main.rs:2391, server.rs:4474,
  server.rs:1544);
- write the tx-index entries (separate code at main.rs:2413,
  server.rs:4517, server.rs:1758);
- write the block-filter index (only main.rs:2417);
- fire `BlockConnected` (no ValidationInterface);
- flush state to disk (no `FlushStateToDisk`).

The lack of a single `connect_tip` primitive means new pipelines (e.g.
a future `processNewBlock` RPC or test harness) must each re-derive
the correct ordering of writes, which is fragile and is what
Pattern D fleet-wide closure (2026-05-07) had to retro-fit only
in `try_attach_and_reorg`.

**Impact:**
Maintenance / correctness hazard. Adding a new write side-effect
(e.g. ZMQ `hashblock` notify, address index, BIP-157 cfheaders)
requires editing **three** call sites in lock-step. W121 BUG-16
landed only on `validation_interval` (main.rs:2417), so the
`submit_block` path **does not populate the block-filter index** for
RPC-submitted blocks — a gap surfaced by the cross-cite.

---

### BUG-5 — `DisconnectTip` not a discrete primitive; disconnect logic is split between `ChainState::disconnect_block`, `ChainState::reorganize`, and `rpc::disconnect_to`

**Severity:** P1
**File:** `crates/consensus/src/chain_state.rs:740-795`
(`disconnect_block`); 627-655 (in-loop disconnect inside `reorganize`);
`crates/rpc/src/server.rs:1300-1480` (`disconnect_to`).
**Core ref:** `bitcoin-core/src/validation.cpp:2929-2992` —
`Chainstate::DisconnectTip`: read block, `DisconnectBlock`, set
`m_chain.SetTip(pprev)`, add disconnected txs to `disconnectpool`,
fire `BlockDisconnected`.

**Description:**
Three disconnect paths:
1. `chain_state.rs:740-795` (the standalone wrapper): used by
   `invalidate_block` test code, but **NOT** called from
   `try_attach_and_reorg`.
2. `chain_state.rs:627-655` (inline inside `reorganize`): the one
   actually used by reorgs.
3. `server.rs:1300-1480` (`disconnect_to`, used by `invalidateblock`
   RPC + dumptxoutset rollback): a third copy with its own batching.

Each enforces the `MAX_REORG_DEPTH` cap differently (BUG-6 below).
Each handles `DisconnectResult::Unclean` differently (chain_state.rs:644
warns; server.rs:1300+ has its own variant). None fires a
`BlockDisconnected` notification.

**Impact:**
Same fleet pattern as BUG-4. Triple-pipeline guard. A change to
disconnect semantics (e.g. mempool refill, prune-lock rewind) must
touch three call sites or risk divergence between
"disconnect from invalidateblock" vs "disconnect during reorg".

---

### BUG-6 — `MAX_REORG_DEPTH = 100` diverges from Core's effective `MIN_BLOCKS_TO_KEEP = 288`; reorgs of depth 101-288 are silently refused

**Severity:** P0-CDIV
**File:** `crates/rpc/src/server.rs:1286`
**Core ref:** `bitcoin-core/src/validation.h:75-76` —
`static const unsigned int MIN_BLOCKS_TO_KEEP = 288;`. Core does not
have a `MAX_REORG_DEPTH` constant per se; the closest analog is the
`fTooFarAhead` check at `validation.cpp:4325` using
`MIN_BLOCKS_TO_KEEP`. Pruned nodes refuse to disconnect below
`tip - MIN_BLOCKS_TO_KEEP`; an unpruned node has no hard reorg-depth
cap.

**Description:**
rustoshi caps reorg depth at 100 in BOTH `disconnect_to`
(server.rs:1322) and `try_attach_and_reorg` (server.rs:1662). The
comment at server.rs:1273-1287 explains the cap is "to keep the
in-memory `WriteBatch` bounded". The cap matches the `MIN_BLOCKS_TO_KEEP`
constant **in spirit** but at the wrong value (100 vs 288), so any
reorg between depth 101 and 288 is refused on rustoshi while Core
accepts it.

**Excerpt:**
```rust
// server.rs:1286
pub const MAX_REORG_DEPTH: u32 = 100;

// server.rs:1322
if depth > MAX_REORG_DEPTH {
    return Err(format!(
        "disconnect_to depth {} exceeds MAX_REORG_DEPTH ({}); refusing \
         non-atomic fallback",
        depth, MAX_REORG_DEPTH
    ));
}
```

vs Core (validation.h:76):
```cpp
static const unsigned int MIN_BLOCKS_TO_KEEP = 288;
// no MAX_REORG_DEPTH constant — only the fTooFarAhead anti-DoS check
```

**Impact:**
On a real-world deep reorg (testnet4 had a 312-block reorg episode
2024-09; signet had a similar event 2025-Q1), rustoshi would refuse
to follow the heavier chain while Core would accept it. This is a
**CONSENSUS-DIVERGENT** split at any reorg depth in 101..288. The
test at `crates/consensus/tests/w101_activate_best_chain_gates.rs:867`
hardcodes `EXPECTED_MAX_REORG_DEPTH = 100` and asserts equality with
the production constant — the test PASSES but pins the **wrong**
value.

**Fix:** one-line, change to 288 + update the W101 test's expected
value:
```rust
pub const MAX_REORG_DEPTH: u32 = 288;
```

---

### BUG-7 — `BlockStatus::VALID_HEADER=1`, `VALID_TREE=2`, `VALID_TRANSACTIONS=3`, `VALID_CHAIN=4`, `VALID_SCRIPTS=5` are used as bit-flags via `self.0 |= flag`; setting `VALID_SCRIPTS` (=5=0b101) makes `has(VALID_HEADER=1)` return true even though no VALID_HEADER level was reached

**Severity:** P0-CDIV
**File:** `crates/storage/src/block_store.rs:21-75`
**Core ref:** `bitcoin-core/src/chain.h:42-86`. The Core values 1..5
are ordinal LEVELS stored in the low 3 bits + flag bits (8=HAVE_DATA,
16=HAVE_UNDO, 32=FAILED_VALID, 64=FAILED_CHILD, 128=OPT_WITNESS,
256=STATUS_RESERVED). `BLOCK_VALID_MASK = 1|2|3|4|5 = 7`
(the mask of the low 3 bits). Validity is queried via `IsValid(nUpTo)`
which does `(nStatus & BLOCK_VALID_MASK) >= nUpTo`.

**Description:**
rustoshi treats these constants as independent bit-flags using
`self.0 |= flag` (block_store.rs:63) and `self.0 & flag != 0`
(line 58). This is mathematically wrong:
- VALID_HEADER (=1, bit 0) and VALID_TREE (=2, bit 1) happen to be
  non-overlapping bits, so OR-ing them gives 3 — but 3 is also
  VALID_TRANSACTIONS, so `has(VALID_TRANSACTIONS)` returns true after
  just setting VALID_HEADER+VALID_TREE without ever reaching the
  TRANSACTIONS level.
- VALID_CHAIN=4 and VALID_SCRIPTS=5: setting VALID_SCRIPTS gives
  `status=5=0b101`. Now `has(VALID_HEADER=1)` returns true (5&1=1≠0),
  `has(VALID_TREE=2)` returns false (5&2=0), `has(VALID_TRANSACTIONS=3)`
  returns true (5&3=1≠0), `has(VALID_CHAIN=4)` returns true (5&4=4≠0).
  So a block that has VALID_SCRIPTS appears to also be at VALID_HEADER,
  VALID_TRANSACTIONS, and VALID_CHAIN — that's actually correct (it
  implies all lower levels) but the encoding is accidental and only
  works for 1+8-style flag bits, not for the 3 vs 4 vs 5 case.
- The real divergence: after setting VALID_HEADER (=1=0b001) and later
  RaiseValidity(VALID_TREE=2=0b010), Core would replace the low 3 bits
  with 2 (giving 0b010 + any other flag bits); rustoshi OR-s, giving
  0b011=3 which silently equals VALID_TRANSACTIONS.

**Excerpt:**
```rust
// block_store.rs:25-75
pub const VALID_HEADER: u32 = 1;
pub const VALID_TREE: u32 = 2;
pub const VALID_TRANSACTIONS: u32 = 3;   // !!! 3 = 1|2; would collide
pub const VALID_CHAIN: u32 = 4;
pub const VALID_SCRIPTS: u32 = 5;        // !!! 5 = 1|4; would collide
pub const HAVE_DATA: u32 = 8;
// ...
pub fn has(&self, flag: u32) -> bool {
    self.0 & flag != 0     // BUG: should be (self.0 & MASK) >= flag for VALID_*
}
pub fn set(&mut self, flag: u32) {
    self.0 |= flag         // BUG: should be (self.0 & !MASK) | flag for VALID_*
}
```

vs Core (chain.h:265-271):
```cpp
bool RaiseValidity(enum BlockStatus nUpTo) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    assert(!(nUpTo & ~BLOCK_VALID_MASK));   // Only validity flags allowed.
    if (nStatus & BLOCK_FAILED_VALID) return false;
    if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
        nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
        return true;
    }
    return false;
}
```

**Impact:**
This is W109 G21+G22 cross-cite + a P0-CDIV. The current usage in
rustoshi gets away with this only because the only validity level
actually written in production is VALID_SCRIPTS (=5), via
`status.set(BlockStatus::VALID_SCRIPTS)` (main.rs:2392, server.rs:4475,
server.rs:1545, etc.). If anyone ever writes VALID_TREE then later
attempts VALID_TRANSACTIONS via `set`, the OR-mask produces silently
wrong status. The validity ladder is also not enforced — there's no
`raise_validity` method that prevents demotion.

**Fix:** factor a real `validity_level()` accessor that returns
`self.0 & 0b111` and compares against the ordinal; change `set` for
VALID_* to clear-and-set the low 3 bits.

---

### BUG-8 — `is_valid_up_to(nUpTo)` accessor absent; downstream code uses `has(BlockStatus::VALID_X)` as a single-flag test, never reaching the Core "validity >= level" semantics

**Severity:** P1
**File:** `crates/storage/src/block_store.rs:57`
**Core ref:** `bitcoin-core/src/chain.h:254-258` —
`IsValid(enum BlockStatus nUpTo)` returns
`((nStatus & BLOCK_VALID_MASK) >= nUpTo)`.

**Description:**
Cross-cite W109 G21. The single most important validity accessor
in Core is `IsValid(nUpTo)`. rustoshi has none. Downstream code at
`server.rs:8598`, `chain_manager::has_valid_transactions` (line 72),
and `find_descendants` consults `status.has(...)` which returns true
on bit-overlap, not "validity level >= X".

**Impact:**
Combined with BUG-7, validity gating throughout rustoshi is on
**bit-overlap** semantics, not "validity ladder reached". A block
with VALID_SCRIPTS set claims to be at VALID_HEADER too (correct by
accident), but a block with only VALID_TREE set fails `has(VALID_HEADER=1)`
(returns false, 2&1=0). This is the exact inverse of Core's "higher
level implies lower" guarantee.

---

### BUG-9 — `compare_chain_work_with_tiebreak` tiebreaks by block hash (lexicographic), not by `nSequenceId` (insertion order). `ChainManagerState` tracks sequence IDs (precious) but the comparator never consults them.

**Severity:** P1
**File:** `crates/consensus/src/chain_manager.rs:165-180`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:19` —
`CBlockIndexWorkComparator::operator()`:
```cpp
if (pa->nChainWork > pb->nChainWork) return false;
if (pa->nChainWork < pb->nChainWork) return true;
if (pa->nSequenceId < pb->nSequenceId) return false;  // ← earliest wins
if (pa->nSequenceId > pb->nSequenceId) return true;
if (pa < pb) return false;   // pointer-address fallback
if (pa > pb) return true;
return false;
```

**Description:**
rustoshi's comparator (chain_manager.rs:165-180) compares chainwork
first (correct), then tiebreaks by **block hash** — lower hash wins.
Comment at line 162 says *"Core uses `nSequenceId` then pointer address;
rustoshi has no live block index object to compare pointers, so the
block hash — which is a stable persistent identifier — provides an
equivalent deterministic tiebreak."*

But `ChainManagerState::sequence_ids` (line 94) DOES track sequence
IDs — assigned by `assign_precious_sequence` (line 115). The
comparator could and should consult this map for `nSequenceId`
parity, but doesn't.

**Excerpt:**
```rust
// chain_manager.rs:165-180
pub fn compare_chain_work_with_tiebreak(
    work_a: &[u8; 32],
    hash_a: &Hash256,
    work_b: &[u8; 32],
    hash_b: &Hash256,
) -> std::cmp::Ordering {
    let cmp = compare_chain_work(work_a, work_b);
    if cmp != std::cmp::Ordering::Equal {
        return cmp;
    }
    // Tiebreak: lower hash value wins (lexicographic, ascending — deterministic).
    hash_b.0.cmp(&hash_a.0)
}
```

vs Core: earliest insertion-order wins.

**Impact:**
CONSENSUS-DIVERGENT in the tiebreak case. An attacker who builds
two same-work chains can engineer which one rustoshi prefers (the
lower-hash one) while Core prefers whichever was seen first. In
practice equal-work tiebreaks are rare but `preciousblock` exists
specifically to manipulate them; the rustoshi semantics make
`preciousblock` ineffective when a competing block has a lower hash.

The dead `ChainManagerState::sequence_ids` HashMap is a fleet
"plumb-but-don't-flip" pattern: the state exists, the assignment
function exists, but the consumer never reads it.

---

### BUG-10 — `BlockIndexEntry.n_tx` is per-block but no `m_chain_tx_count` cumulative counter exists; IBD progress and `getblockheader.chainwork`/`nTx` divergence

**Severity:** P2
**File:** `crates/storage/src/block_store.rs:86-105`
**Core ref:** `bitcoin-core/src/chain.h:125-129` —
`uint64_t m_chain_tx_count{0}; //! cumulative tx count, populated at VALID_TRANSACTIONS`.
`bitcoin-core/src/chain.h:121-123` — `unsigned int nTx{0}; //! per-block`.

**Description:**
Cross-cite W109 G10. `BlockIndexEntry` has `n_tx` (per-block count)
but no `chain_tx_count` cumulative field. Core uses
`m_chain_tx_count` for:
1. IBD progress estimation (`GuessVerificationProgress`).
2. `getblockchaininfo.txcount`.
3. `getblockheader.nTx`-equivalent fields surfacing cumulative
   counts post-assumeUTXO.

W138 assumeUTXO audit (W138 BUG-2) flagged that rustoshi fabricates
testnet4 h=290000 chain-tx-count. Without `m_chain_tx_count`
tracked at acceptance time, IBD progress reporting is degraded
and the assumeutxo snapshot whitelist's `chain_tx_count` field is
essentially dead weight (used at snapshot load but never compared
against accumulating state).

**Impact:**
P2 — observability + correctness gap. `getblockchaininfo.txcount`
either returns 0 or scans the entire `tx_index` CF on each call (DB
walk). Combined with BUG-15, the only way to get accurate
cumulative tx counts is full-chain re-scan.

---

### BUG-11 — `BlockIndexEntry.timestamp` per-block but no `nTimeMax` (max-self-and-ancestors) field; `getblockstats.maxtime` and BIP-94 timewarp future-protection diverge from Core

**Severity:** P2
**File:** `crates/storage/src/block_store.rs:86-105`
**Core ref:** `bitcoin-core/src/chain.h:152` —
`unsigned int nTimeMax{0}; //!< max time this block or any predecessor`.

**Description:**
Cross-cite W109 G10. Core maintains `nTimeMax` = max(self.nTime,
prev.nTimeMax). Used:
1. `getblockstats.maxtime` returns this directly.
2. `CBlockIndex::GetBlockTimeMax()` (chain.h:226-229).
3. BIP-94 (testnet4) timewarp future-protection cross-cite
   (testnet4 nTimeMax bound on retarget).

rustoshi has `BlockIndexEntry.timestamp` (per-block) but no
`time_max`. The functional gap is small (RPC observability),
but the BIP-94 testnet4 nTimeMax interaction is what rustoshi
explicitly wires elsewhere — see `crates/consensus/src/pow.rs` for
BIP-94 difficulty, which uses prev.timestamp not prev.time_max.

**Impact:**
P2 — RPC field divergence; testnet4 BIP-94 nTimeMax-based difficulty
adjustment would need `nTimeMax` if the consensus rule is ever
extended.

---

### BUG-12 — `accept_block_header_chain_work` exists as a public function but is **never called** from the production header-acceptance path

**Severity:** P0
**File:** `crates/consensus/src/validation.rs:1018-1039`
**Core ref:** `bitcoin-core/src/validation.cpp:4225-4232` —
`AcceptBlockHeader`:
```cpp
if (!min_pow_checked) {
    if (pindex->nChainWork < MinimumChainWork()) {
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
    }
}
```

**Description:**
The function `accept_block_header_chain_work` is exposed from
`rustoshi_consensus::lib` (line 60) and is the canonical Core-parity
helper for the chainwork-vs-minimum gate (G8 in W97/W109). But:

1. It is NEVER called from `header_sync::process_headers`
   (header_sync.rs:250-372).
2. It is NEVER called from `headers_presync` (which has its own
   parallel chainwork accounting).
3. It is NEVER called from `main.rs`'s header arrival handler
   (main.rs:2544-2750).

Confirmed via grep: only callers are
`crates/storage/src/w109_block_index_gates.rs:713` (a test) and
`crates/consensus/tests/w97_accept_block_gates.rs:253` (also a test).

**Impact:**
P0 — DoS gate is dead code. An attacker can serve a long chain of
header packets whose accumulated chainwork is below
`params.minimum_chain_work`; rustoshi will store every one to disk
via `put_header` + `put_height_index`, OOMing the disk while Core
would reject after the first packet without storage.

The headers_presync path DOES enforce a chainwork minimum (via
its own logic at headers_presync.rs:949-974), but ONLY in
PRESYNC+REDOWNLOAD mode. Once the node is past initial PRESYNC,
incoming `Headers` messages flow through `header_sync::process_headers`
without the gate.

---

### BUG-13 — `contextual_check_block_header` (full BIP-113 MTP + BIP-9 version-bits + BIP-94 timewarp gate) is exported but **not wired into the production header pipeline**; only an inline MTP check at main.rs:2581 fires

**Severity:** P0-CDIV
**File:** `crates/consensus/src/validation.rs` (function defined,
re-exported in `lib.rs:62`), inline replacement at
`rustoshi/src/main.rs:2557-2598`.
**Core ref:** `bitcoin-core/src/validation.cpp:4081-4100` —
`ContextualCheckBlockHeader` runs BIP-9 version-bits enforcement,
BIP-65/66/112 strict-DER, BIP-94 timewarp.

**Description:**
Cross-cite W97 G7. main.rs:2557-2598 inlines BIP-113 MTP and
MAX_FUTURE_BLOCK_TIME (7200s) checks DIRECTLY in the
`validate_and_store` closure passed to `process_headers`. But:

- The version-bits BIP-9 gate (`bad-version(version=...)`-style
  rejections per BIP-9 activated deployments) is absent.
- BIP-94 testnet4 timewarp inter-block timestamp constraints
  (only fired on the first block of a retarget window) are absent
  for the header path. (The `pow.rs::get_next_work_required` path
  does enforce it for difficulty calc, but the header acceptance
  itself does not reject a header that violates BIP-94's first-block
  timewarp constraint at acceptance time.)

**Impact:**
A peer can serve headers whose `version` violates an active BIP-9
deployment (rare in practice — all current deployments are buried);
rustoshi accepts them. Without the wider header-context check,
the BIP-94 timewarp gate fires only later (at difficulty calculation
for the next retarget), so an attacker can pre-populate the header
tree with timewarp-invalid headers up to the next retarget
boundary, OOMing disk-headers.

---

### BUG-14 — `BlockIndexEntry` is persisted only **after full validation** (post-`process_block` success); headers received during sync write only `(header, height_index)` to disk, so chain_work is not persisted at header-acceptance time

**Severity:** P1
**File:** `rustoshi/src/main.rs:2592-2597` (headers path);
contrast with `rustoshi/src/main.rs:2391-2407` (validation path).
**Core ref:** `bitcoin-core/src/validation.cpp:4189-4210` —
`AcceptBlockHeader` writes a new `CBlockIndex` to `m_block_index`
**and sets `nChainWork`** at header-acceptance time, well before
any block download.

**Description:**
The header-arrival closure (main.rs:2557-2598) writes only:
- `block_store.put_header(&hash, header)` (line 2592)
- `block_store.put_height_index(height, &hash)` (line 2595)

It does NOT write a `BlockIndexEntry`. The chain_work for the
header chain is tracked only in the in-memory `HeaderSync::best_header_*`
fields — not persisted. On restart, the header tree's chainwork has
to be recomputed by walking all stored headers from genesis. The
locator at `header_sync.rs:159` walks the height-index lookup chain,
which works only because the heights are persisted, but does not
recover the chain_work field.

**Impact:**
Cross-cite W109 G3. A restart loses the in-memory `best_header_hash`
+ `best_header_height` distinction from chainstate tip. The
`block_index` write only happens AT full-block validation time
(main.rs:2394, server.rs:4478), so any side-branch header chain
arriving before its blocks have a "ghost" chain on disk
(headers + height-index) but no `BlockIndexEntry` to provide
chain_work or status — `try_attach_and_reorg`'s parent-lookup
at server.rs:1511 would fail with "parent ... not in block index"
even though the parent header is on disk.

---

### BUG-15 — `m_best_header` advances independently of validated tip (correct), but the gap is unbounded: an attacker can keep `best_header` 100k+ blocks ahead of the validated chain by serving headers without serving blocks

**Severity:** P2
**File:** `crates/network/src/header_sync.rs:392-395`
(`set_best_header`); main.rs:2618-2622 (RPC update).
**Core ref:** `bitcoin-core/src/net_processing.cpp` (block-download
deadline + stalling-peer eviction). Core caps the header-tip-vs-chain-tip
gap via the `m_block_in_flight` deadline machinery and stale-peer
disconnect at `nPowTargetSpacing * 60` seconds.

**Description:**
`BlockDownloader` (block_download.rs:24-56) has timeouts and stall
detection per-peer, but the **header-tip can advance arbitrarily**
during sync. main.rs:2693 floors `old_best` at
`chain_state.tip_height()` exactly to handle the wedge case, but the
header-tip itself has no upper-bound vs validated tip. A peer that
serves 2000-headers-per-message rapidly and then refuses to serve
blocks can push `best_header_height` 500k+ blocks ahead of
`tip_height` while the block downloader pipeline starves.

The closest gate is `MAX_RECEIVED_BLOCKS = 512` (block_download.rs:56),
which caps the OoO buffer, but not the header-tip span.

**Impact:**
P2 / soft-DoS. A malicious peer can inflate header storage to ~80 *
1M = 80MB of headers without ever serving the corresponding blocks.
Cross-cite headers_presync gating only catches this before MinChainWork
is reached; after that point the regular path has no equivalent gate.

---

### BUG-16 — `ActivateBestChainStep`'s 32-block chunking + cs_main release-between-iterations absent; deep reorgs (up to MAX_REORG_DEPTH=100) hold the RpcState write-lock for the entire reorg

**Severity:** P1
**File:** `crates/rpc/src/server.rs:1670-1849` (reorg builds the whole
batch under one write-lock); `crates/consensus/src/chain_state.rs:553-713`
(reorganize is a single function, no chunking).
**Core ref:** `bitcoin-core/src/validation.cpp:3224` —
`int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);`
— 32-block chunking inside `ActivateBestChainStep`'s while-loop, with
`cs_main` released between iterations.

**Description:**
Cross-cite W101 G13. rustoshi holds the `RpcState` write-lock for
the full reorg duration. There is no equivalent of Core's "release
cs_main between every 32 blocks". Combined with BUG-6 (cap=100), the
worst-case reorg blocks all RPC for 100*blocktime_validation_ms,
which on mainnet can be 30+ seconds.

**Impact:**
Soft-DoS — RPC is unavailable to other clients during deep reorgs.
Not a consensus issue, but a major UX divergence from Core.

---

### BUG-17 — `fInvalidFound` retry-to-next-best-chain absent: ConnectBlock failure during reorg returns `Err(ValidationError)` without ever attempting an alternative branch

**Severity:** P0-CDIV
**File:** `crates/consensus/src/chain_state.rs:697-704`
**Core ref:** `bitcoin-core/src/validation.cpp:3236-3252` — On
`ConnectTip` failure inside `ActivateBestChainStep`,
`fInvalidFound = true`; the outer `ActivateBestChain` loop
(validation.cpp:3392) then re-runs `FindMostWorkChain` to find an
alternative.

**Description:**
Cross-cite W101 G10. rustoshi's reorganize loop (chain_state.rs:662)
calls `connect_block_with_sequence_locks` and propagates the error
back. The caller `try_attach_and_reorg` (server.rs:1670-1678) maps
this to `Err(format!("reorganize: {}", e))?` and returns. No retry
loop.

**Excerpt:**
```rust
// chain_state.rs:697-704
let (_undo, _fees) = connect_block_with_sequence_locks(
    &block,
    new_height,
    utxo_cache,
    &self.params,
    &null_seq_context,
    prev_block_mtp,
)?;   // ← single ?-return; no retry
```

**Impact:**
A reorg that hits a single invalid block on the new chain dies
permanently; the alternative-branch fallback that Core provides via
`FindMostWorkChain`'s retry loop is absent. Combined with BUG-3
(`FindMostWorkChain` absent), the failed branch leaves the chain
stuck on the original tip even when another, lower-but-valid chain
exists on disk.

---

### BUG-18 — `setBlockIndexCandidates.erase(invalidated)` not modelled (no candidate set to erase from); see BUG-2

**Severity:** P1
**File:** N/A (missing)
**Core ref:** `bitcoin-core/src/validation.cpp:3159,3162` —
`setBlockIndexCandidates.erase(pindexFailed)` and
`setBlockIndexCandidates.erase(pindexTest)` inside `FindMostWorkChain`'s
invalid-ancestor cleanup.

**Description:**
Cross-cite W101 G18. Implicit in BUG-2 / BUG-3. Re-stated as a
separate gate because a future fix that adds the candidate set
must also wire this erase.

**Impact:**
N/A standalone; bundled with BUG-2.

---

### BUG-19 — `MaybeUpdateMempoolForReorg` / `removeForReorg` not called after reorg; stale txs (e.g. CSV-locked txs whose sequence lock no longer holds at the new tip) remain in mempool and get re-broadcast

**Severity:** P1
**File:** `crates/rpc/src/server.rs:1849` (after `write_batch` succeeds,
no mempool refresh).
**Core ref:** `bitcoin-core/src/validation.cpp:3267` —
`MaybeUpdateMempoolForReorg(disconnectpool, true)` calls
`mempool->removeForReorg` (line 569+).

**Description:**
Cross-cite W101 G15. rustoshi's reorg path collects disconnected
blocks into `disconnected_blocks` (server.rs:1613-1646) but never
re-adds the disconnected txs to mempool, AND never iterates the
current mempool to evict txs whose context (CSV, time-based locktime)
became invalid at the new tip.

**Impact:**
Policy violation (NOT consensus): mempool keeps "invalid-at-tip"
txs around, which get re-broadcast on the next mempool flush. Not
a chain-split risk but a policy-bug.

---

### BUG-20 — No `BlockConnected` / `BlockDisconnected` signals fire; ZMQ `hashblock` / `rawblock` notifications and ValidationInterface callbacks are absent from the block-connect / reorg paths

**Severity:** P0-SEC (W141 cross-cite)
**File:** main.rs:2327-2495 (validation_interval); server.rs:1495-1849
(reorg); server.rs:4404 (submitblock).
**Core ref:** `bitcoin-core/src/validation.cpp:2989` —
`m_chainman.m_options.signals->BlockDisconnected(...)`;
`bitcoin-core/src/validation.cpp:3398-3402` —
`signals->BlockConnected(...)` after `cs_main` released.

**Description:**
Cross-cite W101 G14 + W141 BUG-1 (rustoshi: entire 1079-LOC zmq.rs
dead-code). Without `BlockConnected` signals:
- ZMQ `hashblock`/`rawblock`/`hashtx`/`rawtx` topics never publish.
- Wallet doesn't get notified of confirmed txs (rustoshi's wallet is
  largely standalone but the gap means tx confirmation status is
  stale unless explicitly polled).
- BIP-157/158 cfheaders index doesn't increment on every connect
  (the per-block filter index lives at main.rs:2417, only in the
  IBD path, not in submitblock or reorg).

**Impact:**
P0-SEC for ZMQ recipients (electrs/fulcrum/mempool.space) — see W141.

---

### BUG-21 — `MAX_DISCONNECTED_TX_POOL_BYTES` cap on the `DisconnectedBlockTransactions` accumulator absent

**Severity:** P2
**File:** N/A
**Core ref:** `bitcoin-core/src/validation.cpp:3201` —
`DisconnectedBlockTransactions disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES};`.

**Description:**
rustoshi has no equivalent of Core's `DisconnectedBlockTransactions`
with a byte cap (Core uses 20 MB default at
`txmempool.h::MAX_DISCONNECTED_TX_POOL_BYTES`). The
`disconnected_blocks: Vec<Block>` at server.rs:1613-1646 collects
**full block bodies** for mempool refill but has no cap; a
MAX_REORG_DEPTH=100 reorg can buffer 100 * 4MB = 400MB of block
data in RAM before the batch commit.

**Impact:**
Memory pressure during deep reorgs. The MAX_REORG_DEPTH=100 cap (BUG-6)
limits the upper bound, but the cap itself is on the WRONG dimension
(block count, not byte count).

---

### BUG-22 — Reorg walk uses linear `prev_hash` chain traversal; Core's `pskip` O(log n) skip-pointer absent

**Severity:** P1
**File:** `crates/consensus/src/chain_state.rs:574-606` (linear
walk-back in `reorganize`); `crates/consensus/src/chain_manager.rs:200-216`
(linear walk in `is_ancestor`).
**Core ref:** `bitcoin-core/src/chain.cpp` — `CBlockIndex::pskip`
+ `GetAncestor` use binary-lifted skip pointers.

**Description:**
Cross-cite W109 G4 + G7. Every ancestor lookup is O(n). For deep
reorgs (depth N), `reorganize`'s fork-finding loop walks both chains
back step by step, O(N) DB reads. Core's skip-pointer lets
`FindFork` run in O(log N) DB reads, ~10x faster on a 100-block reorg
and ~30x faster on a 1000-block reorg.

**Impact:**
Performance, not correctness. But: combined with BUG-16 (no chunking
+ full write-lock), a deep reorg's wall-clock latency adds N DB
round-trips × ~1ms each = ~100ms reorg-find overhead at depth 100.
Negligible on a fast SSD but contributes to the RPC starvation
window.

---

### BUG-23 — `BLOCK_OPT_WITNESS=128` and `BLOCK_STATUS_RESERVED=256` status flags absent from `BlockStatus`; legacy non-SegWit blocks cannot be distinguished from SegWit-clean blocks

**Severity:** P3
**File:** `crates/storage/src/block_store.rs:21-75`
**Core ref:** `bitcoin-core/src/chain.h:82-85` —
`BLOCK_OPT_WITNESS = 128 //!< block data was received with a witness-enforcing client`,
`BLOCK_STATUS_RESERVED = 256`.

**Description:**
Core's `BLOCK_OPT_WITNESS` flag distinguishes blocks downloaded
pre-SegWit (and thus missing witness data) from post-SegWit blocks.
Used by the historical-rescan path to know whether to re-download
witness-having blocks for a block-witness recovery.

rustoshi has neither flag. Practically, since rustoshi has always
been a SegWit-enforcing client and never downloaded pre-SegWit
witness-stripped blocks, this flag would always be set; the absence
is a P3 documentation gap.

`BLOCK_STATUS_RESERVED` is also absent. The historical assumeUTXO
snapshot pre-validation flag (rustoshi's W138 dead `ChainstateManager`
predecessor) used this; absence is consistent with rustoshi's
single-chainstate design but worth tracking.

**Impact:**
Cosmetic. No runtime divergence.

---

### BUG-24 — `submit_block` direct-connect path performs 8 separate non-atomic DB writes (header → block → height-index → undo → block-index → tx-index → UTXO-flush → best-block); a crash between any two leaves the chain in an inconsistent state

**Severity:** P0
**File:** `crates/rpc/src/server.rs:4404-4577`
**Core ref:** `bitcoin-core/src/validation.cpp:3005-3110` —
`ConnectTip` uses `CCoinsViewCache::Flush` and `FlushStateToDisk`'s
batched write for atomicity.

**Description:**
The `submit_block` accept-direct path writes:
1. `store.put_header(&block_hash, &block.header)` (line 4407)
2. `store.put_block(&block_hash, &block)` (line 4411)
3. `store.put_height_index(new_height, &block_hash)` (line 4418)
4. `store.put_undo(&block_hash, &storage_undo)` (line 4430)
5. `store.put_block_index(&block_hash, &entry)` (line 4489)
6. `store.put_tx_index(&tx.txid(), &entry)` for every tx (line 4524)
7. `utxo_view.flush()` (line 4535)
8. `store.set_best_block(&block_hash, new_height)` (line 4541)

Each is a separate RocksDB write. A crash between (7) and (8) leaves
the UTXO set advanced but the tip pointer not updated; restart picks
up the old tip but the UTXO already reflects the new block. The
next block validation then double-spends.

The Pattern D fleet-wide closure of 2026-05-07 (see comments at
server.rs:1364) explicitly closes this for the **reorg path** via
single `WriteBatch`. The direct-connect path was NOT included.

**Excerpt — sequence of unbatched writes:**
```rust
// server.rs:4407-4544
if let Err(e) = store.put_header(&block_hash, &block.header) { ... }
if let Err(e) = store.put_block(&block_hash, &block) { ... }
if let Err(e) = store.put_height_index(new_height, &block_hash) { ... }
if let Err(e) = store.put_undo(&block_hash, &storage_undo) { ... }
if let Err(e) = store.put_block_index(&block_hash, &entry) { ... }
for tx in &block.transactions {
    if let Err(e) = store.put_tx_index(&tx.txid(), &entry) { ... }
}
if let Err(e) = utxo_view.flush() { ... }
if let Err(e) = store.set_best_block(&block_hash, new_height) { ... }
```

**Impact:**
P0 — post-crash consistency hazard. The validation_interval IBD
loop (main.rs:2339-2434) has the same pattern (separate writes),
inheriting the same crash window.

Cross-cite: this was supposed to be closed by Pattern D
(post-reorg-consistency-fleet-result-2026-05-05.md), but only the
reorg path was retrofitted. The single-block submit and IBD paths
remain unbatched.

---

## Fleet patterns observed

1. **Three-pipeline guard** (BUG-1, BUG-4, BUG-5, BUG-24): the same
   primitive (`block-accept-and-advance-tip`) is implemented three
   times across the codebase with subtle differences in atomicity,
   error handling, and side-effect ordering. The reorg pipeline was
   the only one retrofitted with single-batch atomicity in the
   2026-05-05 Pattern D wave; the IBD and submitblock pipelines
   still write 8 keys non-atomically.

2. **Dead module / plumb-but-don't-flip** (BUG-9, BUG-12, BUG-13):
   - `compare_chain_work_with_tiebreak` *should* consult
     `ChainManagerState::sequence_ids` but doesn't.
   - `accept_block_header_chain_work` is exported and tested but
     never called from production.
   - `contextual_check_block_header` is similarly inert; the
     header-acceptance closure inlines a partial replacement.

3. **Comment-as-confession** (BUG-1): `dumptxoutset rollback`'s
   failure log says *"restart node to recover via ActivateBestChain"*
   — but ActivateBestChain doesn't exist. This is the same shape as
   W138 BUG-1 (rustoshi's `ChainstateManager` dead module) and W145
   BUG-3 (two parallel `block_subsidy` impls).

4. **Wrong-value constant** (BUG-6): `MAX_REORG_DEPTH=100` should be
   288 to match `MIN_BLOCKS_TO_KEEP`. One-line fix; pinned in W101
   test as the wrong value.

5. **Carry-forward re-anchor** (BUG-2, BUG-3, BUG-18): all three are
   downstream consequences of the missing `setBlockIndexCandidates`.
   A future wave that lands the candidate set should close all three
   together.

6. **Bitfield-vs-ordinal confusion** (BUG-7, BUG-8): `BLOCK_VALID_*`
   values are treated as bit-flags via `|=` and `& flag != 0` while
   Core treats them as ordinal levels stored in low 3 bits, queried
   via `(status & MASK) >= level`. Same shape as W109 G21+G22 but
   cross-impl: blockbrew / clearbit / hotbuns may have the same
   pattern — flag this for the W148 fleet rollup.

## Cross-cite to MEMORY.md / prior waves

- **W97 G7** — `contextual_check_block_header` dead code (BUG-13).
- **W101 G1-G5** — `setBlockIndexCandidates` absent (BUG-2, BUG-3).
- **W101 G10** — `fInvalidFound` retry absent (BUG-17).
- **W101 G13** — `ActivateBestChain` chunking absent (BUG-16).
- **W101 G14** — `BlockConnected` signal absent (BUG-20).
- **W101 G15** — `removeForReorg` absent (BUG-19).
- **W101 G18** — `setBlockIndexCandidates.erase` absent (BUG-18).
- **W109 G3** — `BlockIndexEntry` writes on header acceptance (BUG-14).
- **W109 G4 / G7** — skip-pointer absent (BUG-22).
- **W109 G10** — `m_chain_tx_count` / `nTimeMax` absent (BUG-10, BUG-11).
- **W109 G21** — `IsValid(nUpTo)` ordinal check absent (BUG-8).
- **W109 G22** — `RaiseValidity` monotonic absent (BUG-7).
- **W109 G24** — `setBlockIndexCandidates` absent (BUG-2).
- **W121 BUG-16** — block-filter index only in IBD path (BUG-4 fanout).
- **W138 BUG-1** — `ChainstateManager` dead module (BUG-1 same shape).
- **W141 BUG-1** — entire 1079-LOC `zmq.rs` is DEAD (BUG-20).

## Priority for the next fix wave

P0-class (consensus or crash-recovery hazard):
- **BUG-6** — `MAX_REORG_DEPTH` 100 → 288 (one-line; closes a
  CONSENSUS-DIVERGENT split at any reorg depth in 101..288).
- **BUG-7 + BUG-8** — `BlockStatus::VALID_*` ordinal semantics
  (one-helper-function fix: introduce `validity_level()` + factor
  `set_validity_level`).
- **BUG-12** — wire `accept_block_header_chain_work` into the
  production header path (header_sync.rs:339, single call site).
- **BUG-24** — convert `submit_block` direct-connect to single
  `WriteBatch` (mirror the Pattern D refactor already in
  `try_attach_and_reorg`).
- **BUG-13** — wire `contextual_check_block_header` into
  `process_headers`'s closure (replace the inline MTP-only check
  with the full Core-parity helper).

P1 (correctness / DoS):
- **BUG-15** — header-tip-vs-chain-tip cap (mirror Core's
  `MAX_HEADERS_PENDING` style gate).
- **BUG-17** — reorg `fInvalidFound` retry loop (small refactor on
  `try_attach_and_reorg` to fall back to next-best on
  `Err(ConnectFailed)`).
- **BUG-9** — comparator should consult `nSequenceId` not block hash
  (small refactor; precondition: `ChainManagerState` made
  globally-accessible).

Long-tail (P2/P3):
- **BUG-2, BUG-3, BUG-18** — introduce `setBlockIndexCandidates`
  in-memory sorted set; precondition for `ActivateBestChain` proper.
- **BUG-22** — `pskip` skip-pointer for O(log n) ancestor lookups.
- **BUG-19** — mempool `removeForReorg`.
- **BUG-20** — wire `BlockConnected` / `BlockDisconnected` signals.
- **BUG-1, BUG-4, BUG-5** — extract `connect_tip` / `disconnect_tip`
  / `activate_best_chain` as the single canonical control loop
  (architectural rewrite candidate; coupled to candidate-set
  refactor above).
