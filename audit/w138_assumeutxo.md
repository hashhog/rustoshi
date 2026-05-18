# W138 — AssumeUTXO snapshots audit (rustoshi)

**Wave:** W138 — assumeUTXO snapshots (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:**
- `crates/storage/src/snapshot.rs` (~2,420 LOC) — `SnapshotMetadata`,
  `SnapshotReader`, `SnapshotWriter`, `SnapshotState`, `SnapshotActivation`,
  `ChainstateManager`, `compute_hash_serialized`, `compute_utxo_muhash`,
  `tx_out_ser`, `compress_amount`, `write_compressed_script`,
  `read_snapshot_blockhash` / `write_snapshot_blockhash`,
  `find_snapshot_chainstate_dir`.
- `crates/storage/src/w102_assumeutxo_gates.rs` (~729 LOC) — the
  pre-existing W102 gate audit that documents 10 known bugs.
- `rustoshi/src/main.rs` lines 1654-1905 — the `--load-snapshot=<path>`
  CLI activation path (ingestion + tip set).
- `crates/rpc/src/server.rs::dump_tx_outset` (lines 7664-9100) — the
  `dumptxoutset` RPC (latest + rollback modes).
- `crates/rpc/src/server.rs::load_tx_outset` (lines 8045-8121) — the
  `loadtxoutset` RPC, **wholly stubbed** with `RPC_INTERNAL_ERROR`.
- `crates/consensus/src/params.rs` lines 14-52 + 659-728 + 838-875 —
  `AssumeutxoData` struct + mainnet (5 entries: 4 Core + 1 local) +
  testnet4 (3 entries: 2 Core + 1 fabricated h=290000) tables.
  regtest is empty.

**References (Bitcoin Core):**
- `bitcoin-core/src/node/utxo_snapshot.h` + `node/utxo_snapshot.cpp` —
  `SnapshotMetadata`, `WriteSnapshotBaseBlockhash`,
  `ReadSnapshotBaseBlockhash`, `FindAssumeutxoChainstateDir`,
  `SNAPSHOT_MAGIC_BYTES = {'u','t','x','o',0xff}`, `VERSION = 2`,
  `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"`,
  `SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"`.
- `bitcoin-core/src/validation.cpp` lines 5588-6345 —
  `ChainstateManager::ActivateSnapshot`,
  `ChainstateManager::PopulateAndValidateSnapshot`,
  `ChainstateManager::MaybeValidateSnapshot`,
  `ChainstateManager::AddChainstate`,
  `ChainstateManager::LoadAssumeutxoChainstate`,
  `ChainstateManager::MaybeRebalanceCaches`,
  `ChainstateManager::ValidatedSnapshotCleanup`,
  `Chainstate::InvalidateCoinsDBOnDisk`,
  `Chainstate::m_from_snapshot_blockhash`,
  `Chainstate::m_assumeutxo` (`UNVALIDATED` / `VALIDATED` / `INVALID`),
  `Chainstate::m_target_blockhash`, `Chainstate::m_target_utxohash`.
- `bitcoin-core/src/rpc/blockchain.cpp` lines 3074-3548 —
  `dumptxoutset`, `loadtxoutset`, `getchainstates`.
- `bitcoin-core/src/kernel/chainparams.cpp` lines 158-183 (mainnet),
  376-389 (testnet4), 607-628 (regtest) — `m_assumeutxo_data` tables.

**Methodology:** 30-gate matrix covering snapshot header format,
peer-supplied vs file-supplied snapshot, CoinsSnapshotReader streaming,
`m_from_snapshot_blockhash` flag, background-validator state machine,
deferred block download triggers, dump/load round-trip integrity, and
AssumeUTXO chainparams table integrity. Each gate is classified PRESENT
/ PARTIAL / MISSING with rustoshi code refs. Bugs are catalogued with
P0-CONSENSUS / P0-CDIV / P0 / P1 / P2 / P3 severity.

**Note:** This wave **extends** the pre-existing W102 audit (which
catalogues 10 bugs in `w102_assumeutxo_gates.rs`). The W102 bugs are
re-validated here as still-present and additional gaps unique to W138
(snapshot persistence, restart, `getchainstates` RPC, AssumeUTXO chainparams
fabrication) are added on top.

---

## 30-gate matrix

### Section 1 — Snapshot file header

| # | Gate | Status | Refs |
|---|------|--------|------|
| G1 | `SNAPSHOT_MAGIC_BYTES = b"utxo\xff"` | PRESENT | `snapshot.rs:57`; mirrors Core `node/utxo_snapshot.h:28` |
| G2 | Version `u16` LE (Core `VERSION = 2`) emitted + range-checked | PRESENT | `snapshot.rs:60` + `:189-192` |
| G3 | `network_magic` (`pchMessageStart`) embedded + verified | PRESENT | `snapshot.rs:194-202` |
| G4 | `base_blockhash` (32B) embedded | PRESENT | `snapshot.rs:204-207` |
| G5 | `coins_count` (`u64` LE) embedded | PRESENT | `snapshot.rs:209-212` |

### Section 2 — Per-coin record encoding (CoinsSnapshotReader)

| # | Gate | Status | Refs |
|---|------|--------|------|
| G6 | Grouped layout: `txid || CompactSize(n_coins_in_txid) || (vout, code, amount, ScriptCompression)*` | PRESENT | `snapshot.rs:309-387` + `:481-520` |
| G7 | `code` = `(height<<1)\|coinbase` via Bitcoin `VARINT` (not CompactSize) | PRESENT | `snapshot.rs:336-338`; mirrors Core `serialize.h::ReadVarInt` |
| G8 | Per-coin `height > base_height` rejection (Core L5814) | PRESENT | `snapshot.rs:347-358` — **gated via opt-in `with_base_height()`**; main.rs:1692 wires it |
| G9 | Per-coin `MoneyRange(value)` rejection (Core L5820) | PRESENT | `snapshot.rs:360-369` (always-on); mirrors Core `MoneyRange` |
| G10 | Trailing-byte / "left-over coins" guard | PRESENT | `snapshot.rs:389-398` `verify_complete()`; main.rs:1780 wires it |

### Section 3 — AssumeUTXO chainparams + hash check

| # | Gate | Status | Refs |
|---|------|--------|------|
| G11 | `AssumeutxoData::height`, `blockhash`, `hash_serialized`, `chain_tx_count` struct | PRESENT | `consensus/params.rs:14-52` |
| G12 | Mainnet entries match Core (840k/880k/910k/935k) | **PARTIAL — BUG-1** | `consensus/params.rs:660-707` Core entries plus **fabricated h=944,183 hashhog-local entry** at `:717-728` |
| G13 | Testnet4 entries match Core (90k/120k only) | **PARTIAL — BUG-2 P0-CDIV** | `consensus/params.rs:838-874` claims `[90k, 120k, 290k]` but **Core only defines `[90k, 120k]`**; `290_000` is a fabricated entry with no upstream provenance |
| G14 | Signet / testnet3 / regtest assumeutxo tables empty | PARTIAL — BUG-3 | `consensus/params.rs:783, 919, 957` empty for regtest; Core regtest has 3 entries (110, 200, 299) for unit/functional/fuzz tests; rustoshi cannot fuzz-load Core regtest snapshots |
| G15 | `hash_serialized` recomputed over loaded UTXO set + compared to chainparams (Core L5912) | PARTIAL — BUG-4 | `main.rs:1714-1715, 1792-1801` — recomputed in **both** legacy AND core-shaped forms and accepted if **either** matches; legacy form has no provenance to Core, weakens the consensus check |

### Section 4 — Headers-chain presence + chainwork

| # | Gate | Status | Refs |
|---|------|--------|------|
| G16 | Base blockhash must be in headers-chain before load (Core L5611-5614) | **MISSING — BUG-5 P0-CONSENSUS** | `main.rs:1659-1905` proceeds unconditionally; **W102 G4 still open**; `snap_index_entry.prev_hash = Hash256::ZERO` at `:1871` creates a phantom orphan index entry |
| G17 | Base block's header chainwork ≥ `nMinimumChainWork` (Core L5622-5624) | **MISSING — BUG-6 P0-CDIV** | `main.rs:1845` hardcodes `snapshot_chain_work = minimum_chain_work` regardless of the snapshot block's real cumulative work; **W102 G5 still open**; a snapshot for h=1 with chain_work near zero would be accepted with inflated work |
| G18 | "Best header more-work than snapshot base" check (Core L5622) | MISSING — BUG-7 | `main.rs:1659-1905` — no `m_best_header->GetAncestor(snapshot_start_block->nHeight) != snapshot_start_block` check; a forked headers-chain with more work than the snapshot-anchored chain would silently lose to the snapshot |
| G19 | Reject when current chain is already snapshot-active (Core L5600 "Can't activate ... more than once") | **MISSING — BUG-8** | `main.rs:1659-1905` — no `from_snapshot_blockhash`-already-set check; running `--load-snapshot` twice in sequence would silently overwrite the first snapshot's tip pointer |
| G20 | Reject when mempool not empty (Core L5627-5629) | MISSING — BUG-9 | `main.rs:1659-1905` — no `mempool.size() > 0` check; activation pre-RPC bind makes this latent (mempool always empty), but if the CLI path is reordered (or the RPC path is ever wired) the guard is needed |

### Section 5 — Dual-chainstate / background-validator state machine

| # | Gate | Status | Refs |
|---|------|--------|------|
| G21 | `Chainstate::m_from_snapshot_blockhash` field on the chainstate | **MISSING — BUG-10 P0-CDIV** | `consensus/chain_state.rs` — no `from_snapshot_blockhash` field, and `SnapshotActivation` (in `snapshot.rs:1192-1232`) is **never instantiated outside test code** (confirmed by `grep ChainstateManager::new` finding only `w102_assumeutxo_gates.rs` and `snapshot.rs::tests`); **W102 G14 still open** |
| G22 | Second "background IBD" `Chainstate` constructed (Core L5664-5666 `make_unique<Chainstate>(...base_blockhash)`) | **MISSING — BUG-11 P0-CDIV** | `main.rs:1659-1905` constructs **no** second chainstate; W102 G14/G15 still open |
| G23 | `ChainstateManager::AddChainstate` wired (Core L6170) | **MISSING — BUG-12 P0-CDIV** | `rustoshi_storage::ChainstateManager` exists but is never instantiated in `rustoshi/src/main.rs` (only in tests); the API at `storage/src/snapshot.rs:1342-1514` is dead code |
| G24 | `MaybeValidateSnapshot` invoked when background IBD reaches base height (Core L5967) | **MISSING — BUG-13 P0-CDIV** | No call site for `should_validate_snapshot()` outside test code (`grep` returns only `w102` + `snapshot::tests`); W102 G16 still open |
| G25 | On `MaybeValidateSnapshot` hash mismatch → `m_assumeutxo = INVALID` + `InvalidateCoinsDBOnDisk` + fatal error (Core L6010-6017) | **MISSING — BUG-14 P0-CDIV** | No `SnapshotState::Invalid` arm in `SnapshotState` enum (`snapshot.rs:608-635`); rename-to-`_INVALID` path absent; W102 G17 still open |
| G26 | Cache rebalance between snapshot + IBD chainstates (Core L6085 `MaybeRebalanceCaches`) | PARTIAL — BUG-15 | `snapshot.rs:1485-1513` defines `snapshot_cache_size` / `ibd_cache_size` getters but production never calls them (only tests). Production uses a single shared cache for the only chainstate |
| G27 | `ValidatedSnapshotCleanup` (rename `chainstate_snapshot` → `chainstate`, delete bg dir) (Core L6280) | MISSING — BUG-16 | No rename/cleanup function in `snapshot.rs`; the helpers `find_snapshot_chainstate_dir` + `read_snapshot_blockhash` exist but are not called from production startup |

### Section 6 — Persistence across restart

| # | Gate | Status | Refs |
|---|------|--------|------|
| G28 | `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"` written under snapshot chainstate dir (Core `WriteSnapshotBaseBlockhash`) | PARTIAL — BUG-17 | `main.rs:1808` calls `write_snapshot_blockhash(&datadir, &blockhash)` writing to the **datadir root**, not under a separate `chainstate_snapshot/` directory; restart won't trigger the Core `LoadAssumeutxoChainstate` reconstruction path |
| G29 | On startup, `LoadAssumeutxoChainstate` reads `base_blockhash` file + recreates snapshot chainstate (Core L6151) | **MISSING — BUG-18 P0-CDIV** | `main.rs` startup never reads the `base_blockhash` file via `read_snapshot_blockhash`; the helper exists at `snapshot.rs:1252-1277` but is dead code from production's POV |
| G30 | RPC `loadtxoutset` activates a snapshot (Core `rpc/blockchain.cpp:3368-3447`) | **MISSING — BUG-19 P0-CDIV** | `crates/rpc/src/server.rs:8045-8121` returns `RPC_INTERNAL_ERROR` **unconditionally**; W102 G25 still open; the documented operator workflow is "stop the node, restart with CLI flag" |
| BONUS | RPC `getchainstates` (Core `rpc/blockchain.cpp:3462`) | **MISSING — BUG-20** | `grep getchainstates` in `crates/rpc/src/server.rs` returns nothing; no RPC method exposing snapshot/background chainstate status; operators have no JSON-RPC introspection of `snapshot_blockhash`, `validated`, or `coins_db_cache_bytes` per chainstate |

---

## Catalogued bugs (20 total)

### P0-CONSENSUS (1)

- **BUG-5** (G16) `--load-snapshot` does NOT check that `base_blockhash`
  appears in the headers chain before ingesting coins. Core's
  `ActivateSnapshot` errors out with `"The base block header (X) must
  appear in the headers chain. Make sure all headers are syncing, and
  call loadtxoutset again"` (validation.cpp:5611-5614). Rustoshi
  fabricates a `BlockIndexEntry` with `prev_hash = Hash256::ZERO`
  (main.rs:1871) — the snapshot tip becomes an orphan index entry not
  connected to any chain. **Consensus impact**: a snapshot for the
  wrong network or a non-existent block can be activated; the
  `assumeutxo_data` chainparams check (G15) catches blockhash
  fabrication, but a same-blockhash + wrong-prev-header scenario
  (corrupted/forged file passing the hash check) bypasses every other
  invariant Core enforces. Aggravated by BUG-4 (legacy-hash fallback).

### P0-CDIV (7)

- **BUG-2** (G13) testnet4 `assumeutxo_data` contains a fabricated
  third entry at height **290,000** that does NOT exist in Bitcoin
  Core's `kernel/chainparams.cpp::CTestNet4Params::m_assumeutxo_data`
  (Core has only `[90'000, 120'000]`). The `hash_serialized`
  `97267e00…14545` and `blockhash` `0000000577f274…ac0` have no upstream
  provenance — they are fabricated values. Any rustoshi node that loads
  a testnet4 snapshot for h=290k will accept it with no cross-impl
  verification; Core would reject. **Comment trail at params.rs:837**
  states "Values lifted verbatim from `bitcoin-core/src/kernel/chainparams.cpp`
  ... Heights 90000, 120000, 290000" — **factually wrong**, classic
  "comment-as-confession" lying about provenance.
- **BUG-6** (G17) `chain_work` for the snapshot tip is hardcoded to
  `params.minimum_chain_work` (main.rs:1845) regardless of the snapshot
  block's real cumulative work. Documented as intentional ("We don't
  have the real cumulative work without scanning history"). Effect: a
  rustoshi node that ingested a forged snapshot for an early block
  (e.g. h=1) would still accept the snapshot's tip as having crossed
  the minimum-work threshold. Core's chainwork check
  (validation.cpp:5622-5624) compares against the **real** headers-chain
  ancestor's `nChainWork`.
- **BUG-10** (G21) `Chainstate` has no `m_from_snapshot_blockhash`
  field. `SnapshotActivation` (storage/snapshot.rs:1192) exists but is
  never wired into the live `ChainState` in `crates/consensus`. **Every
  Core code path keyed on `m_from_snapshot_blockhash` is unreachable in
  rustoshi**: prune lower-bound (Core L6354), `IsBackgroundIBD`-style
  classification, snapshot-vs-historical mempool transfer (Core
  L6184), chainstate selection (`ActiveChainstate` vs
  `HistoricalChainstate`).
- **BUG-11** (G22) Second "background IBD" chainstate is never
  constructed. Core's `ActivateSnapshot` calls
  `std::make_unique<Chainstate>(...)` then `AddChainstate`. Rustoshi
  proceeds with a single chainstate that simply jumps from genesis to
  the snapshot tip — there is no independent path to ever
  cross-validate the snapshot.
- **BUG-13** (G24) `MaybeValidateSnapshot` is never invoked. The
  background IBD chainstate would normally trigger it on reaching the
  snapshot height (Core ConnectTip path). Rustoshi has no second
  chainstate, so the comparison `validated_cs_stats->hashSerialized ==
  au_data.hash_serialized` never runs.
- **BUG-14** (G25) `SnapshotState::Invalid` and `m_assumeutxo = INVALID`
  arms are absent. Even if a future fix wires BUG-13, there's no
  state-machine arm to mark the snapshot rejected, no
  `InvalidateCoinsDBOnDisk`-equivalent rename, no fatal-error shutdown
  path. The node would silently keep using the bad UTXO set.
- **BUG-18** (G29) Restart never reconstructs the snapshot chainstate
  from disk. Core's `LoadAssumeutxoChainstate` (validation.cpp:6151)
  calls `FindAssumeutxoChainstateDir` + `ReadSnapshotBaseBlockhash` on
  startup. Rustoshi has both helpers (storage/snapshot.rs:1252-1289)
  but `main.rs` never calls either; the `from_snapshot_blockhash`
  marker is fire-and-forget. After restart, the node looks identical
  to a non-snapshot node — there's no way to identify a chainstate
  as snapshot-derived for IBD prune semantics or RPC introspection.
- **BUG-19** (G30) RPC `loadtxoutset` is **unconditionally disabled**
  (server.rs:8095-8120). RPC returns `RPC_INTERNAL_ERROR` directing
  operators to restart with CLI flag. Pre-existing W102 G25 finding,
  unchanged.

### P0 (5)

- **BUG-1** (G12) Mainnet `assumeutxo_data` contains an extra
  hashhog-local entry at h=944,183 in addition to the 4 Core entries.
  Documented as intentional in params.rs:708-716 ("NOT a Bitcoin Core
  chainparams entry"). Effect: a rustoshi node will accept a snapshot
  that no Core node accepts. The cross-impl chain
  (blockbrew/lunarblock/hotbuns) is documented to use the same h=944183
  values, so this is internally consistent within hashhog but **diverges
  from Core**. Not P0-CDIV because the divergence is only
  "additional acceptance" not "different chain selection", but operators
  who trust Core's hashes will be surprised.
- **BUG-4** (G15) `hash_serialized` is recomputed in **both** legacy
  and core-shaped forms (main.rs:1714-1715, 1792-1801) and either match
  causes acceptance. The "legacy" form (Hash256-prefixed + LE
  u32(height) + 1B coinbase + LE u64(value) + raw script) has **no
  Core provenance**. Any `AssumeutxoData::hash_serialized` value pinned
  in chainparams that was computed in the legacy form would mean the
  snapshot file passes by satisfying the wrong invariant. The dual-hash
  accept-either logic was added 2026-05-03 to recover a mainnet snapshot
  load — but the legacy form should be retired now that core-form is
  available, otherwise it weakens the consensus check.
- **BUG-7** (G18) No headers-chain better-work check. Core's
  `ActivateSnapshot` (validation.cpp:5622-5624) rejects activation if
  there exists a headers-chain branch with more cumulative work than
  the snapshot-anchored chain. Without this check, an attacker
  controlling header sync (e.g. via early-IBD eclipse) could feed a
  forked headers chain that has more work than the snapshot but
  doesn't contain the snapshot block; loading the snapshot anyway
  commits the node to the inferior chain.
- **BUG-12** (G23) `ChainstateManager::AddChainstate` (Core L6170) has
  no rustoshi equivalent in production. `rustoshi_storage::ChainstateManager`
  exists at storage/snapshot.rs:1342-1514 but is **never instantiated
  outside test code** — `grep ChainstateManager::new` finds 8 hits, all
  in `w102_assumeutxo_gates.rs` and `snapshot.rs::tests`. The whole
  abstraction is well-engineered dead code.
- **BUG-17** (G28) `SNAPSHOT_BLOCKHASH_FILENAME` is written under the
  datadir root (main.rs:1808 `write_snapshot_blockhash(&datadir, ...)`)
  instead of under a separate `chainstate_snapshot/` directory. Core's
  contract is the file lives inside the snapshot chainstate's own
  leveldb dir so `FindAssumeutxoChainstateDir` can locate it. Rustoshi's
  file lives next to `LOG`, `CURRENT`, etc. — a future
  `find_snapshot_chainstate_dir(&datadir)` call would fail because the
  `_snapshot` suffix dir doesn't exist.

### P1 (5)

- **BUG-3** (G14) regtest `assumeutxo_data` is empty. Core regtest has
  3 entries at heights 110/200/299 used by `feature_assumeutxo.py`,
  `tool_bitcoin_chainstate.py`, and `fuzz/utxo_snapshot.cpp`. Rustoshi
  cannot run the equivalent functional tests because there are no
  rendezvous hashes in chainparams.
- **BUG-8** (G19) No double-activation guard. Core: `if
  (this->CurrentChainstate().m_from_snapshot_blockhash) return error("Can't
  activate a snapshot-based chainstate more than once")` (Core L5600).
  Rustoshi never checks because there's no `m_from_snapshot_blockhash`
  field. Running `--load-snapshot=A` then `--load-snapshot=B` would
  silently let B's coins overwrite A's; the persisted
  `base_blockhash` file would be flipped, and `set_best_block` would
  jump again. The current code path runs pre-binding so practically
  hard to trigger, but the invariant is absent.
- **BUG-9** (G20) No empty-mempool guard at activation. Latent because
  activation runs pre-RPC-bind; surfaces if RPC `loadtxoutset` is ever
  wired (BUG-19 fix).
- **BUG-15** (G26) Single-chainstate cache rebalance is absent. The
  helpers `snapshot_cache_size` / `ibd_cache_size` exist in
  `ChainstateManager` but are never wired (BUG-12). Functional impact
  is low because there's only one chainstate.
- **BUG-20** (BONUS) RPC `getchainstates` is missing. Operators have
  no JSON-RPC way to know whether the active chainstate is
  snapshot-derived, whether validation is complete, what the
  background chainstate's height is, or cache allocations. Important
  for ops + monitoring tooling that mirrors Core's API.

### P2 (2)

- **BUG-16** (G27) `ValidatedSnapshotCleanup` (rename
  `chainstate_snapshot` → `chainstate` + delete bg-dir) has no rustoshi
  equivalent. Latent because there's no second chainstate to clean up;
  becomes relevant when BUG-11 is fixed.
- **W102 G29** (carried forward) On hash-mismatch the CLI path returns
  `Err(...)` after all coins have been written to CF_UTXO; the datadir
  is left poisoned. Documented in `w102_assumeutxo_gates.rs:600-613`.
  Still open.

### P3 (0)

(None unique to this audit — `W102 G10` partial-flush cadence and
`W102 G30` ZMQ-notification gaps are documented in W102 and not
re-promoted here.)

---

## Top 5 findings

1. **BUG-5 / G16 P0-CONSENSUS**: `--load-snapshot` ingests coins
   regardless of whether the snapshot's `base_blockhash` is in the
   headers chain. Combined with **BUG-4** (legacy-hash-fallback
   accept-either), a forged snapshot that matches one of the
   chainparams hashes can be ingested even without a corresponding
   headers-chain commitment. Core's `ActivateSnapshot` rejects
   unconditionally at this point (validation.cpp:5611-5614).

2. **BUG-2 / G13 P0-CDIV**: testnet4 `assumeutxo_data` has a
   **fabricated 290,000 entry not in Core**, with a
   factually-wrong "lifted verbatim from Core" comment at
   params.rs:837. Classic comment-as-confession lying about
   provenance — should be deleted and the comment corrected.

3. **BUG-10/11/12/13/14/18 / G21-G29 P0-CDIV (six bugs)**: the entire
   dual-chainstate / background-validator state machine is missing.
   `Chainstate::m_from_snapshot_blockhash`, second-chainstate
   construction, `MaybeValidateSnapshot`, `INVALID`-state handling,
   restart re-construction — all absent. `ChainstateManager` is
   well-engineered dead code (only used by tests). The W102 audit
   tagged 3 of these (G14/G15/G16); W138 confirms 6 total, all P0-CDIV.

4. **BUG-19 / G30 P0-CDIV**: `loadtxoutset` RPC is **wholly
   unimplemented** — returns `RPC_INTERNAL_ERROR` regardless of
   input. Operator tooling that mirrors Core's JSON-RPC interface
   cannot activate snapshots at runtime; only the CLI flag works.
   Plus **BUG-20 (BONUS)**: `getchainstates` RPC is missing entirely.

5. **BUG-4 / G15 P0**: dual-hash accept-either (legacy + core form,
   either match passes) weakens the consensus check. The legacy
   form has no Core provenance and was added 2026-05-03 to recover a
   mainnet snapshot load — should be retired now that core-form is
   computed correctly.

---

## Cross-references

- **W102 audit** (`crates/storage/src/w102_assumeutxo_gates.rs`) is the
  pre-existing companion. W138 confirms all 10 W102 BUGs (G4, G5, G8,
  G10, G14, G15, G16, G17, G25, G29, G30) are still present, and adds 9
  new ones (BUG-1, 2, 3, 7, 8, 9, 15, 17, 20).
- Snapshot writer / reader **G1–G10 codec correctness is excellent** —
  all roundtrip tests pass byte-for-byte against Core's `TxOutSer` (see
  `snapshot.rs:2264-2295`). The gaps are entirely in **state-machine
  wiring + chainparams provenance**, not in codec.
- Cumulative count for this wave: **20 bugs** (1 P0-CONSENSUS + 7
  P0-CDIV + 5 P0 + 5 P1 + 2 P2).
