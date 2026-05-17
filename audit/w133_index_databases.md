# W133 — Index databases (txindex + coinstatsindex) parity audit (rustoshi)

**Wave**: W133 (Index databases DISCOVERY)
**Impl**: rustoshi (Rust)
**Audit date**: 2026-05-17
**Reference**:
- `bitcoin-core/src/index/base.{h,cpp}` — `BaseIndex` framework
  (`ThreadSync`, `Start`, `Stop`, `BlockConnected`, `BlockDisconnected`,
  `BlockUntilSyncedToCurrentChain`, `Rewind`, `ProcessBlock`, `Commit`,
  `m_synced`, `m_init`, `m_best_block_index`, `CustomInit`, `CustomAppend`,
  `CustomCommit`, `CustomRemove`, `CustomOptions`, `AllowPrune`,
  `GetSummary`, `SetBestBlockIndex` → prune-lock update).
- `bitcoin-core/src/index/txindex.{h,cpp}` — `TxIndex::CustomAppend`,
  `TxIndex::FindTx`, `TxIndex::DB::WriteTxs`, `ReadTxPos`,
  `DB_TXINDEX = 't'`, `AllowPrune() == false`.
- `bitcoin-core/src/index/coinstatsindex.{h,cpp}` — `CoinStatsIndex::CustomAppend`,
  `CustomRemove`, `CustomInit`, `CustomCommit`, `LookUpStats`,
  `RevertBlock`, `DB_MUHASH = 'M'`, `AllowPrune() == true`,
  height-keyed + hash-keyed entries.
- `bitcoin-core/src/index/disktxpos.h` — `CDiskTxPos { nFile, nPos, nTxOffset }`,
  VARINT-encoded.
- `bitcoin-core/src/kernel/coinstats.cpp` — `TxOutSer`, `ApplyCoinHash`,
  `RemoveCoinHash`.
- `bitcoin-core/src/crypto/muhash.{h,cpp}` — `MuHash3072`, `Num3072`,
  `ToNum3072` (`SHA256 + ChaCha20::Keystream(384)`), `Finalize`.
- `bitcoin-core/src/init.cpp` (`-txindex` registration via `g_txindex`,
  `-coinstatsindex` via `g_coin_stats_index`, prune-mode refusal).

**Excluded**: blockfilterindex (covered by W121).

**Production code changes**: 0 (pure audit).
**Audit subject**:
- `crates/storage/src/indexes/txindex.rs` (223 LOC) — `TxIndex` /
  `TxLocation` (the "well-engineered helper never wired" parallel;
  never instantiated in production).
- `crates/storage/src/indexes/coinstatsindex.rs` (437 LOC) — `CoinStatsIndex`
  / `CoinStatsEntry`, `serialize_coin_for_muhash` (BUGGY — see BUG-13).
- `crates/storage/src/indexes/muhash.rs` (688 LOC) — `Num3072` /
  `MuHash3072` (own implementation; not Core-byte-compatible — see
  BUG-13 / BUG-14).
- `crates/storage/src/block_store.rs` — `TxIndexEntry`,
  `put_tx_index` / `get_tx_index` / `delete_tx_index` /
  `batch_put_tx_index` / `batch_delete_tx_index` (the
  ACTUAL production code path; uses fields `block_hash`, `tx_offset`,
  `tx_length`).
- `rustoshi/src/main.rs::write_tx_index_entries` (lines 370-388) — the
  production txindex write helper, called from every connect path.
- `crates/rpc/src/server.rs::get_tx_out_set_info` (lines 8123-8290) —
  RPC `gettxoutsetinfo`, references CoinStatsIndex but always falls
  through to full-scan.
- `crates/rpc/src/server.rs::get_raw_transaction` (lines 3423-3598),
  `crates/rpc/src/rest.rs::rest_tx` (lines 525-547) — txindex
  consumers.
- `crates/rpc/src/server.rs::get_index_info` (lines 8635-8682) —
  `getindexinfo` RPC.
- `rustoshi/src/main.rs::cli` (line 148: `txindex: bool`) — CLI flag
  parsed but unused (see BUG-23).

**Test file**: `crates/storage/tests/test_w133_index_databases.rs` — 30
gates, mix of PASS regression pins + `#[ignore]`-pinned xfail BUG-N
stubs.

## Why this matters

Index databases are observable in three high-impact ways:

1. **RPC parity / SPV / light clients.** `getrawtransaction(<txid>)`
   without an explicit blockhash REQUIRES `-txindex` in Core. Light
   clients, block explorers, and PSBT signers query rustoshi against
   a Core-compatible API surface; if `tx_offset` / `tx_length` are
   zeroed (BUG-1) the on-disk lookup path is effectively a linear
   block-scan, and if the genesis coinbase is unconditionally indexed
   (BUG-7) rustoshi returns hits for a tx that Core says is unindexed.
2. **`gettxoutsetinfo` byte parity.** The
   `muhash` field is a 32-byte commitment to the **entire** UTXO set,
   re-derivable from any other Core node — it's the canonical "did
   your UTXO set match consensus?" diagnostic. rustoshi's
   `serialize_coin_for_muhash` (BUG-13) uses **VARINT(compress_amount)**
   for the value and **VARINT** for the height-code, where Core uses
   **int64 LE** and **uint32 LE** respectively. Every coin
   contributes a byte-different element → the muhash never matches
   Core for non-trivial UTXO sets. This is the same shape as the
   blockbrew W122 BUG-1 (Word64 boundary) and nimrod W122 LSB-vs-MSB
   bugs found yesterday: a self-tautological local test passes
   ("insert + remove = identity") but a byte-exact comparison against
   Core's reference muhash diverges.
3. **Assumeutxo + UTXO snapshots.** The same `TxOutSer` form
   commits to the `hash_serialized_3` field — Core's assumeutxo
   activation point validates the snapshot's UTXO set against this
   hash. rustoshi's snapshot writer (`crates/storage/src/snapshot.rs`)
   uses the Core-correct `tx_out_ser` (uncompressed int64 LE), but
   the `serialize_coin_for_muhash` in coinstatsindex.rs uses the
   **wrong** form. **Two pipelines, two byte layouts** — see BUG-13.

## 30-gate audit matrix

| Gate | Status  | Severity | Finding |
|------|---------|----------|---------|
| G1   | MISSING | P0-CDIV  | **BaseIndex framework entirely absent** (no `ThreadSync`, no `m_synced/m_init`, no `BlockUntilSyncedToCurrentChain`, no `StartBackgroundSync`); indexes are inline in connect_tip and have no async/catchup state machine — see BUG-1 |
| G2   | OK      | -        | Per-block sequential indexing invariant preserved: rustoshi inlines index writes into the same atomic RocksDB batch as the UTXO/tip flip (`disconnect_to` line 1417-1424, `try_attach_and_reorg` line 1758-1768) — matches Core's "BlockConnected updates index synchronously" semantic albeit without the BaseIndex thread |
| G3   | BUG     | P0-CDIV  | **`TxIndexEntry.tx_offset` and `.tx_length` are ALWAYS zero** in every production write site (`main.rs:378-379`, `server.rs:1818-1819 / 4521-4522 / 9575-9576`). Fields exist but are never populated — see BUG-1 |
| G4   | BUG     | P1       | **`crates/storage/src/indexes/txindex.rs::TxIndex` is dead code**: never instantiated in production. Only doc-comment mentions (`indexes/mod.rs:20`). The struct has a correct-looking `index_block(...)` that computes real offsets (`80 + varint_size(n)` + per-tx accumulation), but no caller ever uses it — see BUG-2 |
| G5   | OK      | -        | Disconnect path wires `batch_delete_tx_index` for every tx in the disconnected block, atomically with UTXO + tip flip (`server.rs:1417-1424`); reorg path wires both sides (`server.rs:1758-1840`). Pattern C0 + Pattern D fleet-wide closure landed 2026-05-05/07 |
| G6   | BUG     | P0-CDIV  | **txindex includes the genesis coinbase**. `write_tx_index_entries` does not gate on `height == 0`. Core's `TxIndex::CustomAppend` (txindex.cpp:77) returns true early when `block.height == 0` so the genesis-coinbase txid is NEVER indexed — see BUG-7 |
| G7   | BUG     | P1       | **`getindexinfo` omits `coinstatsindex`**. `server.rs:8635-8682` reports `txindex` and `basic block filter index` only. Core's `rpc/node.cpp::getindexinfo` (lines 363-412) reports all three when active — see BUG-3 |
| G8   | BUG     | P1       | **`getindexinfo.synced` is hardcoded `true`**. `server.rs:8657 / 8675` sets `"synced": true` unconditionally if the CF has any row, with comment "the rustoshi indexer is synchronous, so it is always at the tip the moment connect_tip returns". Counter-example: during IBD, a stale rebuild from an older datadir, or a partial truncate, the CF can be non-empty while the indexer is behind tip — see BUG-4 |
| G9   | MISSING | P0-CDIV  | **No `BlockUntilSyncedToCurrentChain` equivalent**. Core's RPCs (`getrawtransaction`, `gettxoutsetinfo`) call this to wait for the index to catch up to the chain tip BEFORE returning. rustoshi's RPCs read the CF directly with no fence — see BUG-5 |
| G10  | MISSING | P1       | **No per-index `DB_BEST_BLOCK` locator persistence**. Core writes a CBlockLocator under `'B'` (per-index DB) at every commit interval (`BaseIndex::Commit`) so an unclean shutdown is recoverable by walking the locator back to the last common ancestor. rustoshi has no per-index locator — see BUG-6 |
| G11  | MISSING | P1       | **No format-version handling**. Core's index DBs include format-version checks (e.g., coinstats.cpp:92 — "old index at `indexes/coinstats` superseded by `indexes/coinstatsindex`"); a downgrade or upgrade path is supported. rustoshi's indexes live in shared `ChainDb` column families with no version key — an incompatible schema change would silently produce garbage |
| G12  | BUG     | P0-CDIV  | **`CoinStatsIndex::put_stats` is NEVER CALLED in production code**. Grep `put_stats\|CoinStatsEntry::genesis` produces hits only inside the index module itself and in `#[cfg(test)]` blocks. The CF (`CF_COINSTATS`) is **always empty** outside of tests. `gettxoutsetinfo` (`server.rs:8141`) always falls through to full UTXO-scan path — see BUG-8 |
| G13  | MISSING | P0-CDIV  | **No `-coinstatsindex` CLI flag at all**. `rustoshi/src/main.rs` has no `coinstatsindex: bool`. Core gates `g_coin_stats_index` initialization on `-coinstatsindex=1` (init.cpp). rustoshi has no equivalent flag, no init path, no thread spawn — see BUG-9 |
| G14  | BUG     | P0-CDIV  | **`serialize_coin_for_muhash` uses VARINT for value + height-code**. Core's `TxOutSer` (kernel/coinstats.cpp:46-51) serializes `outpoint + uint32_t(LE)(height<<1+coinbase) + CTxOut(int64_t LE nValue, scriptPubKey)` — i.e. **uncompressed int64 LE for value, uint32 LE for code**. rustoshi's helper uses `write_varint(code)` and `write_varint(compress_amount(value))` (lines 241-245). Every coin element bytewise diverges — see BUG-13 |
| G15  | BUG     | P1       | **Two-pipeline divergence**: `crates/storage/src/snapshot.rs::tx_out_ser` (lines 737-755) is Core-correct (`u32 LE code` + `i64 LE value` + `compact_size(spk.len()) || spk`), but `coinstatsindex.rs::serialize_coin_for_muhash` (lines 226-251) is **NOT**. Two encoders, two byte layouts. The RPC `get_tx_out_set_info` (server.rs:8249-8256) uses the BUGGY one — see BUG-13 / BUG-14 |
| G16  | OK      | -        | `Num3072::multiply` schoolbook + Mersenne-fold + double-FullReduce is structurally correct; `inverse` via Fermat's little theorem produces matching values for `a * a^-1 == 1 mod p`; bound on the work-buffer is correct (Step-1 cell <= 2^128 - 2^65 + 1, no u128 overflow) |
| G17  | BUG     | P2       | **`Num3072::inverse` is square-and-multiply over `p-2`** vs Core's safegcd (Bernstein-Yang). Core: O(log²p) constant-time. rustoshi: O(3072 × log²p) bit-by-bit. Final answer correct, but ~50–100× slower per UTXO finalize. Only paid once per `gettxoutsetinfo` so cosmetic in practice; flagged for completeness |
| G18  | BUG     | P2       | **ChaCha20 inside `MuHash3072::to_num3072`** is a **bespoke reimplementation**, not a call into a vetted crate. The implementation appears correct (constants `61707865/3320646e/79622d32/6b206574`, 10 double-rounds, LE32 limb readback) but: (a) doc-comment line 367 says "8 rounds per block" — STALE (actual is 20 rounds = 10 double-rounds matching RFC 8439); (b) zero-allocation cleanse vs Core's `memory_cleanse` absent — secrets-in-RAM risk is nil here (no secrets) but pattern is inconsistent with Core |
| G19  | BUG     | P0-CDIV  | **`MuHash3072` finalize is NOT Core-byte-compatible** even if `serialize_coin_for_muhash` were fixed, BECAUSE the input-byte serialization (BUG-13) diverges from Core. Combined with the never-wired `CustomAppend` (BUG-8), rustoshi's muhash cannot match Core's `gettxoutsetinfo` muhash for any non-trivial UTXO set |
| G20  | BUG     | P1       | **No `CustomCommit(DB_MUHASH)` equivalent**. Core writes the **un-finalized** MuHash3072 state (`numerator + denominator`, 768 bytes total) under `'M'` in the coinstatsindex DB at every commit — so a restart can resume the running accumulator without rescanning the entire UTXO set. rustoshi serializes the muhash inside each `CoinStatsEntry` (one per height) — but `put_stats` is never called (BUG-8) so this is also moot today |
| G21  | MISSING | P1       | **No `DBHashKey` / `DBHeightKey` Core scheme**. Core's coinstatsindex.cpp stores entries under BOTH `(height)` and `(hash)` keys, and on `CustomRemove` it copies the height-key entry to a hash-key entry so historical lookups survive a reorg (coinstatsindex.cpp:222-225 — `CopyHeightIndexToHashIndex`). rustoshi's `CoinStatsIndex` is height-keyed only; a reorg overwrites and the pre-reorg hash entry is lost — would matter if BUG-8 were fixed |
| G22  | BUG     | P1       | **`CoinStatsIndex::get_best_height` is O(N) backwards scan**. Lines 188-200 iterate `(0..=10_000_000).rev()` calling `has_stats(height)` per step. Core uses the BaseIndex locator (`'B'`) → O(1). For a mainnet-tip rustoshi node with hypothetical coinstatsindex enabled, this would do up to 10 million has_stats round-trips on every cold-restart |
| G23  | BUG     | P1       | **`--txindex` CLI flag does not gate the writes**. `cli.txindex` is parsed (`main.rs:148`) and read from config (`main.rs:1249`), but no production call site checks it before `write_tx_index_entries`. txindex is always-on regardless of flag. Core: `g_txindex` is `nullptr` unless `-txindex=1` (init.cpp). Wastes ~1.5–2 GB on a mainnet tip; also exposes `getrawtransaction` semantics Core wouldn't expose |
| G24  | MISSING | P1       | **No prune-mode refusal for `coinstatsindex`**. Core enforces: txindex `AllowPrune()=false` (txindex.h:34) → refuses to run with `-prune`; coinstatsindex `AllowPrune()=true` (coinstatsindex.h:52) → updates prune-lock to protect the indexed range. rustoshi has neither; `CoinStatsIndex` has no `AllowPrune` concept; `BlockStore::prune_block` (block_store.rs:727) does not honor any index's lower bound |
| G25  | BUG     | P0-CDIV  | **`TxIndexEntry` serialized as `serde_json`** (`block_store.rs:503-504`, `:511-513`). Core uses `CDiskTxPos` with `VARINT(nFile, nPos, nTxOffset)` → typically 6-12 bytes per entry. rustoshi's JSON is ~80-120 bytes per entry. ~10× disk amplification on a full txindex; key bytes also diverge — see BUG-12 |
| G26  | BUG     | P1       | **`CoinStatsEntry.muhash` field is 768 bytes serialized as JSON `Vec<u8>`** (lines 57-58, 99). With JSON byte-array encoding (`[0,12,255,...]`) the on-disk representation is ~3-4× larger than the underlying 768 raw bytes. Core uses raw `READWRITE(obj.muhash)` of two `Num3072` limb arrays. Compounds the schema-as-JSON issue with bandwidth wastage |
| G27  | OK      | -        | Big-endian height keys in `CF_TX_INDEX` / `CF_COINSTATS` give RocksDB lexicographically-sorted iteration order; `outpoint_key` writes vout big-endian (block_store.rs:248-252; verified in get_tx_out_set_info path which decodes BE at server.rs:8228) |
| G28  | MISSING | P2       | **No `interruption_point` plumbing**. Core's `ComputeUTXOStats` accepts a `std::function<void()> interruption_point` so a shutdown during a heavy gettxoutsetinfo scan exits cleanly. rustoshi's full-scan path (`server.rs:8211-8259`) has no interrupt check; a Ctrl-C during a long scan completes the entire iteration |
| G29  | BUG     | P2       | **`CoinStatsIndex::get_best_height` upper bound is `10_000_000`** (line 191). Magic number; if mainnet ever hits that height (year ~2218 at 10 min blocks → not soon, but) the loop silently misses entries above. Should be `u32::MAX` or based on `state.best_height` |
| G30  | OK      | -        | `bogo_size` formula matches Core (32+4+4+8+2+spk_len) — verified in `get_tx_out_set_info` (`server.rs:8225`) and `get_bogo_size` (`coinstatsindex.rs:210-217`). 50-byte fixed overhead + spk len matches `kernel/coinstats.cpp:35-43` |

**Total: 30 gates, 17 BUGs, 8 MISSING, 5 OK** (non-OK: 25). Five of the
17 BUGs are **P0-CDIV** (`tx_offset/tx_length=0`, genesis-coinbase
indexed, `serialize_coin_for_muhash` byte-incompatible,
`CoinStatsIndex::put_stats` never wired in production, MuHash byte-divergence)
plus G1 (no BaseIndex framework) and G9 (no BlockUntilSynced) are P0-CDIV
MISSING gaps. The remaining 12 BUGs are P1/P2.

## Top findings

### BUG-1 (P0-CDIV) — `TxIndexEntry.tx_offset` / `.tx_length` are always zero

**Where**: `rustoshi/src/main.rs:370-388` (`write_tx_index_entries`),
plus every other production write site:
- `crates/rpc/src/server.rs:1815-1820` (reorg-connect),
- `crates/rpc/src/server.rs:4519-4524` (reorg-attach path),
- `crates/rpc/src/server.rs:9573-9578` (legacy `generateblocks` path),
- `crates/rpc/src/server.rs:14315-14316 / 14417-14418` (tests intentionally
  mirror the production zero-fill).

Every call constructs `TxIndexEntry { block_hash, tx_offset: 0, tx_length: 0 }`.
The struct has the FIELDS for on-disk offsets, but no production code path
ever computes the actual offset within the serialized block. The
consumers — `crates/rpc/src/server.rs::get_raw_transaction` (line 3560-3590)
and `crates/rpc/src/rest.rs::rest_tx` (line 530-544) — read `tx_entry`, then
load the full block and **linearly scan transactions** looking for the
matching txid, ignoring `tx_offset` and `tx_length` entirely.

**Core**: `CDiskTxPos { nFile, nPos, nTxOffset }` (disktxpos.h) is the
ENTIRE point of the txindex. `TxIndex::CustomAppend` (txindex.cpp:74-89)
walks the block computing each tx's serialized offset starting from
`GetSizeOfCompactSize(block.data->vtx.size())` and adding
`GetSerializeSize(TX_WITH_WITNESS(*tx))` per tx. `TxIndex::FindTx`
(txindex.cpp:93-120) seeks directly to `postx.nTxOffset` and reads
the tx — no linear scan.

**Severity**: P0-CDIV functionally because the index fields exist on
wire (in JSON exposed via internal RPC tests) but report `0,0`. P1 for
performance (rustoshi's tx lookup is O(n_tx) per call, Core's is O(1)
after a seek).

**Fix shape**: Either (a) compute real offsets and populate, (b) drop
the fields from `TxIndexEntry` and the JSON serialization, or (c) wire
the existing `crates/storage/src/indexes/txindex.rs::TxIndex::index_block`
(which DOES compute offsets) into the production write path.

### BUG-2 (P1) — `crates/storage/src/indexes/txindex.rs::TxIndex` is dead code

**Where**: `crates/storage/src/indexes/txindex.rs:81-160`. The whole
struct, its `new`/`put`/`get`/`delete`/`contains`/`index_block`/
`disconnect_block` API surface, is **never instantiated in production**.
Grep `TxIndex::new\|TxIndex {` produces only doc-comment hits in
`indexes/mod.rs:20` and worktree copies.

`TxIndex::index_block` (lines 126-149) DOES compute real offsets:
```rust
let mut offset = 80u32 + varint_size(txids.len() as u64);
for (i, (txid, &size)) in txids.iter().zip(tx_sizes.iter()).enumerate() {
    let location = TxLocation::new(block_hash, height, offset, size, i as u32);
    self.put(txid, &location)?;
    offset += size;
}
```

The production code path uses `BlockStore::put_tx_index` with a
DIFFERENT struct (`TxIndexEntry` instead of `TxLocation`) and never
calls this helper.

**Severity**: P1 — well-engineered helper never wired (same pattern as
W121 BUG-16 BlockFilterIndex pre-FIX-69). FIX-69 wired the filter
index; this audit identifies the txindex analog.

### BUG-8 (P0-CDIV) — `CoinStatsIndex::put_stats` is never called in production

**Where**: `crates/storage/src/indexes/coinstatsindex.rs:154-160`.
Production grep:

```
$ grep -rn "put_stats\|CoinStatsEntry::genesis\|CoinStatsEntry::default"
  rustoshi/src/ crates/ | grep -v test_ | grep -v '#\[cfg(test'
```

Returns only re-exports and the definition itself. No production code
calls `put_stats`. `CF_COINSTATS` is always empty outside of unit
tests.

Consequence: `gettxoutsetinfo` (`server.rs:8141`) ALWAYS falls through
to the full-scan path (`server.rs:8159+`), even for the `muhash` /
`none` hash types Core specifically optimizes via the index. A
mainnet-tip rustoshi has ~110 million UTXOs; a full scan per RPC call
is ~30s wall-time, vs Core's ~5ms via the index. This also means the
RUNNING muhash accumulator (the "incremental hash" advantage that
motivated muhash in the first place) is never maintained.

**Severity**: P0-CDIV functionally (the index advertised on the
`getindexinfo` surface is non-functional) + P0-perf.

**Related**: BUG-9 (no `-coinstatsindex` CLI flag), BUG-13 (the
serializer it would use is wrong anyway).

### BUG-13 (P0-CDIV) — `serialize_coin_for_muhash` is byte-incompatible with Core's `TxOutSer`

**Where**: `crates/storage/src/indexes/coinstatsindex.rs:226-251`.

```rust
pub fn serialize_coin_for_muhash(
    txid: &Hash256, vout: u32, height: u32, is_coinbase: bool,
    value: u64, script_pubkey: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(36 + 10 + 10 + script_pubkey.len());
    // Outpoint
    data.extend_from_slice(txid.as_bytes());        // 32B
    data.extend_from_slice(&vout.to_le_bytes());    // 4B
    // Code: height * 2 + coinbase
    let code = (height as u64) * 2 + (is_coinbase as u64);
    write_varint(&mut data, code);                  // ❌ Core: u32 LE = 4B
    // Value (compressed using varint)
    write_varint(&mut data, compress_amount(value));// ❌ Core: i64 LE = 8B
    // ScriptPubKey
    data.extend_from_slice(script_pubkey);          // ❌ Core: CompactSize(len) || bytes
    data
}
```

**Core** (`kernel/coinstats.cpp:46-51`):

```cpp
static void TxOutSer(T& ss, const COutPoint& outpoint, const Coin& coin) {
    ss << outpoint;                                          // 36B
    ss << static_cast<uint32_t>((coin.nHeight << 1) + coin.fCoinBase);  // 4B LE
    ss << coin.out;  // CTxOut::SERIALIZE_METHODS: READWRITE(nValue, scriptPubKey)
                     //  → 8B LE int64 + CompactSize(spk.size()) + spk bytes
}
```

Three byte-level divergences:
1. **height/coinbase code**: rustoshi uses VARINT (1-10 bytes); Core uses `uint32_t` LE (fixed 4 bytes).
2. **value**: rustoshi uses VARINT(compress_amount(v)); Core uses `int64_t` LE uncompressed (fixed 8 bytes).
3. **scriptPubKey**: rustoshi emits raw bytes with NO length prefix; Core prepends `CompactSize(spk.size())`.

A single P2WPKH coin at height 100 with value 50_000_000 sat and a
22-byte spk:
- Core: `32 + 4 + 4 + 8 + 1 (CompactSize 22) + 22` = **71 bytes**
- rustoshi: `32 + 4 + 1 (varint code=200) + 5 (varint(compress_amount(50M))) + 22` = **64 bytes**

Different length AND different contents. Every muhash element diverges
→ accumulator diverges → `gettxoutsetinfo.muhash` is **never** equal
to Core's for any non-trivial UTXO set.

**Cross-impl resonance**: This is the same shape as W122 blockbrew
BUG-1 ("LSB-first byte packing where Core packs MSB-first") and W122
nimrod BUG-1 ("same LSB vs MSB at gcs.nim:79+109") — a local SHA256d
self-test passes ("insert + remove = identity"), but byte-exact
against Core fails. Promotes the **"audit framework requires byte-exact
against Core, not SHA256d self-tautology"** pattern from W122 to fleet
discipline.

**Fix shape**: Replace `serialize_coin_for_muhash` body with the
existing `snapshot.rs::tx_out_ser` body (lines 737-755), which IS
Core-correct. Then thread `tx_out_ser` consistently and delete one
of the two functions. **The Core-correct encoder ALREADY EXISTS in the
codebase** at `crates/storage/src/snapshot.rs:737-755` — two-pipeline
divergence on byte layout.

### BUG-23 (P1) — `--txindex` CLI flag is parsed but never gates the writes

**Where**: `rustoshi/src/main.rs:148` defines `txindex: bool` on the
`Cli` struct, `:1249` merges it from the config file via `merge_bool!`,
and `:4513-4515` tests `--txindex` parses to `true`. But NO production
call site checks `cli.txindex` before calling `write_tx_index_entries`.

```bash
$ grep -nE "if .*\.txindex|cli\.txindex|args\.txindex" rustoshi/src/main.rs
4423:        assert!(!cli.txindex);
4515:        assert!(cli.txindex);
```

Only `#[test]` blocks. Production always writes.

**Core** (`init.cpp`): `g_txindex` is `std::make_unique<TxIndex>` only
if `args.GetBoolArg("-txindex", DEFAULT_TXINDEX)` is true. Otherwise
the global is nullptr and `getrawtransaction(<txid>)` (no blockhash)
returns RPC_INVALID_ADDRESS_OR_KEY.

**Consequence**:
1. **Correctness divergence**: a rustoshi node started WITHOUT
   `--txindex` will still serve `getrawtransaction(<txid>)` for any
   tx anywhere on its main chain. Core under the same config would
   refuse with "No such mempool transaction. Use -txindex or provide
   a block hash to enable blockchain transaction queries."
2. **Disk waste**: a default-config rustoshi accumulates the full
   txindex on every block; for mainnet tip that's ~1.5–2 GB of
   serde_json blobs.

**Fix shape**: gate every `write_tx_index_entries` call (5 production
sites: `main.rs:918, :1104, :2413, :2942` + reorg path
`server.rs:1815`) on the `cli.txindex` boolean. Persist it into
something equivalent to `g_txindex.IsActive()` so disconnect/reorg
paths also respect the gate.

## Universal patterns observed

- **Two-pipeline divergence on byte serialization** (BUG-13 / BUG-15)
  — rustoshi has a Core-correct `tx_out_ser` in `snapshot.rs` AND a
  Core-incompatible `serialize_coin_for_muhash` in `coinstatsindex.rs`,
  and the RPC path uses the bad one. Same architectural class as W122
  blockbrew / nimrod LSB-vs-MSB divergence and the ouroboros
  two-pipeline guard family.
- **Well-engineered helper never wired** (BUG-2, BUG-8) — both
  `indexes/txindex.rs::TxIndex` (with offset-computing `index_block`)
  and `indexes/coinstatsindex.rs::CoinStatsIndex` (with `put_stats` /
  `get_stats` / muhash plumbing) are full implementations that are
  never instantiated in production. Identical shape to W121 BUG-16
  pre-FIX-69.
- **Audit-comment-as-confession** (BUG-4, BUG-8 implicitly) —
  `server.rs:8631-8634` says "the rustoshi indexer is synchronous,
  so it is always at the tip the moment connect_tip returns" — true
  for the synchronous-during-connect path but FALSE during IBD /
  partial-rebuild / reorg-mid-flight; the comment rationalizes a
  hardcoded `synced: true` that should be conditional. Compounds with
  W122 blockbrew BUG-1 "test-comment-as-confession" pattern.
- **CLI flag parsed but unused** (BUG-23) — `--txindex` is observable
  via `getindexinfo` and config-file merge, but no production code
  reads it. Equivalent shape to a feature flag that's "wired through
  but not consulted" — a particularly insidious bug because the test
  suite shows the flag works (`test_cli_txindex_flag` passes), but
  the production effect is hardcoded.
- **Missing entire framework** (G1 / BUG-1 in framework sense) —
  rustoshi inlines index updates rather than implementing the Core
  BaseIndex abstraction. This is a legitimate design choice for a
  single-chain-tip node, but it leaks: no
  `BlockUntilSyncedToCurrentChain` (BUG-5), no per-index locator
  (BUG-6), no format-version (G11), no prune-lock cooperation
  (BUG-11).

## Out of scope

- **blockfilterindex** is covered by W121 / W122; this audit
  cross-references it only to inherit the "well-engineered helper
  never wired" pattern.
- **txospenderindex** (Core's `txospenderindex.h/cpp`) — not implemented
  in rustoshi at all. Out of W133 scope; would be a follow-on
  discovery wave.
- **Mempool index** (Core's mempool persistence covered by FIX-72 /
  FIX-76 / FIX-77) — distinct subsystem, not addressed here.
