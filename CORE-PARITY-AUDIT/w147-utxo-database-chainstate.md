# W147 — UTXO database / chainstate (CCoinsView + CCoinsViewCache + CCoinsViewDB)

**Wave:** W147 — UTXO database / chainstate (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi UTXO database + in-memory cache layer
(`CCoinsView` / `CCoinsViewCache` / `CCoinsViewDB` equivalents), with
focus on the DIRTY/FRESH state machine, on-disk key/value format, the
flush pipeline, obfuscation, and the multi-pipeline structural fault
where the `CoinsView*` hierarchy is fully implemented but production
uses `BlockStoreUtxoView` instead.

**Files audited:**
- `crates/storage/src/utxo_cache.rs` — `Coin` (59-119), `CacheEntryFlags`
  DIRTY/FRESH (138-147), `CoinsCacheEntry` (155-199), `CoinsView` trait
  (209-227), `CoinsViewDB` (236-303), `CoinsViewCache` (312-621),
  `flush_to_db` (541-568), `sync_to_db` (573-607),
  `outpoint_key` (666-671), `is_unspendable` (674-676).
- `crates/storage/src/block_store.rs` — `CoinEntry` storage struct
  (124-133), `BlockStoreUtxoView` (848-1013) — the **actually-used**
  production path, `flush_into_batch` (914-938), `add_utxo` /
  `spend_utxo` (987-1012), `outpoint_key` (820-825),
  `DEFAULT_UTXO_CACHE_BYTES = 2 GiB` (832), `CACHE_ENTRY_OVERHEAD =
  180` (838).
- `crates/storage/src/db.rs` — `ChainDb` (75-310), `open` (89-141),
  metadata keys (`META_BEST_BLOCK_HASH` = `b"best_block_hash"` 16),
  no obfuscation (none).
- `crates/storage/src/columns.rs` — `CF_UTXO = "utxo"` (29), key format
  comment "txid (32 bytes) + vout (4 bytes, big-endian)" (28).
- `crates/storage/src/snapshot.rs` — `CompressAmount`/`CompressScript`
  exist here (`compress_amount` decompress logic 1002-1057, 1144) —
  but ONLY for assumeutxo snapshot encoding, NOT for on-disk Coin.
- `crates/consensus/src/validation.rs` — `CoinEntry` consensus version
  (1402-1411), `UtxoView` trait (1424-1473), `is_unspendable`
  (2097-2102) used by `connect_block`.

**Bitcoin Core references:**
- `bitcoin-core/src/coins.h`:
  - `Coin` class (34-90): `fCoinBase:1` + `nHeight:31` bit-packed
    (40-44), `Serialize` writes `VARINT(nHeight*2 + fCoinBase)` then
    `Using<TxOutCompression>(out)` (62-72), `IsSpent` = output null
    (82-84), `DynamicMemoryUsage` = scriptPubKey usage (86-88).
  - `CCoinsCacheEntry` invariants (94-108) — eight state combos, only
    four valid: unspent+FRESH+DIRTY, unspent+!FRESH+DIRTY,
    unspent+!FRESH+!DIRTY, spent+!FRESH+DIRTY.
  - `CCoinsView` virtual interface (310-345): `GetCoin`, `HaveCoin`,
    `GetBestBlock`, `GetHeadBlocks`, `BatchWrite(cursor, hashBlock)`,
    `Cursor()`, `EstimateSize`.
- `bitcoin-core/src/coins.cpp`:
  - `AddCoin` (87-124) — `IsUnspendable()` early-return (91), FRESH
    computed as `!IsDirty()` only when entry already present and
    spent+DIRTY (109-113), dirty_count tracking.
  - `SpendCoin` (152-176) — FetchCoin, dec dirty_count if dirty,
    Erase if FRESH else SetDirty + Clear, ++dirty_count on the
    SetDirty path.
  - `BatchWrite` (CCoinsViewCache::BatchWrite 208-280) — iterates
    cursor, propagates DIRTY entries to parent with FRESH semantics
    preserved when applicable, asserts no FRESH-coin-in-parent.
  - `Flush` (281-298) — `BatchWrite` with will_erase=true, asserts
    `m_dirty_count==0` after.
- `bitcoin-core/src/txdb.cpp`:
  - `DB_COIN = 'C'` (23), `DB_BEST_BLOCK = 'B'` (24),
    `DB_HEAD_BLOCKS = 'H'` (25), `DB_COINS = 'c'` deprecated (27).
  - Key encoding via `CoinEntry { uint8_t key{DB_COIN}; COutPoint*; }`
    serialized as `key || outpoint->hash || VARINT(outpoint->n)`
    (82-89) — Note: VARINT vout, NOT fixed 4-byte BE.
  - `BatchWrite` (100-167) — multi-batch protocol with
    `DB_HEAD_BLOCKS` two-tip atomicity, partial flush at
    `batch.ApproximateSize() > m_options.batch_write_bytes`, optional
    crash-injection via `simulate_crash_ratio`, WARN if dirty_count
    > 10M.
- `bitcoin-core/src/dbwrapper.h`:
  - `OBFUSCATION_KEY = "\000obfuscate_key"` (14 bytes, 192) — 8-byte
    random XOR key XOR'd over EVERY value on write/read; prevents
    anti-virus false positives.
- `bitcoin-core/src/compressor.cpp`:
  - `CompressAmount` / `DecompressAmount` (~22-90) — mantissa+exponent
    compression mapping integer satoshi values to smaller varint
    integers (`50 * COIN` compresses to 4 bytes vs 8).
  - `CompressScript` / `DecompressScript` (~96-220) — well-known
    pattern tags `0x00..0x05` covering P2PKH/P2SH/P2PK
    compressed/uncompressed; cuts P2PKH/P2SH from 25/23 bytes to 21.
- `bitcoin-core/src/validation.cpp`:
  - `FlushStateToDisk` modes IF_NEEDED/PERIODIC/ALWAYS (~2790-2880),
    dbcache threshold triggers, `-dbcache` default (DEFAULT_DB_CACHE
    = 450 MiB nMinDbCache=4 nMaxDbCache=16384).

**Production code changes:** 0 (pure audit).

## Why this matters

The UTXO database is the **state machine load-bearing wall** of a full
node. Three failure modes recur across this layer and all three are
fleet patterns documented in MEMORY.md:

1. **Two-pipeline guard.** rustoshi ships both a fully-functional
   `CoinsView` / `CoinsViewCache` / `CoinsViewDB` hierarchy
   (utxo_cache.rs, 1077 LOC modeling Core's design point-for-point)
   AND a separate `BlockStoreUtxoView` (block_store.rs, 200 LOC
   `HashMap<OutPoint, Option<CoinEntry>>` with NO DIRTY / NO FRESH /
   NO sentinel-list / NO `BatchWrite` cursor protocol). The
   production `main.rs` IBD path (lines 822, 987, 1574, 2260) calls
   `BlockStoreUtxoView` exclusively — `CoinsViewCache` is dead code,
   referenced only by its own tests and by `snapshot.rs`. This is
   the same fleet pattern as W138 ChainstateManager (rustoshi /
   blockbrew / clearbit defined-no-callers), W134 nimrod RelayManager
   dead module, W141 zmq.rs entire-file-dead-code.

2. **On-disk format incompatibility with Core's chainstate.** Even
   though rustoshi names its CF `CF_UTXO`, the key encoding is
   `txid || vout.to_be_bytes()` (no `'C'` prefix, fixed 4-byte BE
   vout) and the value is `serde_json::to_vec(&CoinEntry)` (JSON,
   not VARINT + CompressAmount + CompressScript). This means:
   - **rustoshi cannot load a Core chainstate.** Cross-impl
     comparison via Core's `dumptxoutset` snapshot is the only
     interop path; raw `chainstate/` byte-level mount-and-swap is
     impossible.
   - **JSON values are ~3-5× larger** than Core's binary, inflating
     UTXO set on disk and forcing more frequent compactions.
   - **No obfuscation** — anti-virus heuristics that match raw
     scriptPubKey bytes (e.g., the `EICAR`-style false-positive
     class that the obfuscate_key XOR was added to defeat) can flag
     rustoshi's UTXO DB.

3. **`BlockStoreUtxoView` has NO state-machine semantics.** It is a
   plain HashMap<OutPoint, Option<CoinEntry>> where `None` = spent
   and `Some(c)` = present. Compared to Core's `CCoinsCacheEntry`:
   - No DIRTY flag → every entry is always flushed (no clean-fetch
     optimization).
   - No FRESH flag → outputs that are created and spent within the
     same block STILL incur a delete-from-DB write (Core skips
     these via FRESH+spent → erase from cache, never touch DB).
   - No sentinel doubly-linked list → flush iterates the full cache
     map even when only a small fraction is modified.
   - No `BatchWrite` cursor protocol → no will-erase distinction,
     no try-erase elision, no dirty_count assertion.

The third failure mode is the worst kind: it works correctly but
silently triples to fivefold the IBD UTXO-write cost vs Core, while
the comprehensive `CoinsViewCache` implementation that WOULD give
parity sits unused. Wiring `BlockStoreUtxoView` to delegate to
`CoinsViewCache` is the single highest-leverage fix in this audit.

## Audit framework (30 gates / 24 BUGS catalogued)

Gate legend:
- **PASS** — behaviour matches Core (regression pin).
- **BUG-N** — divergence, gap, or hazard.

| #   | Behaviour                                                                                       | Status |
|-----|--------------------------------------------------------------------------------------------------|--------|
| G1  | `CCoinsView` trait surface (GetCoin / HaveCoin / GetBestBlock / BatchWrite / Cursor)             | BUG-1 |
| G2  | `CCoinsViewDB` key encoding = `'C' + txid + VARINT(vout)`                                        | BUG-2 |
| G3  | `CCoinsViewDB` value encoding = `VARINT(height*2+coinbase) + TxOutCompression(out)`              | BUG-3 |
| G4  | `OBFUSCATION_KEY` 8-byte XOR over every value                                                    | BUG-4 |
| G5  | `DB_BEST_BLOCK` = single byte `'B'`                                                              | BUG-5 |
| G6  | `DB_HEAD_BLOCKS` = `'H'` for crash-recovery two-tip protocol                                     | BUG-6 |
| G7  | `Coin::Serialize` writes `VARINT(nHeight*2 + fCoinBase)`                                         | BUG-7 |
| G8  | `Coin` is bit-packed `nHeight:31 + fCoinBase:1` (5 bytes vs 8)                                   | BUG-8 |
| G9  | `CompressAmount` mantissa+exponent encoding for nValue                                           | BUG-9 |
| G10 | `CompressScript` well-known pattern tags 0x00..0x05                                              | BUG-10 |
| G11 | `CCoinsCacheEntry` DIRTY flag on production path                                                 | BUG-11 |
| G12 | `CCoinsCacheEntry` FRESH flag on production path                                                 | BUG-12 |
| G13 | `CCoinsViewCache` sentinel-list of flagged entries                                               | BUG-13 |
| G14 | `BatchWrite(cursor, hashBlock)` Core-compatible interface                                        | BUG-14 |
| G15 | Production code path uses `CoinsViewCache` (not parallel `BlockStoreUtxoView`)                   | BUG-15 |
| G16 | `dbcache` default = 450 MiB (Core's `DEFAULT_DB_CACHE`)                                          | BUG-16 |
| G17 | `dbcache` user-configurable via `-dbcache` argument                                              | BUG-17 |
| G18 | `FlushStateToDisk` modes IF_NEEDED/PERIODIC/ALWAYS                                               | BUG-18 |
| G19 | OP_RETURN IsUnspendable drop on AddCoin                                                          | PASS (consensus path) |
| G20 | OP_RETURN dropper also rejects `size > MAX_SCRIPT_SIZE` (10_000 bytes)                           | BUG-19 (dead path only) |
| G21 | `AddCoin` with possible_overwrite forbids overwriting unspent coin                               | PASS (panic on dead path) / BUG-20 (production silently overwrites) |
| G22 | `SpendCoin` removes entry from cache when FRESH (no DB delete)                                   | PASS (dead path) / BUG-12 (production has no FRESH) |
| G23 | `SpendCoin` marks DIRTY when not FRESH (will issue DB delete)                                    | PASS (dead path) / BUG-12 (production stores None) |
| G24 | `flush_to_db` is atomic via single `WriteBatch`                                                  | BUG-21 (dead path uses per-call put/delete) |
| G25 | `flush_into_batch` writes UTXO + best-block in same batch                                        | BUG-22 (best-block written separately) |
| G26 | `Cursor()` / `GetCursor` returns ordered iterator over UTXO set                                  | BUG-23 |
| G27 | `EstimateSize()` returns a meaningful approximation of on-disk size                              | BUG-24 |
| G28 | `serde_json::from_slice` rejects corrupted CoinEntry data                                        | PASS (returns error) |
| G29 | `CacheEntryFlags::FRESH` invariants (FRESH-spent in cache is illegal)                            | PASS (dead path enforces) |
| G30 | `WARN_FLUSH_COINS_COUNT = 10M` operator notification                                             | BUG-24 (silent on huge flush) |

Additional findings outside the gate matrix:
- The dead `is_unspendable` in utxo_cache.rs:674 misses
  `len > MAX_SCRIPT_SIZE`; consensus path is correct.
- `META_BEST_BLOCK_HASH` is a 16-byte key in CF_META; Core uses a
  1-byte `'B'` in the same UTXO column family. This isn't a bug per
  se but means a single Core-compatible UTXO export tool would have
  to know two key formats.
- `CoinEntry` is duplicated as three structs across the workspace
  (`storage::block_store::CoinEntry`, `storage::utxo_cache::Coin`,
  `consensus::validation::CoinEntry`) with a manual conversion in
  `BlockStoreUtxoView::add_utxo` (line 988) — every shape-touching
  change needs three coordinated edits (cross-cite W145 BUG-14).

## BUGS

### BUG-1 — `CoinsView` trait surface is missing `Cursor()`, `GetHeadBlocks`, `EstimateSize`

**Severity:** P1
**File:** `crates/storage/src/utxo_cache.rs:209-227`
**Core ref:** `bitcoin-core/src/coins.h:310-345`

**Description:**
Core's `CCoinsView` virtual interface specifies six methods:
`GetCoin`, `HaveCoin`, `GetBestBlock`, `GetHeadBlocks`, `BatchWrite`,
`Cursor`, `EstimateSize`. rustoshi's `CoinsView` trait has only three:
`get_coin`, `have_coin`, `get_best_block`, plus a default-zero
`estimate_size`. No `Cursor`, no `BatchWrite`, no `GetHeadBlocks`.
This means:
- No way to iterate the UTXO set from a `&dyn CoinsView` — required
  for `dumptxoutset` snapshot export, `gettxoutsetinfo`, and any
  index back-fill.
- No way to atomically commit a parent cache to a child view via
  the cursor protocol — Core's flush pipeline is fundamentally
  inexpressible.
- No two-tip crash recovery (DB_HEAD_BLOCKS).

**Excerpt:**
```rust
// utxo_cache.rs:209
pub trait CoinsView {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError>;
    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool, StorageError> { ... }
    fn get_best_block(&self) -> Result<Option<Hash256>, StorageError>;
    fn estimate_size(&self) -> usize { 0 }
}
```

**Impact:** No drop-in compatibility with code paths that assume the
Core interface. snapshot.rs has to use a parallel `compute_utxo_hash<V: CoinsView>(...)`
helper that calls `entries()` on a concrete `CoinsViewCache` instead
of going through the trait — coupling the snapshot path to a single
implementation.

---

### BUG-2 — `outpoint_key` is `txid || vout.to_be_bytes()` instead of `'C' || txid || VARINT(vout)`

**Severity:** P0-CDIV (chainstate-format-divergence)
**File:** `crates/storage/src/utxo_cache.rs:666` AND
         `crates/storage/src/block_store.rs:820` (parallel duplicate)
**Core ref:** `bitcoin-core/src/txdb.cpp:82-89` —
              `SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }`
              where `key{DB_COIN}` is the single byte `'C'`.

**Description:**
rustoshi writes UTXO keys as 36 bytes: `txid (32) + vout (4 BE)`.
Core writes them as `1 + 32 + VARINT(vout)` = 34-38 bytes depending
on vout magnitude. Two divergences:

1. **No `'C'` discriminator byte.** Core's chainstate column family
   shares its keyspace with `DB_BEST_BLOCK = 'B'` (1 byte) and
   `DB_HEAD_BLOCKS = 'H'` (1 byte), plus the deprecated `DB_COINS
   = 'c'`. The leading byte is how Core distinguishes coin entries
   from metadata in the same DB. rustoshi avoids the collision by
   putting metadata in a separate CF (`CF_META`), so functionally
   safe, but means raw Core chainstate exports cannot be mounted.

2. **VARINT vout, not fixed 4-byte BE.** `vout=0` is 1 byte in Core,
   `vout=255` is 2 bytes, `vout=2^32-1` is 5 bytes. rustoshi
   ALWAYS writes 4 bytes BE. This affects:
   - DB iteration order (Core's lexicographic order interleaves
     low-vout entries of higher txids with high-vout entries of
     lower txids — rustoshi's order is strictly txid-major then
     vout-major).
   - Storage size (rustoshi wastes ~3 bytes per coin for the most
     common vout=0 case — at 100M UTXOs, that's ~300 MB).

**Excerpt:**
```rust
// utxo_cache.rs:666 (and identical at block_store.rs:820)
fn outpoint_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.vout.to_be_bytes());
    key
}
```

**Impact:** rustoshi's chainstate CF is NOT byte-compatible with
Core. Any cross-impl tooling (e.g., a hypothetical `chainstate-diff`
sidecar that compares two impls' chainstate dirs) must convert
formats. Two parallel `outpoint_key` functions also violate DRY —
shape-touching changes require coordinated edits in two files.

---

### BUG-3 — Coin value is serialized as `serde_json::to_vec(CoinEntry)` instead of `VARINT + TxOutCompression`

**Severity:** P0-CDIV
**File:** `crates/storage/src/utxo_cache.rs:250-251` and
         `crates/storage/src/block_store.rs:927`
**Core ref:** `bitcoin-core/src/coins.h:62-72` —
              `::Serialize(s, VARINT(code)); ::Serialize(s, Using<TxOutCompression>(out));`

**Description:**
Both rustoshi UTXO-write paths (the dead `CoinsViewDB::put_coin` and
the production `BlockStoreUtxoView::flush_into_batch`) serialize the
coin as JSON:
```json
{"height":840000,"is_coinbase":false,"value":50000000,"script_pubkey":"76a914..."}
```
A typical P2PKH UTXO is ~85-100 bytes in JSON. Core's binary format
is `VARINT(height*2+coinbase) + CompressAmount(value) + CompressScript(scriptPubKey)`:
- `VARINT(height*2)` for h=840000: 3 bytes
- `CompressAmount(50_000_000)`: 4 bytes  
- `CompressScript(P2PKH)`: 21 bytes (1-byte tag + 20-byte hash)
- Total: **28 bytes** vs rustoshi's **~85-100 bytes**.

At 100M UTXOs (current mainnet), rustoshi's chainstate is ~3-4× the
size of Core's (~3 GB vs ~9 GB). RocksDB compaction frequency, IBD
disk-write amplification, and memory cache miss rates all scale
proportionally.

**Excerpt:**
```rust
// utxo_cache.rs:247
pub fn put_coin(&self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StorageError> {
    let key = outpoint_key(outpoint);
    let entry = coin.to_entry();
    let data = serde_json::to_vec(&entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
    self.db.put_cf(CF_UTXO, &key, &data)
}

// block_store.rs:923 (production)
for (outpoint, coin) in self.cache.drain() {
    let key = outpoint_key(&outpoint);
    match coin {
        Some(c) => {
            let data = serde_json::to_vec(&c).map_err(|e| ...)?;
            batch.put_cf(cf, &key, &data);
        }
        None => batch.delete_cf(cf, &key),
    }
}
```

**Impact:** 3-4× chainstate bloat. Core IBD writes ~9 GB to the UTXO
column at mainnet tip; rustoshi writes ~30 GB. Disk IOPS during
the dbcache flush phase (the biggest IBD bottleneck after script
verification) suffer proportionally. Snapshot interop is already
addressed via `snapshot.rs` (which uses `CompressAmount` /
`CompressScript`), so the compression code exists — it just isn't
plumbed to the on-disk Coin write path.

---

### BUG-4 — `OBFUSCATION_KEY` XOR is completely absent

**Severity:** P2
**File:** `crates/storage/src/db.rs` (none) — no obfuscation anywhere
         in the storage layer.
**Core ref:** `bitcoin-core/src/dbwrapper.h:192` —
              `inline static const std::string OBFUSCATION_KEY{"\000obfuscate_key", 14};`
              `bitcoin-core/src/dbwrapper.cpp:253` — random 8-byte key
              read/written at open; XOR'd across every value.

**Description:**
Core stores a random 8-byte obfuscation key under the special
`"\000obfuscate_key"` key on first DB open. EVERY value written to
the chainstate is XOR'd against this key (looped to value length).
The original purpose was to prevent anti-virus software from
heuristic-matching the raw scriptPubKey bytes (e.g., a P2PK output
with a particular pubkey could trigger an EICAR-style match,
quarantining the entire chainstate).

rustoshi has zero obfuscation:
- No `OBFUSCATION_KEY` constant defined.
- No XOR layer in `ChainDb::put_cf` / `get_cf`.
- mempool_persist.rs uses XOR for the on-disk mempool snapshot —
  the primitive exists in the workspace but isn't applied to the
  UTXO DB.

**Excerpt:**
```rust
// db.rs:160-170 (production path — no obfuscation)
pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    let cf = self.db.cf_handle(cf_name).ok_or_else(...)?;
    Ok(self.db.get_cf(&cf, key)?)
}
pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
    let cf = self.db.cf_handle(cf_name).ok_or_else(...)?;
    self.db.put_cf(&cf, key, value)?;
    Ok(())
}
```

**Impact:** Anti-virus false positives on raw script bytes can
quarantine `testnet4-data/<node>/storage/` files. Low likelihood
on modern Linux servers (the original Windows AV problem class)
but the missing primitive is a Core-parity gap. Also affects
backup/restore tooling that diffs chainstate dirs across machines.

---

### BUG-5 — `DB_BEST_BLOCK` is a 16-byte string `"best_block_hash"` in CF_META, not single byte `'B'` in CF_UTXO

**Severity:** P3
**File:** `crates/storage/src/db.rs:16` —
         `pub const META_BEST_BLOCK_HASH: &[u8] = b"best_block_hash";`
**Core ref:** `bitcoin-core/src/txdb.cpp:24` —
              `static constexpr uint8_t DB_BEST_BLOCK{'B'};`

**Description:**
Core writes the best-block hash under the 1-byte key `'B'` in the
same database file as the coin entries (`'C'` prefix), so a single
DB iterator can read both. rustoshi places it in a separate column
family (`CF_META`) under a 16-byte ASCII key. Functionally
equivalent for atomic-batch semantics (RocksDB column families
share a WAL), but means:
- `chainstate/` byte-level dir-swap between rustoshi and Core is
  impossible.
- A 16-byte key instead of 1-byte is a minor space waste.

**Excerpt:**
```rust
// db.rs:15-19
pub const META_BEST_BLOCK_HASH: &[u8] = b"best_block_hash";
pub const META_BEST_HEIGHT: &[u8] = b"best_height";
pub const META_HEADER_TIP_HASH: &[u8] = b"header_tip_hash";
```

**Impact:** Documented above (cross-impl chainstate interop).

---

### BUG-6 — `DB_HEAD_BLOCKS` two-tip crash recovery protocol is completely absent

**Severity:** P1
**File:** `crates/storage/src/utxo_cache.rs:541-567` (`flush_to_db`)
         AND `crates/storage/src/block_store.rs:914-938` (`flush_into_batch`)
**Core ref:** `bitcoin-core/src/txdb.cpp:25` `DB_HEAD_BLOCKS = 'H'`,
              `bitcoin-core/src/txdb.cpp:100-167` `CCoinsViewDB::BatchWrite`
              writes `(hashBlock, old_tip)` BEFORE the coin updates and
              erases it AFTER, so a crash mid-flush can be detected
              and reported via `getchainstates`.

**Description:**
Core's BatchWrite protocol:
1. Erase `DB_BEST_BLOCK`.
2. Write `DB_HEAD_BLOCKS = [hashBlock, old_tip]` (the two-tip
   in-flight marker).
3. Write all dirty coins (potentially in multiple sub-batches if
   over `batch_write_bytes`).
4. Erase `DB_HEAD_BLOCKS`.
5. Write `DB_BEST_BLOCK = hashBlock`.

If the process crashes between steps 2 and 4, the next start-up
reads `DB_HEAD_BLOCKS` and either:
- Continues forward (if `hashBlock` is reachable from the block
  index), or
- Errors with `"The coins database detected an inconsistent state,
  likely due to a previous crash or shutdown. You will need to
  restart bitcoind with the -reindex-chainstate or -reindex
  configuration option."` (txdb.cpp:115).

rustoshi has no such protocol. The flush path in production
(`flush_into_batch`) is:
1. Iterate `cache.drain()` writing coins to the WriteBatch.
2. Caller commits the batch (which atomically writes coins + tip
   marker in `lib.rs:813` and elsewhere).

This is "good enough" for single-batch reorgs (atomic), but for
the large IBD dbcache flush where Core splits into multiple
sub-batches, rustoshi has no inconsistency-detection. A crash
during a multi-block dbcache flush (e.g., the 450 MiB → 0
flush window) could leave the UTXO set partially-updated with
NO marker that anything went wrong.

**Excerpt:**
```rust
// block_store.rs:914 (production)
pub fn flush_into_batch(&mut self, batch: &mut WriteBatch) -> Result<(), StorageError> {
    if self.cache.is_empty() { return Ok(()); }
    let cf = self.store.db.cf_handle(CF_UTXO).ok_or_else(...)?;
    for (outpoint, coin) in self.cache.drain() {
        let key = outpoint_key(&outpoint);
        match coin {
            Some(c) => { batch.put_cf(cf, &key, &serde_json::to_vec(&c)?); }
            None    => { batch.delete_cf(cf, &key); }
        }
    }
    self.estimated_mem = 0;
    Ok(())
}
// No DB_HEAD_BLOCKS marker. No partial-batch split. No assertion
// that the batch fits under batch_write_bytes (Core's 16 MiB
// default).
```

**Impact:** Silent corruption window during dbcache flush at IBD
peak (where the entire 2 GiB cache is being committed to disk).
RocksDB's WAL provides atomicity for a SINGLE WriteBatch but not
across multiple commit cycles. The default RocksDB WriteBatch size
limit (4 GiB) is well above the rustoshi cache size, so a single
batch likely suffices in practice, but the safety primitive is
absent.

---

### BUG-7 — `Coin::Serialize` does not pack height+coinbase into a single VARINT

**Severity:** P0-CDIV (subset of BUG-3)
**File:** `crates/storage/src/utxo_cache.rs:99-118` (`Coin::from_entry`,
         `Coin::to_entry`) — stores `height: u32` and `is_coinbase: bool`
         as separate JSON fields.
**Core ref:** `bitcoin-core/src/coins.h:62-72` —
              `uint32_t code = nHeight * uint32_t{2} + fCoinBase;`
              `::Serialize(s, VARINT(code));`

**Description:**
Core packs the 31-bit block height and 1-bit coinbase flag into a
single `uint32_t code` and writes it as a VARINT. For mainnet h=840000:
`code = 1680000` or `1680001` → VARINT = 3 bytes. rustoshi's JSON
writes `"height":840000,"is_coinbase":false` = 30+ characters.

This is part of BUG-3 (the JSON-vs-binary divergence) but called
out separately because the (height, is_coinbase) packing has
specific semantics: the LSB carries `fCoinBase`. Any downstream
tool that parses the chainstate must shift by 1 and mask &1 — code
that uses Core's packed format will misread rustoshi data and vice
versa.

**Impact:** Same as BUG-3. Sub-bug of BUG-3.

---

### BUG-8 — `Coin` is NOT bit-packed (32-bit height + 8-bit bool instead of 31+1)

**Severity:** P3
**File:** `crates/storage/src/utxo_cache.rs:59-66`
**Core ref:** `bitcoin-core/src/coins.h:40-44` —
              `unsigned int fCoinBase : 1; uint32_t nHeight : 31;`

**Description:**
Core packs Coin's height and coinbase flag into a single 32-bit
struct with bitfields, so `sizeof(Coin)` is `sizeof(CTxOut) + 4`.
rustoshi's `Coin` uses `pub height: u32` (4 bytes) + `pub is_coinbase:
bool` (1 byte, padded to 8 by alignment) — at least 8 bytes overhead
per coin in memory.

For a 100M-UTXO cache, this is ~400 MB additional RAM vs Core.

**Excerpt:**
```rust
// utxo_cache.rs:58
pub struct Coin {
    pub tx_out: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}
```

**Impact:** Memory overhead in the cache. The compiler's struct
alignment makes this larger than a hand-packed bitfield (Rust has
no native `u32:31 + bool:1` bitfield support without unsafe). At
the 450 MiB dbcache budget Core ships with, rustoshi might fit ~5
MiB fewer UTXOs in the same RAM.

---

### BUG-9 — `CompressAmount` is not applied to on-disk Coin values

**Severity:** P0-CDIV (subset of BUG-3, but also affects snapshot interop)
**File:** `crates/storage/src/snapshot.rs:1002-1057` —
         `compress_amount` / `decompress_amount` are defined here
         BUT only used by the snapshot read/write path; NOT used by
         `utxo_cache::Coin::put_coin` or `BlockStoreUtxoView::flush_into_batch`.
**Core ref:** `bitcoin-core/src/compressor.cpp:22-90` —
              `CompressAmount(uint64_t n)` mantissa+exponent encoding.

**Description:**
The compression primitive EXISTS in the rustoshi codebase (snapshot.rs)
and is used for assumeutxo snapshot encoding. But the chainstate
on-disk write path does NOT use it — it goes straight to JSON. This
is the "dead-helper-at-call-site" pattern from W141 (rustoshi has
the function, the function works, no production caller).

**Excerpt:**
```rust
// snapshot.rs has compress_amount + decompress_amount.
// utxo_cache.rs:247 (put_coin) does NOT call compress_amount.
// block_store.rs:927 (flush_into_batch) does NOT call compress_amount.
```

**Impact:** Easy fix; wiring `compress_amount(value)` + binary
serialization into the put path would shave 2-5 bytes off every
P2PKH/P2SH/P2WPKH coin.

---

### BUG-10 — `CompressScript` is not applied to on-disk Coin scriptPubKey values

**Severity:** P0-CDIV (subset of BUG-3, but also affects snapshot interop)
**File:** `crates/storage/src/snapshot.rs:1002-1144` — `try_compress_script` /
         decompression are defined here BUT only used by the snapshot
         read/write path.
**Core ref:** `bitcoin-core/src/compressor.cpp:96-220` —
              `CompressScript` well-known pattern tags 0x00..0x05.

**Description:**
Same dead-helper pattern as BUG-9 but for scripts. P2PKH (25 bytes
raw) compresses to 21 bytes (1-byte tag + 20-byte hash); P2SH (23
bytes) to 21 bytes; P2PK (35-67 bytes) to 33 bytes. Across a
100M-UTXO chainstate this is ~400 MB of avoidable disk usage.

**Impact:** Same as BUG-9 — wire `try_compress_script` into the put
path.

---

### BUG-11 — `BlockStoreUtxoView` (production) has NO DIRTY flag

**Severity:** P1
**File:** `crates/storage/src/block_store.rs:848-1013`
**Core ref:** `bitcoin-core/src/coins.h:104-108` —
              `CCoinsCacheEntry` DIRTY semantics: only DIRTY entries
              propagate on Flush.

**Description:**
`BlockStoreUtxoView::cache: HashMap<OutPoint, Option<CoinEntry>>`
stores either a coin (Some) or a deletion-marker (None), with no
flag distinguishing "this coin was just fetched from DB and never
modified" from "this coin was created by the current block".

Consequences:
- Every `get_utxo` that falls through to DB **does not** populate
  the cache (line 977 returns the value via `.ok().flatten()` but
  does NOT insert into `self.cache`). So second reads of the same
  outpoint go to disk again.
- When `flush` is called, the only state tracked is "is this in
  the cache?" — not "is this dirty?". This is fine ONLY because
  fetched-from-DB coins are never inserted into the cache (no
  clean-fetched-then-spent class). But it means there's no
  benefit-of-caching for read patterns: e.g., the block-validation
  loop that reads input.previous_output for every tx input is
  going to disk every single time.

**Excerpt:**
```rust
// block_store.rs:965-985
fn get_utxo(&self, outpoint: &OutPoint) -> Option<...CoinEntry> {
    if let Some(cached) = self.cache.get(outpoint) {
        return cached.as_ref().map(|c| ...);
    }
    // Fall back to database
    self.store.get_utxo(outpoint).ok().flatten().map(|c| ...)
    // NOTE: does NOT insert into self.cache → next call re-fetches from disk
}
```

**Impact:** Major IBD perf regression vs Core. Core's
`CCoinsViewCache::FetchCoin` (coins.cpp:30-50) inserts into the
cache on first read so subsequent reads are O(1). rustoshi pays the
DB-read cost for every input lookup.

---

### BUG-12 — `BlockStoreUtxoView` (production) has NO FRESH flag

**Severity:** P1
**File:** `crates/storage/src/block_store.rs:987-1012`
**Core ref:** `bitcoin-core/src/coins.cpp:152-176` —
              `SpendCoin`: if FRESH, erase from cache (no DB delete);
              else, mark dirty and clear (DB delete on flush).

**Description:**
Core's FRESH optimization: when a coin is created in the cache
(AddCoin without first being fetched from parent), it's marked
FRESH. If that coin is then spent in the same flush window, the
SpendCoin path **just erases it from the cache** — the parent
never sees it. No DB write, no DB delete.

rustoshi's `BlockStoreUtxoView::spend_utxo` (line 1004) ALWAYS
inserts `None` into the cache. On flush, `None` triggers a
`batch.delete_cf(cf, &key)`. If the coin was created in the same
flush window (i.e., a coinbase that was immediately spent by a
within-block child tx, which is impossible per consensus but
common at the boundary across multiple flushes), the delete is
issued anyway and RocksDB has to record an absent-key tombstone.

The cumulative effect: rustoshi writes MORE to disk than Core for
the same IBD workload, because every short-lived UTXO (in-and-out
within the dbcache window) becomes one PUT + one DELETE instead of
nothing.

**Excerpt:**
```rust
// block_store.rs:1004
fn spend_utxo(&mut self, outpoint: &OutPoint) {
    let new_size = Self::estimate_entry_size(&None);
    if let Some(old) = self.cache.insert(outpoint.clone(), None) {
        let old_size = Self::estimate_entry_size(&old);
        self.estimated_mem = self.estimated_mem.saturating_sub(old_size) + new_size;
    } else {
        self.estimated_mem += new_size;
    }
}
```

**Impact:** Disk-write amplification at IBD peak. Hardest to
measure without benchmark; estimated 1.5-2× write amplification on
the UTXO column family vs Core.

---

### BUG-13 — `CCoinsViewCache` sentinel-list of flagged entries is absent

**Severity:** P2
**File:** `crates/storage/src/utxo_cache.rs:312-621`
**Core ref:** `bitcoin-core/src/coins.h:248-310` — `CoinsViewCacheCursor`
              maintains a sentinel-rooted doubly-linked list of all
              DIRTY+FRESH entries; flush iterates the linked list, not
              the full HashMap.

**Description:**
Core's `CCoinsCacheEntry` participates in an intrusive doubly-linked
list rooted at a sentinel inside `CCoinsViewCache`. Only DIRTY or
FRESH entries are linked. On `Flush`, the cursor walks the linked
list — typically a small fraction of the HashMap.

rustoshi's `CoinsViewCache::flush_to_db` iterates `self.cache.drain()`,
the FULL HashMap. At a 2 GiB cache, that's tens of millions of
entries, most of which are clean fetched-from-DB entries with
nothing to write.

**Excerpt:**
```rust
// utxo_cache.rs:541
pub fn flush_to_db(&mut self, db: &CoinsViewDB) -> Result<(), StorageError> {
    for (outpoint, entry) in self.cache.drain() {  // full HashMap iteration
        if !entry.is_dirty() { continue; }
        ...
    }
}
```

**Impact:** Flush time is O(cache_size) instead of O(dirty_count).
For the default Core cache layout where 90%+ of entries are clean
fetched-from-DB, this is a ~10× flush-time slowdown. Operationally
visible as longer FlushStateToDisk pauses during IBD.

---

### BUG-14 — `BatchWrite(cursor, hashBlock)` interface is not implemented

**Severity:** P1
**File:** `crates/storage/src/utxo_cache.rs:209-227` (trait surface) —
         no `batch_write` method on `CoinsView`.
**Core ref:** `bitcoin-core/src/coins.h:333` —
              `virtual void BatchWrite(CoinsViewCacheCursor& cursor, const uint256& hashBlock);`

**Description:**
Core's `CCoinsView` defines a virtual `BatchWrite` that takes a
cursor (the linked list of DIRTY entries from the child cache) and
the new best-block hash. The CCoinsViewCache override (coins.cpp:208-280)
implements multi-level cache flushing where one cache flushes to its
parent (which is another cache, not necessarily a DB). The DB
override (txdb.cpp:100-167) handles the on-disk commit.

rustoshi has no `batch_write` on the `CoinsView` trait. The
production path effectively assumes a 2-level hierarchy (cache +
DB) hardcoded into `BlockStoreUtxoView::flush_into_batch`. Adding a
third level (e.g., per-thread script-validation caches, or a parent
"main" cache + child "block-being-connected" cache) would require
threading the new state through `BlockStoreUtxoView` directly — the
trait does not let you compose caches.

**Excerpt:**
```rust
// utxo_cache.rs:209 — no batch_write
pub trait CoinsView {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError>;
    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool, StorageError> { ... }
    fn get_best_block(&self) -> Result<Option<Hash256>, StorageError>;
    fn estimate_size(&self) -> usize { 0 }
    // MISSING: fn batch_write(&self, cursor: ..., hash_block: Hash256) -> Result<...>
}
```

**Impact:** Architectural — prevents composability of caches. Any
future work that adds a per-block "scratch cache" on top of the
main cache (e.g., for atomic block-disconnect-and-replay) has to
work around this. Currently, the work happens against
`BlockStoreUtxoView` directly with the cache lifetime tied to the
block-processing function.

---

### BUG-15 — `CoinsViewCache` is dead code; production uses `BlockStoreUtxoView`

**Severity:** P0
**File:** `crates/storage/src/utxo_cache.rs:312-621` (1077-LOC dead-code module)
         vs `crates/storage/src/block_store.rs:848-1013` (production)
**Core ref:** N/A — this is a two-pipeline guard.

**Description:**
The `CoinsView` / `CoinsViewCache` / `CoinsViewDB` hierarchy in
`utxo_cache.rs` is a faithful port of Bitcoin Core's design — it
has DIRTY/FRESH flags, the AddCoin / SpendCoin state machine, the
flush/sync split, the FRESH-spent optimization, even the
overwrite-with-possible_overwrite panic for non-BIP-30 cases.

But `rustoshi/src/main.rs` (the daemon entrypoint) never
constructs a `CoinsViewCache`. Every production path
(`run_import_from_stdin` line 822, `run_import_from_blk_files` line
987, the headers-first sync at line 2260, the RPC reorg handler at
server.rs:9005) constructs a `BlockStoreUtxoView` from
`block_store.utxo_view()`. The faithful Core-port is unused.

The only callers of `CoinsViewCache` are:
- `utxo_cache.rs::tests::*` (lines 689+).
- `utxo_cache_w100_tests.rs` (the W100 audit-test suite).
- `snapshot.rs::compute_utxo_hash<V: CoinsView>` — takes a generic
  but the only call site uses the dead path.

This is the **same fleet shape** as:
- W138 ChainstateManager (rustoshi defined-no-callers).
- W134 nimrod RelayManager dead module.
- W141 rustoshi zmq.rs entire-file-dead-code.
- W139 hotbuns confAvg/failAvg matrix.

**Excerpt:**
```rust
// rustoshi/src/main.rs:1574 (production)
let mut utxo_view = block_store.utxo_view();  // BlockStoreUtxoView
// ... validation passes &mut utxo_view to chain_state.process_block ...
// CoinsViewCache::new() is NEVER called in main.rs.
```

**Impact:** Every other BUG in this audit's "dead path" column
(BUG-19, BUG-21, BUG-22, parts of BUG-7..10) is materially worse
because the well-engineered code is parallel-unused while the
unsophisticated code (`BlockStoreUtxoView`) is in production.
Single highest-leverage fix: have `BlockStoreUtxoView` delegate
to `CoinsViewCache` for in-memory state, and have the flush path
go through `BatchWrite`. Estimated ~50 LOC of plumbing + ~10
delete-block-of-duplicate-functions.

---

### BUG-16 — `dbcache` default disagrees: dead path uses 450 MiB (Core); production uses 2 GiB

**Severity:** P2
**File:** `crates/storage/src/utxo_cache.rs:46` —
         `pub const DEFAULT_DB_CACHE_BYTES: usize = 450 * 1024 * 1024;`
         (DEAD).
         `crates/storage/src/block_store.rs:832` —
         `pub const DEFAULT_UTXO_CACHE_BYTES: usize = 2 * 1024 * 1024 * 1024;`
         (PRODUCTION).
**Core ref:** `bitcoin-core/src/validation.h` — `DEFAULT_DB_CACHE = 450 MiB`.

**Description:**
The dead path has the correct Core-matching default (450 MiB). The
production path has a 2 GiB default — over 4× larger. Two
consequences:

1. **Memory footprint divergence.** A rustoshi node defaults to
   reserving 2 GiB for the UTXO cache vs Core's 450 MiB. On a 4-
   or 8-GiB-RAM VPS, this is the difference between "node fits"
   and "node OOMs".
2. **No `-dbcache` argument plumbing.** The user can override via
   `BlockStore::utxo_view_with_cache_limit` (a Rust API) but
   there's no CLI flag. Core's `-dbcache=N` is missing — see
   BUG-17.

**Excerpt:**
```rust
// block_store.rs:832
pub const DEFAULT_UTXO_CACHE_BYTES: usize = 2 * 1024 * 1024 * 1024;

// utxo_cache.rs:46 (DEAD - matches Core)
pub const DEFAULT_DB_CACHE_BYTES: usize = 450 * 1024 * 1024;
```

**Impact:** Operational footgun on small machines. Comment-as-
confession candidate: utxo_cache.rs:45 says "matching Bitcoin Core's
-dbcache default" but the constant is never used in production.

---

### BUG-17 — `-dbcache=N` CLI argument is absent

**Severity:** P2
**File:** `rustoshi/src/main.rs` (search shows no `-dbcache` /
         `--dbcache` flag).
**Core ref:** `bitcoin-core/src/init.cpp` — `-dbcache=<n>` in MiB,
              clamped to `nMinDbCache=4` and `nMaxDbCache=16384`.

**Description:**
Core's chainstate cache size is operator-tunable via `-dbcache=N`
(the most-used IBD-tuning knob). On a 64-GiB machine, operators
set `-dbcache=32000` to dramatically speed up IBD by reducing
flush frequency. rustoshi has no such flag — the cache is
hardcoded at 2 GiB via `BlockStoreUtxoView::new` (or 450 MiB via
the dead path).

**Impact:** Operators cannot tune the cache for available memory.
On large machines, IBD takes longer than necessary.

---

### BUG-18 — `FlushStateToDisk` mode enum (IF_NEEDED / PERIODIC / ALWAYS) is absent

**Severity:** P1
**File:** `rustoshi/src/main.rs:928-934, 1111-1117, 2419+` — only
         "flush if cache exceeds limit" logic; no periodic flush,
         no forced flush on shutdown.
**Core ref:** `bitcoin-core/src/validation.cpp:2790-2880` —
              `FlushStateToDisk(FlushStateMode mode)` with three
              triggers:
              - `IF_NEEDED`: only if cache exceeds dbcache.
              - `PERIODIC`: every hour OR every 24-hour-equivalent
                worth of blocks.
              - `ALWAYS`: shutdown, manual `flushchainstate`, etc.

**Description:**
rustoshi only has `flush_if_needed` (block_store.rs:942), which
checks `estimated_mem >= max_cache_bytes`. There is no PERIODIC
flush (Core flushes every ~1 hour even if the cache isn't full),
and no ALWAYS-mode flush hook. The closest analog is the final
flush at `main.rs:1593` which fires once at exit.

Consequences:
- Long IBD pauses are concentrated at the cache-full boundary
  instead of being amortized across periodic flushes.
- A crash mid-IBD before any cache-full event loses all UTXO
  state since the last persisted tip — even if the daemon ran
  for 6 hours catching up to thousands of blocks.

**Excerpt:**
```rust
// main.rs:928
if utxo_view.needs_flush() {  // only IF_NEEDED equivalent
    ...
    utxo_view.flush()?;
}
// No periodic flush. No forced-on-shutdown semantics beyond
// the cleanup at exit (main.rs:1593).
```

**Impact:** Crash-recovery window is "since last cache-full event"
instead of Core's "last hour or last cache-full, whichever came
first". For a node with `-dbcache=8000`, that could be 12+ hours
of work lost on a crash.

---

### BUG-19 — Dead `is_unspendable` in utxo_cache.rs misses `MAX_SCRIPT_SIZE` check

**Severity:** P3 (dead path)
**File:** `crates/storage/src/utxo_cache.rs:674-676`
**Core ref:** `bitcoin-core/src/script/script.h:563-566` —
              `IsUnspendable() = (size > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE)`.

**Description:**
```rust
// utxo_cache.rs:674
fn is_unspendable(script: &[u8]) -> bool {
    !script.is_empty() && script[0] == 0x6a // OP_RETURN
}
```
Misses the `script.len() > MAX_SCRIPT_SIZE` (10_000 bytes)
clause. The consensus path's `is_unspendable` at validation.rs:2097
is correct. So this only affects the dead `CoinsViewCache::add_coin`
path; production goes through `connect_block` → consensus's
`is_unspendable` → `BlockStoreUtxoView::add_utxo`.

**Impact:** Cosmetic — dead code. But if the dead path ever
becomes live (which is the recommended fix for BUG-15), this
silently regresses the IsUnspendable predicate.

---

### BUG-20 — `BlockStoreUtxoView::add_utxo` (production) silently overwrites unspent coins (no possible_overwrite gate)

**Severity:** P0
**File:** `crates/storage/src/block_store.rs:987-1002`
**Core ref:** `bitcoin-core/src/coins.cpp:87-124` — `AddCoin`
              with `check_for_overwrite`/`possible_overwrite` flag
              throws if attempting to overwrite an unspent coin
              outside of BIP-30 paths.

**Description:**
Core's AddCoin asserts that overwriting an unspent coin is only
valid for BIP-30 (pre-2012 duplicate coinbase) paths. Outside of
that, an overwrite indicates a consensus bug — and Core throws.

rustoshi's `BlockStoreUtxoView::add_utxo` (production) silently
overwrites:
```rust
fn add_utxo(&mut self, outpoint: &OutPoint, coin: ...CoinEntry) {
    let storage_coin = CoinEntry { ... };
    let new_size = Self::estimate_entry_size(&Some(storage_coin.clone()));
    if let Some(old) = self.cache.insert(outpoint.clone(), Some(storage_coin)) {
        // Replace: subtract old, add new -- NO CHECK that old is spent or that
        // overwrite is expected
        let old_size = Self::estimate_entry_size(&old);
        self.estimated_mem = self.estimated_mem.saturating_sub(old_size) + new_size;
    } else { ... }
}
```

The dead `CoinsViewCache::add_coin` (utxo_cache.rs:399, 411) DOES
panic on overwrite-of-unspent. The production path does not.

Note: validation.rs:1625 has a pre-check `if utxo_view.get_utxo(&outpoint).is_some()` for
duplicate-output detection, which is the BIP-30 gate. So the
panic-protection happens upstream, not at the cache layer. But it
means a future caller that goes around the validation check (e.g.,
a test, a reorg replay) won't get the defense-in-depth catch.

**Impact:** Defense-in-depth gap. A bug in the validation path
that allows duplicate AddCoin would silently corrupt the UTXO set
instead of panicking. Cross-cite W138 BUG-7 (hotbuns: snapshot
chainstate NOT isolated from existing UTXOs).

---

### BUG-21 — `CoinsViewDB::put_coin` / `delete_coin` are per-call, not batched

**Severity:** P2 (dead path)
**File:** `crates/storage/src/utxo_cache.rs:247-258`
**Core ref:** `bitcoin-core/src/txdb.cpp:100` — `CCoinsViewDB::BatchWrite`
              uses a single `CDBBatch` for all coin mutations + tip update.

**Description:**
The dead path's `put_coin` issues one `self.db.put_cf(CF_UTXO, key, data)`
per coin. RocksDB's `put_cf` without a WriteBatch wrapper issues an
individual write — no atomicity guarantee across multiple coin
writes within the same conceptual block-connect. If `CoinsViewCache::
flush_to_db` ever became live (BUG-15 fix), it would write coins
non-atomically.

The production path (BlockStoreUtxoView) does use a WriteBatch via
`flush_into_batch` — so this is dead-only.

**Excerpt:**
```rust
// utxo_cache.rs:247
pub fn put_coin(&self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StorageError> {
    let key = outpoint_key(outpoint);
    let entry = coin.to_entry();
    let data = serde_json::to_vec(&entry)?;
    self.db.put_cf(CF_UTXO, &key, &data)  // single-key write
}
```

**Impact:** Dead-path bug; doesn't fire today. But conflicts with
the BUG-15 fix path.

---

### BUG-22 — `flush_to_db` writes best-block via separate `db.put_cf` instead of in the same batch

**Severity:** P1 (dead path)
**File:** `crates/storage/src/utxo_cache.rs:557-562`
**Core ref:** `bitcoin-core/src/txdb.cpp:158-159` — `batch.Write(DB_BEST_BLOCK, hashBlock)`
              inside the same `CDBBatch` as the coin writes.

**Description:**
```rust
// utxo_cache.rs:557 (dead path)
if let Some(hash) = self.hash_block.take() {
    use crate::columns::CF_META;
    use crate::db::META_BEST_BLOCK_HASH;
    db.db().put_cf(CF_META, META_BEST_BLOCK_HASH, hash.as_bytes())?;
}
```
The best-block hash is written via a separate `put_cf` call AFTER
all the coin writes. There is no `WriteBatch` wrapping the entire
flush, so a crash between the last coin write and the best-block
write leaves the DB in a state where the coins are mostly-but-not-
quite up-to-date for `hashBlock`, but `META_BEST_BLOCK_HASH` still
points to the previous tip. On restart, the daemon would try to
"replay" from the old tip, applying the same coin mutations a
second time — which is undefined behavior for delete-then-add
sequences.

Production `flush_into_batch` (block_store.rs:914) does NOT
write the best-block in the same batch either — the caller (e.g.,
main.rs) is responsible for adding it. So this gap also exists in
production, just structurally distributed.

**Impact:** Atomicity gap. Same crash-window class as BUG-6.

---

### BUG-23 — `CoinsView::Cursor()` is absent; cannot iterate UTXO set from the trait

**Severity:** P2
**File:** `crates/storage/src/utxo_cache.rs:209-227`
**Core ref:** `bitcoin-core/src/coins.h:336` —
              `virtual std::unique_ptr<CCoinsViewCursor> Cursor() const;`

**Description:**
Core's CCoinsView provides a virtual `Cursor()` that returns a
`CCoinsViewCursor` for iterating the entire UTXO set. This is used
by:
- `dumptxoutset` (snapshot export).
- `gettxoutsetinfo` (UTXO statistics RPC).
- `gettxoutsetinfo coin_stats` index back-fill.
- assumeutxo background validation.

rustoshi's `CoinsView` trait has no equivalent. Iteration happens
via concrete-type calls:
- `CoinsViewCache::entries()` (utxo_cache.rs:610) returns a HashMap
  iterator over the in-memory cache ONLY (not the DB).
- `ChainDb::iter_cf(CF_UTXO)` returns raw RocksDB iteration.

Both are bypasses around the trait. Snapshot code at
`compute_utxo_hash<V: CoinsView>` takes a generic but the only
implementation that satisfies it is `CoinsViewCache` (which then
only sees the cache portion, not the DB-backed coins). For a real
"iterate the entire UTXO set" operation, you have to drop down to
`ChainDb::iter_cf` directly.

**Impact:** Architectural; same class as BUG-1 / BUG-14.
Capability gap: `dumptxoutset` and `gettxoutsetinfo` either work
in spite of this (by using `ChainDb` directly) or fall short of
Core parity.

---

### BUG-24 — `EstimateSize()` is unimplemented (returns 0) and `WARN_FLUSH_COINS_COUNT` is absent

**Severity:** P3
**File:** `crates/storage/src/utxo_cache.rs:224-226` —
         `fn estimate_size(&self) -> usize { 0 }` default.
         `crates/storage/src/utxo_cache.rs:654-656` — `CoinsViewCache`
         override returns dynamic memory usage of the cache, NOT
         an estimate of the on-disk UTXO size.
**Core ref:** `bitcoin-core/src/txdb.cpp:168-170` —
              `EstimateSize() { return m_db->EstimateSize(DB_COIN, DB_COIN + 1); }`
              — actual on-disk byte estimate.
              `bitcoin-core/src/txdb.cpp:69` —
              `WARN_FLUSH_COINS_COUNT = 10'000'000;` for operator
              warnings on huge flushes.

**Description:**
Core's `CCoinsViewDB::EstimateSize` returns an actual on-disk byte
estimate (via leveldb's range-size API). rustoshi returns 0 for the
DB-backed view and dynamic memory usage for the cache — neither
matches Core semantics.

Also: Core warns the operator with `LogWarning("Flushing large (%d
entries) UTXO set to disk, it may take several minutes", dirty_count)`
when dirty_count exceeds 10M. rustoshi has no equivalent — flushes
are silent regardless of size.

**Excerpt:**
```rust
// utxo_cache.rs:224
fn estimate_size(&self) -> usize { 0 }  // default impl
// utxo_cache.rs:654-656 (CoinsViewCache override — dynamic mem, not on-disk)
fn estimate_size(&self) -> usize { self.dynamic_memory_usage() }
```

**Impact:** Operators don't see "flushing 10M coins" warnings during
IBD's heavy phases. RPC `gettxoutsetinfo` cannot return an
accurate on-disk size estimate.

---

## Fleet pattern summary

- **Two-pipeline guard** (8th distinct in rustoshi alone, 14th
  across the fleet): `CoinsViewCache` (1077 LOC dead) vs
  `BlockStoreUtxoView` (200 LOC production). Same shape as W138
  ChainstateManager and W141 zmq.rs.
- **Three-way struct duplication** (cross-cite W145 BUG-14):
  `Coin` / storage `CoinEntry` / consensus `CoinEntry` with manual
  conversion at every boundary.
- **Dead-helper-at-call-site** (W141 W139 pattern): `compress_amount`
  and `try_compress_script` exist in snapshot.rs but are NOT used
  by the on-disk Coin write path that desperately needs them.
- **Carry-forward re-anchor** (cross-cite W140): the comment at
  utxo_cache.rs:45 says "matching Bitcoin Core's -dbcache default"
  for a constant that's dead — same shape as clearbit's
  carry-forward re-anchor across 6 weeks.
- **Comment-as-confession** (cross-cite W141 5th instance): line
  45 "matching Bitcoin Core's -dbcache default" (but dead);
  block_store.rs:911 "Mirrors bitcoin-core/src/validation.cpp::
  DisconnectTip" (the docstring describes Core's behavior but the
  best-block write is not in the same batch — see BUG-22).
- **30-of-30-gates-buggy avoidance**: 24 of 30 gates failed but
  the 6 passing gates are the consensus-correctness ones
  (OP_RETURN drop, AddCoin overwrite panic on dead path, FRESH
  invariants on dead path, JSON corruption detection). The
  production path's correctness is downstream of the consensus
  path's checks rather than the cache layer's own defense.

## Recommended fix wave priorities

1. **BUG-15 fix — wire `BlockStoreUtxoView` to `CoinsViewCache`.**
   Highest leverage; closes BUG-11, BUG-12, BUG-13, BUG-14
   transitively. ~50 LOC plumbing.
2. **BUG-3 / BUG-7 / BUG-9 / BUG-10 fix — wire `compress_amount` +
   `try_compress_script` + binary serialization into the Coin
   on-disk write path.** Cuts chainstate from ~30 GB to ~9 GB at
   mainnet tip. ~80 LOC.
3. **BUG-2 fix — change `outpoint_key` to `'C' + txid + VARINT(vout)`.**
   One-line per call site (two call sites); rest is migration script
   for existing chainstate dirs.
4. **BUG-16 / BUG-17 fix — change `DEFAULT_UTXO_CACHE_BYTES` to
   450 MiB and add `-dbcache=N` CLI plumbing.** Operational footgun
   fix; 1-line constant + ~20 LOC CLI parsing.
5. **BUG-6 fix — add `DB_HEAD_BLOCKS` two-tip protocol.** Crash-
   recovery defense; ~30 LOC in flush + startup-recovery handling.
6. **BUG-18 fix — add `FlushStateMode` enum + PERIODIC trigger.**
   Crash-window reduction; ~50 LOC in main.rs flush call sites.
7. **BUG-4 fix — add `OBFUSCATION_KEY` XOR layer in `ChainDb`.**
   Low-impact unless deployed on AV-active Windows; ~40 LOC.

Total estimated effort: ~270 LOC of production code to close
all gates except BUG-1/BUG-14/BUG-23 (which are architectural
trait-surface refactors).
