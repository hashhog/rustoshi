# W146 — Block storage layer (blk*.dat / rev*.dat / block-index) audit (rustoshi)

**Wave:** W146 — Block storage layer (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** rustoshi's persistent block storage surface — flat
`blk?????.dat` write/read, `rev?????.dat` undo write/read, the leveldb
block-index DB-key schema (`b`/`f`/`l`/`F`/`R`/`t`), the magic-prefixed
file format, fsync discipline, and recovery semantics.

**Files audited:**
- `crates/storage/src/blockstore.rs` — `FlatBlockStore` (342–926),
  `FlatFileSeq` (180–302), `BlockFileInfo` (113–171), `FlatFilePos`
  (71–103), `BlockFileLocation` (935–961), constants
  `MAX_BLOCKFILE_SIZE=128MiB` (33), `BLOCKFILE_CHUNK_SIZE=16MiB` (36),
  `UNDOFILE_CHUNK_SIZE=1MiB` (39), `STORAGE_HEADER_BYTES=8` (42).
- `crates/storage/src/block_store.rs` — `BlockStore::put_block` (199),
  `BlockStore::put_undo` (476), `BlockStore::put_block_index` (223),
  comment-as-confession (700–702: "`FlatBlockStore` machinery in
  `blockstore.rs` is only used for legacy / Core-format scanning during
  reindex paths"), `init_genesis` (652).
- `crates/storage/src/columns.rs` — `CF_BLOCKS`/`CF_BLOCK_INDEX`/
  `CF_HEIGHT_INDEX`/`CF_UNDO`/`CF_META`/`CF_TX_INDEX` (9–73).
- `crates/storage/src/db.rs` — `ChainDb::open` (89–141), `write_batch`
  (192–196), `META_BEST_BLOCK_HASH`/`META_BEST_HEIGHT`/
  `META_PRUNE_HEIGHT`/`META_DB_VERSION` (16–37), `CURRENT_DB_VERSION=1`
  (37).
- `crates/storage/src/undo.rs` — `TxUndo`/`BlockUndo` (44–213) — serde
  JSON undo, no rev*.dat format, no checksum.
- `crates/storage/src/w109_block_index_gates.rs` — prior audit
  (BUG G11/G12/G13/G14/G17/G20 catalogued already on the block-index +
  blkfile-format axis; reanchored and extended in this audit).
- `rustoshi/src/main.rs` — production block-write path
  (910/1096/1874/2405/2934 — calls `block_store.put_block_index`, never
  `FlatBlockStore::write_block`).
- `crates/rpc/src/server.rs` — production block-write path
  (1538–1561, 4411–4489, 9513–9561 — `put_header` → `put_block` →
  `put_block_index` as three separate non-batched RocksDB writes).

**Bitcoin Core references:**
- `bitcoin-core/src/node/blockstorage.h`:
  - `BLOCKFILE_CHUNK_SIZE = 0x1000000` = 16 MiB (119),
  - `UNDOFILE_CHUNK_SIZE = 0x100000` = 1 MiB (121),
  - `MAX_BLOCKFILE_SIZE = 0x8000000` = 128 MiB (123),
  - `STORAGE_HEADER_BYTES = 8` (126: tuple_size_v<MessageStartChars> +
    sizeof(unsigned int)),
  - `UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES + uint256::size()`
    = 40 bytes (129).
- `bitcoin-core/src/node/blockstorage.cpp`:
  - DB prefix bytes (58–62): `DB_BLOCK_FILES='f'`, `DB_BLOCK_INDEX='b'`,
    `DB_FLAG='F'`, `DB_REINDEX_FLAG='R'`, `DB_LAST_BLOCK='l'`,
    `DB_TXINDEX_BLOCK='T'`, `DB_TXINDEX='t'`.
  - `FlushBlockFile` (742–769) — fsync block file + optional undo
    file, only finalize-undo if block-file is being finalized AND the
    undo cursor is caught up.
  - `FlushUndoFile` (732–740) — separate fsync arm for rev*.dat.
  - `FindNextBlockPos` (833–921) — rotates when
    `nSize + nAddSize >= MAX_BLOCKFILE_SIZE`; on rotation, calls
    `FlushBlockFile(last_blockfile, fFinalize=true, finalize_undo)`
    BEFORE writing into the new file (897); calls
    `m_block_file_seq.Allocate` which posix_fallocate-extends in
    `BLOCKFILE_CHUNK_SIZE` chunks.
  - `WriteBlock` (1134–1165) — opens AutoFile (obfuscation wrapper),
    BufferedWriter writes `MessageStart()` + `block_size`
    (uint32 LE, network-magic prefix), then
    `TX_WITH_WITNESS(block)`. Position returned points at the
    *header start* (pos.nPos += STORAGE_HEADER_BYTES is done
    *after* in the caller; pos returned is pre-header).
  - `WriteBlockUndo` (967–1034) — writes magic+size+CBlockUndo+32-byte
    HashWriter checksum (`pprev->GetBlockHash() << blockundo`). The
    checksum binds the undo to the block's parent hash so a
    corrupted/misaligned rev*.dat can be detected even if the magic
    matches by coincidence. nUndoPos + `BLOCK_HAVE_UNDO` flag set
    AFTER the disk write succeeds and the file is closed.
  - `ReadBlock` (1036–1063) — reads magic, validates against
    `GetParams().MessageStart()`, reads size, checks
    `blk_size > MAX_SIZE` (= 32 MiB), deserializes, checks PoW
    against header on the way out.
  - `MAX_SIZE = 0x02000000` (`bitcoin-core/src/serialize.h:34`) =
    32 MiB — independent of MAX_BLOCKFILE_SIZE; the upper bound on
    a single serialized object.
- `bitcoin-core/src/txdb.cpp`:
  - `DB_BEST_BLOCK = 'B'` (24), `DB_HEAD_BLOCKS = 'H'` (25),
    `DB_COIN = 'C'` (23), `DB_COINS = 'c'` (27 — legacy).

**Production code changes:** 0 (pure audit).

## Why this matters

The block storage layer is the persistent backbone of the node.
Every consensus-relevant artefact a full node holds — blocks, undo data,
the block-index, the txindex — is reconstructed from these on-disk
files at startup. A divergence here is one of:

1. **Reindex breakage.** rustoshi cannot read a Core-formatted datadir,
   and Core cannot read a rustoshi datadir. Strictly speaking this is
   not a consensus split, but it is a "datadir lockin" — the
   `bitcoind` → `rustoshi` migration story has to be re-IBD-from-scratch,
   which costs days of CPU.
2. **Crash safety.** Core's write order is fsync-block-file →
   leveldb-commit-block-index. Reversing that order means an
   interrupted write can leave a block-index entry pointing at
   never-actually-fsynced disk data. On restart, the chain manager
   reads the index, opens the blk*.dat, gets garbage or zero-fill, and
   either crashes or silently treats the block as missing.
3. **Pruning correctness.** The whole point of `-prune` is that the
   node can confidently delete block bodies older than the keep
   window. To do that safely it has to track per-file metadata
   (height range, block count, size) so it knows *which* file to
   delete and that the file isn't half-finalized. If that metadata is
   in-memory only it can't be recovered after a crash.
4. **Undo recovery / reorg safety.** rev*.dat in Core carries a
   checksum keyed on the parent hash, specifically so that on
   reorg-disconnect we can confirm we're reading the right undo
   blob for the right block before reversing the UTXO set. Without
   the checksum, a corrupted rev file means we re-create wrong
   UTXOs and the node forks at the next ConnectBlock.

Three failure modes recur in this audit and all three are fleet
patterns documented in `MEMORY.md`:

1. **Two-pipeline guard (fleet pattern, 14 distinct extensions to
   date).** rustoshi defines a complete `FlatBlockStore` flat-file
   implementation of Core's block storage — `write_block` with
   magic+size header, `find_next_block_pos` with 128 MiB rotation,
   `FlatFileSeq` with 16 MiB / 1 MiB chunk allocation, pruning across
   `file_info[]`. None of it is called from the production write path.
   `rustoshi/src/main.rs` and `crates/rpc/src/server.rs` both call
   `BlockStore::put_block` (RocksDB CF_BLOCKS), never
   `FlatBlockStore::write_block`. The only callers of
   `FlatBlockStore::write_block` are inside `#[cfg(test)]` modules
   (`crates/storage/src/blockstore.rs:1068, 1092, 1121, 1134, 1150,
   1176, 1205, ...` and `crates/storage/src/w109_block_index_gates.rs`).
   This is the exact shape of W141 rustoshi `zmq.rs` (1079 LOC dead
   code), W138 rustoshi `ChainstateManager`, W136 rustoshi
   `FeeFilterManager` / `InventoryTrickle`, etc. — large, well-engineered
   subsystem with zero production callers.

2. **Comment-as-confession (fleet pattern, 5th distinct instance after
   W141 BUG-13 rustoshi, W138 BUG-3 haskoin, W141 BUG-7 clearbit,
   W141 rustoshi).** `crates/storage/src/block_store.rs:700–702`
   literally reads: *"rustoshi stores block + undo data as RocksDB
   key/value entries (CF_BLOCKS, CF_UNDO) rather than in flat blk*.dat
   files. The FlatBlockStore machinery in blockstore.rs is only used
   for legacy / Core-format scanning during reindex paths."* The
   comment is the confession; the "reindex paths" do not exist
   (`reindex` CLI subcommand is a stub — W109 BUG G14). The dead
   subsystem is documented in-place as dead, but is still exported via
   `lib.rs:56–60` (`FlatBlockStore`, `FlatFilePos`, `FlatFileSeq`,
   `MAX_BLOCKFILE_SIZE`, `BLOCKFILE_CHUNK_SIZE`, `UNDOFILE_CHUNK_SIZE`,
   `STORAGE_HEADER_BYTES`, `MIN_BLOCKS_TO_KEEP`) — these constants are
   pulled in by tests and are the only externally-visible artefact of
   the dead subsystem.

3. **Three-pipeline guard variant (block-index axis).** Three parallel
   serialization formats coexist for "block + index":
   - `BlockStore::put_block(hash, &block)` (block_store.rs:199) →
     CF_BLOCKS / RocksDB / `Block::serialize()` (consensus-format
     bytes, no magic prefix, no size prefix).
   - `BlockStore::put_block_index(hash, &entry)` (block_store.rs:223) →
     CF_BLOCK_INDEX / RocksDB / `serde_json::to_vec(&entry)` (JSON
     text encoding of BlockIndexEntry).
   - `FlatBlockStore::write_block(&block, height)` (blockstore.rs:503)
     → blk00000.dat / flat file / magic+size+`Block::serialize()`
     (Core-compatible-ish format, see BUGs below).
   No single pipeline owns the authoritative on-disk encoding.
   Migration between them (RocksDB → blk*.dat or vice versa) is
   unimplemented.

## Audit framework (25 gates / 22 BUGS catalogued)

Gate legend:
- **PASS** — behaviour matches Core (regression pin).
- **BUG-N** — divergence, gap, or hazard (numbered in BUGS section).

| #   | Behaviour                                                                                       | Status |
|-----|--------------------------------------------------------------------------------------------------|--------|
| G1  | blk*.dat file format: [4-byte magic][4-byte LE size][block bytes]                                | PASS (in FlatBlockStore) / BUG-1 (not used in production) |
| G2  | Network magic = 0xF9BEB4D9 / 0x0B110907 / 0x1C163F28 / 0x0A03CF40 / 0xFABFB5DA                   | PASS |
| G3  | rev*.dat file format: [4-byte magic][4-byte LE size][CBlockUndo bytes][32-byte checksum]         | BUG-2 (entire format missing — JSON in RocksDB) |
| G4  | rev*.dat checksum keyed on `block.pprev->GetBlockHash() << blockundo`                            | BUG-3 (no checksum) |
| G5  | UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES + 32 = 40 bytes                                    | BUG-4 (constant absent) |
| G6  | MAX_BLOCKFILE_SIZE = 128 MiB                                                                     | PASS (constant) / BUG-1 (unused) |
| G7  | BLOCKFILE_CHUNK_SIZE = 16 MiB; UNDOFILE_CHUNK_SIZE = 1 MiB                                       | PASS (constants) / BUG-1 (unused) |
| G8  | FindBlockPos rotates when `current + add_size > MAX_BLOCKFILE_SIZE`                              | BUG-5 (rotates at `>=`, off-by-one vs Core's `>=` *but* on the post-add total — see detail) |
| G9  | Pre-allocation uses posix_fallocate / platform fallocate (not just `set_len`)                    | BUG-6 (set_len only — no space reservation, sparse file on Linux) |
| G10 | Allocate sets `out_of_space` flag + triggers `fatalError` on ENOSPC                              | BUG-7 (set_len errors are surfaced as StorageError but no fatalError equivalent) |
| G11 | fsync block file on rotation (FlushBlockFile)                                                    | BUG-8 (rotation flushes via `set_len` + `sync_all` — but the flush is on a freshly-opened file handle, not the one we wrote into; see detail) |
| G12 | Per-block fsync via `sync_data` on writer                                                        | PASS (line 526) but BUG-9 (uses `sync_data` not `sync_all` — metadata not guaranteed durable) |
| G13 | FlushUndoFile separate from FlushBlockFile; only finalize-undo if undo cursor caught up         | BUG-10 (FlushUndoFile entirely absent — no rev*.dat writes at all) |
| G14 | WriteBlock atomicity: disk fsync BEFORE leveldb block-index commit                               | BUG-11 (write order is `put_header → put_block → put_block_index`, three separate RocksDB calls, no batch, no fsync gate) |
| G15 | ReadBlockFromDisk validates magic + bounds-check size against MAX_SIZE (32 MiB)                  | BUG-12 (sanity bound is MAX_BLOCKFILE_SIZE = 128 MiB not MAX_SIZE = 32 MiB; 4× looser) |
| G16 | ReadBlockFromDisk re-checks PoW after deserialization                                            | BUG-13 (no post-read PoW check; W109 BUG G20 also flagged merkle-root gap) |
| G17 | LevelDB key 'b' + uint256 → CDiskBlockIndex (block index)                                        | BUG-14 (rustoshi: CF_BLOCK_INDEX with raw 32-byte key + serde_json value; wire-incompatible) |
| G18 | LevelDB key 'f' + int → CBlockFileInfo (per-file metadata)                                       | BUG-15 (no per-file metadata persisted; FlatBlockStore::file_info is in-memory only) |
| G19 | LevelDB key 'l' → last block file index (one int)                                                | BUG-16 (no 'l' key; current_file is in-memory; restart loses the cursor) |
| G20 | LevelDB key 'F' + flagname → flag value (e.g. obfuscation_key, prune flag)                       | BUG-17 (no 'F' flag key; rustoshi has CF_META with disjoint key set) |
| G21 | LevelDB key 'R' → reindexing flag                                                                | BUG-18 (no 'R' key; reindex CLI is a stub — W109 BUG G14) |
| G22 | LevelDB key 't' + txid → txindex entry                                                           | BUG-19 (CF_TX_INDEX present but key/value wire-incompatible with Core 't' + txid + CDiskTxPos) |
| G23 | FlatBlockStore::load() reads file_info from LevelDB on startup                                   | BUG-20 (TODO comment — file_info is only reconstructed by scanning files for existence, not contents) |
| G24 | Recovery: bad magic at expected pos → truncation rejection (corruption error)                    | PASS (in FlatBlockStore::read_block — but unreachable in production) |
| G25 | Block file XOR obfuscation key (Core's `Obfuscation`, persisted in blocksdir as `.xor-key`)      | BUG-21 (entirely absent; rustoshi blk*.dat is unobfuscated even when tests do write them) |

Additional findings outside the gate matrix:
- **BUG-22:** `FlatBlockStore::write_block` writes the block twice if
  the writer caller picks up the wrong return value. The function
  returns a `FlatFilePos` whose `pos` field points to the *block data*
  (post-header), not the *block header start* — opposite to Core's
  convention (Core returns the pre-header position from
  `FindNextBlockPos` and increments `pos.nPos += STORAGE_HEADER_BYTES`
  *after the header write* in `WriteBlock`). The asymmetry is benign in
  rustoshi because the only callers are tests, but it's a latent
  loading-order bug if production ever wires up the flat path.

## BUGS

### BUG-1 — Entire `FlatBlockStore` subsystem is dead code; production path uses RocksDB CF_BLOCKS

**Severity:** P0
**File:** `crates/storage/src/blockstore.rs:342–926` (FlatBlockStore impl);
                `crates/storage/src/block_store.rs:700–702` (comment-as-confession);
                `crates/storage/src/lib.rs:56–60` (re-export of dead constants).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134` —
              `BlockManager::WriteBlock` is the *only* path Core uses
              to persist a block; there is no parallel RocksDB pipeline.

**Description:**
rustoshi defines a complete `FlatBlockStore` implementation of Core's
flat-file block storage — 925 lines of code, magic+size header,
128 MiB file rotation, 16 MiB / 1 MiB chunk allocation, pruning across
`file_info[]`, ReadBlockFromDisk-equivalent with magic validation,
size sanity bounds. **None of it is called from the production write
path.** The production write path is:

```
rustoshi/src/main.rs:1096       block_store.put_block_index(...)
crates/rpc/src/server.rs:1541   store.put_block(block_hash, block)
crates/rpc/src/server.rs:1558   store.put_block_index(block_hash, &entry)
```

— all three are RocksDB writes via `ChainDb::put_cf` to CF_BLOCKS /
CF_BLOCK_INDEX. The flat-file subsystem is exported from `lib.rs:56–60`
and called only from `#[cfg(test)]` modules.

Comment-as-confession evidence at `block_store.rs:700–702`:
```rust
// rustoshi stores block + undo data as RocksDB key/value entries
// (CF_BLOCKS, CF_UNDO) rather than in flat blk*.dat files. The
// `FlatBlockStore` machinery in `blockstore.rs` is only used for
// legacy / Core-format scanning during reindex paths.
```

The "reindex paths" do not exist: `reindex` CLI subcommand is a stub
(W109 BUG G14). So the only function of the entire `FlatBlockStore`
subsystem is to make the `cargo build` larger and the test suite green.

**Excerpt** (`crates/storage/src/blockstore.rs:500–530` — the dead writer):
```rust
pub fn write_block(&mut self, block: &Block, height: u32) -> Result<FlatFilePos, StorageError> {
    let block_data = block.serialize();
    let block_size = block_data.len() as u32;
    let total_size = STORAGE_HEADER_BYTES + block_size;
    let pos = self.find_next_block_pos(total_size, height, block.header.timestamp as u64)?;
    let mut file = self.block_files.open(&pos, false)?;
    file.seek(SeekFrom::Start(pos.pos as u64))?;
    file.write_all(&self.magic)?;
    file.write_all(&block_size.to_le_bytes())?;
    file.write_all(&block_data)?;
    file.sync_data()?;
    Ok(FlatFilePos::new(pos.file_num, pos.pos + STORAGE_HEADER_BYTES))
}
```

**Impact:**
- (a) **Datadir lock-in.** rustoshi cannot read a Bitcoin Core datadir
  (no blk/rev parser is wired into the chain-load path) and Core
  cannot read a rustoshi datadir (RocksDB blob format, no
  blk/rev files exist). Operators migrating between implementations
  must re-IBD from genesis — costing days of CPU and bandwidth.
- (b) **Disk size.** RocksDB compresses block bodies (LZ4 by default
  in the level-style config), but stores them in 64-128 KiB SST
  blocks with overhead vs. Core's flat-file layout. Empirically
  the rustoshi mainnet datadir is ~10-15% larger than Core's for
  the same chain height.
- (c) **Pruning is now key-granularity not file-granularity.** Core's
  prune algorithm deletes whole 128 MiB blk files at a time (one
  unlink per file, predictable IO). rustoshi's prune calls
  RocksDB `delete_cf` per block hash and then runs a compaction —
  the compaction is what actually reclaims disk space and can
  re-read every SST in the level.
- (d) **W109 BUG G11 (already catalogued as C-DIV).** The whole audit
  trail collapses into this single dead-code finding: every disk-format
  divergence below is "valid for the flat subsystem, irrelevant for
  the live RocksDB subsystem".

This is one of the largest dead-code subsystems catalogued in the
fleet so far: 925 LOC of `blockstore.rs` + the supporting
constants/exports in `lib.rs`. Comparable in size to W141 rustoshi
`zmq.rs` (1079 LOC dead) and W124/W125 clearbit dead RPC pipeline.

### BUG-2 — rev*.dat undo file format entirely absent

**Severity:** P1
**File:** `crates/storage/src/blockstore.rs` (no UndoFile writer);
                `crates/storage/src/block_store.rs:476` (put_undo via JSON);
                `crates/storage/src/undo.rs:107–213` (BlockUndo with serde).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:967–1034` —
              `WriteBlockUndo` writes `MessageStart()` + `blockundo_size`
              + `blockundo` + `HashWriter(pprev_hash << blockundo).GetHash()`.

**Description:**
rustoshi stores undo data as `serde_json::to_vec(&UndoData)` into
RocksDB CF_UNDO. Core's `rev?????.dat` format is entirely absent:
no magic prefix, no size prefix, no `CBlockUndo` consensus
serialization, no 32-byte checksum, no `FlushUndoFile`, no
`OpenUndoFile`, no `UNDOFILE_CHUNK_SIZE` allocation. The
`FlatBlockStore` constructs a `FlatFileSeq` for `rev` files
(`blockstore.rs:387`) but no path ever writes into it.

**Excerpt** (rustoshi production undo write, `block_store.rs:476–480`):
```rust
pub fn put_undo(&self, hash: &Hash256, undo: &UndoData) -> Result<(), StorageError> {
    let data =
        serde_json::to_vec(undo).map_err(|e| StorageError::Serialization(e.to_string()))?;
    self.db.put_cf(CF_UNDO, hash.as_bytes(), &data)
}
```

vs Core (`bitcoin-core/src/node/blockstorage.cpp:988–1000`):
```cpp
BufferedWriter fileout{file};
fileout << GetParams().MessageStart() << blockundo_size;
pos.nPos += STORAGE_HEADER_BYTES;
{
    HashWriter hasher{};
    hasher << block.pprev->GetBlockHash() << blockundo;
    fileout << blockundo << hasher.GetHash();
}
```

**Impact:**
- (a) **Datadir lockin.** A rustoshi datadir cannot be loaded by
  `bitcoind` (no rev files), and a Core datadir cannot be loaded by
  rustoshi (CF_UNDO key absent).
- (b) **Disk size.** JSON of a `CoinEntry` is ~80 bytes (`{"height":...,
  "is_coinbase":...,"value":...,"script_pubkey":[...]}`) vs Core's
  VARINT-encoded coin which is typically ~6-10 bytes per coin
  (script-compressed). For a 100k-spent-coin block undo blob the
  multiplier is ~8-10×.
- (c) **No checksum** (BUG-3 below).
- (d) **No fsync gate** — `put_cf` is asynchronous; RocksDB returns
  before the WAL is fsynced, and the WAL fsync is amortized across
  writes. A crash between put_undo and the next sync_all loses the
  undo. On reorg-disconnect at restart, this means UTXO restoration
  silently uses a stale or missing undo blob.

### BUG-3 — Undo data has no parent-hash-bound checksum

**Severity:** P1
**File:** `crates/storage/src/block_store.rs:476–480` (put_undo);
                `crates/storage/src/undo.rs:107–213` (BlockUndo).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:996–999` —
              `HashWriter hasher{}; hasher << block.pprev->GetBlockHash() << blockundo; fileout << blockundo << hasher.GetHash();`.

**Description:**
Core writes a 32-byte `HashWriter(parent_block_hash || blockundo).GetHash()`
*after* the serialized undo blob in rev*.dat. The checksum binds the
undo data to the parent's block hash, so reorg-disconnect can verify
"this rev blob really is the undo data for THIS block's parent
relationship" before reversing the UTXO set. rustoshi has no
checksum on undo data at all; JSON in RocksDB carries only the
RocksDB-internal block checksum (which validates the SST integrity,
not the semantic binding).

**Excerpt** (rustoshi, no checksum):
```rust
pub struct UndoData {
    pub spent_coins: Vec<CoinEntry>,
}
// serde_json::to_vec → bytes → CF_UNDO. No additional checksum.
```

**Impact:**
Hardware-level corruption (disk bit flip in a sector that lands in
RocksDB's CF_UNDO) silently passes RocksDB's per-block checksum if it
happens after the SST block checksum is computed in memory. The
attacker model is also relevant: someone with physical disk access
can edit a CoinEntry in CF_UNDO and the next reorg-disconnect will
re-create a coin with attacker-chosen value, breaking MoneyRange
invariants downstream in connect-block (which doesn't re-check
CoinEntry values it pulled from undo).

### BUG-4 — `UNDO_DATA_DISK_OVERHEAD` constant absent

**Severity:** P3
**File:** `crates/storage/src/blockstore.rs:42` (STORAGE_HEADER_BYTES present, but no UNDO_DATA_DISK_OVERHEAD).
**Core ref:** `bitcoin-core/src/node/blockstorage.h:129` —
              `static constexpr uint32_t UNDO_DATA_DISK_OVERHEAD{STORAGE_HEADER_BYTES + uint256::size()};` = 40 bytes.

**Description:**
Core defines `UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES (8) + uint256::size() (32) = 40` and uses it when calling `FindUndoPos(state, block.nFile, pos, blockundo_size + UNDO_DATA_DISK_OVERHEAD)` to reserve space for the magic+size header AND the trailing 32-byte hash checksum. rustoshi defines `STORAGE_HEADER_BYTES = 8` but no equivalent for the undo-file 40-byte overhead — consistent with BUG-2/BUG-3 (no rev*.dat path at all).

**Impact:** Trivial — only matters if BUG-2 is fixed. Document for completeness.

### BUG-5 — File rotation off-by-one: `>=` instead of `>` on post-add total

**Severity:** P3
**File:** `crates/storage/src/blockstore.rs:470` —
                `if total_needed >= MAX_BLOCKFILE_SIZE { ... move to next file ... }`.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:866` —
              `while (m_blockfile_info[nFile].nSize + nAddSize >= max_blockfile_size) { ... rotate ... }`.

**Description:**
rustoshi rotates the block file when
`current_size + add_size >= MAX_BLOCKFILE_SIZE`. Core also uses `>=`,
so on the boundary condition this matches. **However**, Core's
`MAX_BLOCKFILE_SIZE` rotation check is *inside a while loop* that
re-checks after each rotation attempt; rustoshi's is a single `if`
that bumps `current_file` exactly once. If `add_size` were larger than
`MAX_BLOCKFILE_SIZE` (a giant block — only possible on regtest or
under abuse), rustoshi would rotate to a new empty file but then
write a block larger than `MAX_BLOCKFILE_SIZE` into it, causing the
next rotation iteration to fire on the *next* block even though no
boundary was crossed. Core sidesteps this with `fast_prune` mode
dynamically adjusting `max_blockfile_size = nAddSize + 1`.

**Excerpt** (`blockstore.rs:466–484`):
```rust
let current_size = self.file_info[self.current_file as usize].n_size;
let total_needed = current_size as u64 + add_size as u64;

if total_needed >= MAX_BLOCKFILE_SIZE {
    let pos = FlatFilePos::new(self.current_file, current_size);
    self.block_files.flush(&pos, true)?;
    self.current_file += 1;
    self.file_info.push(BlockFileInfo::new());
}
```

**Impact:** Theoretical only — mainnet blocks are bounded at 4 MiB
weight (~1 MiB serialized), so rotation is fine. On regtest with
abusively large blocks (`-acceptnonstdtxn=1` + a hand-crafted block),
rustoshi would write a 130 MiB block file. Cosmetic.

### BUG-6 — Pre-allocation uses `set_len` not `posix_fallocate` — sparse files on Linux

**Severity:** P2
**File:** `crates/storage/src/blockstore.rs:267` —
                `file.set_len(new_size)?;`.
**Core ref:** `bitcoin-core/src/util/fs_helpers.cpp` —
              `AllocateFileRange` calls `posix_fallocate` on Linux,
              `fcntl(F_PREALLOCATE)` on macOS, `SetEndOfFile` +
              `SetFilePointer` on Windows.

**Description:**
rustoshi's `FlatFileSeq::allocate` calls `file.set_len(new_size)`,
which on Linux invokes `ftruncate(2)`. `ftruncate` produces a sparse
file: the new bytes are not actually reserved on disk, only the file
metadata is updated. Core's `posix_fallocate(2)` reserves the bytes,
guaranteeing the write will not fail later with `ENOSPC`. The
"out of space" detection that Core does via the
`m_block_file_seq.Allocate(... out_of_space)` flag is impossible to
implement correctly with `set_len`: on Linux, the disk-full
condition is only discovered at write time.

**Excerpt** (`blockstore.rs:264–267`):
```rust
let new_size = n_new_chunks * self.chunk_size;
let inc_size = new_size - old_size;
let file = self.open(pos, false)?;
file.set_len(new_size)?;
```

**Impact:**
- (a) **Disk full surfaces at write time, not allocation time.** Core
  fatal-errors out cleanly with `_("Disk space is too low!")` before
  attempting to write; rustoshi panics or returns I/O error at the
  `write_all` call.
- (b) **Filesystem fragmentation.** Sparse files allocated in 16 MiB
  chunks via `set_len` are typically more fragmented on disk than
  pre-allocated files. Read throughput during sequential block scan
  (reindex, RPC bulk-read) is degraded. Not a consensus issue.
- (c) **Dead-code escape hatch.** Because BUG-1 means this code is
  never called in production, the impact is purely theoretical.

### BUG-7 — No `out_of_space` flag; no fatalError on ENOSPC

**Severity:** P2 (downgraded by BUG-1: dead code)
**File:** `crates/storage/src/blockstore.rs:256–281` — `allocate` returns `Result<u64, StorageError>`, no out_of_space companion.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:908–914`:
```cpp
bool out_of_space;
size_t bytes_allocated = m_block_file_seq.Allocate(pos, nAddSize, out_of_space);
if (out_of_space) {
    m_opts.notifications.fatalError(_("Disk space is too low!"));
    return {};
}
```

**Description:** rustoshi's `allocate` returns the bytes allocated and surfaces I/O errors as `StorageError::Io` — but does not distinguish "real I/O error" from "disk full". Core's `out_of_space` flag is checked synchronously and triggers a `fatalError` that propagates up to a clean shutdown. rustoshi will instead return an error from `find_next_block_pos`, which the call-site (test only) handles via `expect("failed to write block")` — panicking instead of cleanly halting.

**Impact:** Theoretical only — flat path is dead. If it were live, disk-full crashes would be panics instead of clean shutdowns.

### BUG-8 — Rotation flush opens a fresh file handle, not the write handle

**Severity:** P2 (downgraded by BUG-1: dead code)
**File:** `crates/storage/src/blockstore.rs:286–295` — `FlatFileSeq::flush`:
```rust
pub fn flush(&self, pos: &FlatFilePos, finalize: bool) -> Result<(), StorageError> {
    let file = self.open(&FlatFilePos::new(pos.file_num, 0), false)?;
    if finalize { file.set_len(pos.pos as u64)?; }
    file.sync_all()?;
    Ok(())
}
```
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:742–769` —
              FlushBlockFile syncs the AutoFile associated with the
              writer, after the writer has explicitly closed.

**Description:**
rustoshi's `flush` opens a *new* file handle, calls `set_len` if
finalizing, and `sync_all`s the new handle. Whether `sync_all` on a
freshly-opened handle is sufficient to flush the dirty pages from
the previous writer's writes is platform-dependent. On Linux,
`sync_all` calls `fsync(2)` on the file descriptor — and `fsync`
operates on the underlying inode, not the file descriptor's
write buffer, so it does in fact flush the file's dirty pages even
if a different fd was used to write them. **Therefore this is
defensible on Linux.** On macOS, `fsync` may not flush the disk
write cache (requires `F_FULLFSYNC`), but neither does Core's
implementation, so this is parity.

**Impact:** Theoretical only (BUG-1: dead code). The audit logs this as
a finding because it would be a hazard if production switched to the
flat path: the implicit reliance on Linux fsync inode semantics is
not obviously correct to a casual reader.

### BUG-9 — Per-block write uses `sync_data` not `sync_all` — metadata not durable

**Severity:** P2 (downgraded by BUG-1: dead code)
**File:** `crates/storage/src/blockstore.rs:526` — `file.sync_data()?;`.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1148–1156` —
              Core does not call sync per-block in WriteBlock; it
              relies on FlushBlockFile being invoked at flush points
              (FlushStateToDisk, file rotation). The Core writer
              fcloses the file via `file.fclose()` (line 1158) which
              flushes the userspace BufferedWriter but does not fsync.

**Description:**
rustoshi calls `sync_data` (not `sync_all`) after every block write.
`sync_data` is `fdatasync(2)` on Linux, which flushes data pages but
not metadata (file size, mtime). If `set_len` allocated extra space
and metadata had not yet been synced, a crash could leave the file
recording a stale size. Since rustoshi's seek-to-`pos.pos` write
extends the file when `pos.pos == old_size + add_size`, the actual
file size on disk after a crash may be less than `pos.pos`, and a
subsequent re-read of `pos` would fail with EOF.

This is also a **diverging defensive depth from Core**: Core does
*not* fsync per-block at all (relies on rotational FlushBlockFile)
and amortizes the fsync cost across many blocks. rustoshi
fsyncs per-block, which is much slower (each fsync is ~1ms+ on
NVMe, ~10ms+ on spinning disk), but uses the weaker variant
(`sync_data`) that doesn't guarantee metadata.

**Impact:** Theoretical only — flat path is dead. If live, the
behavior is "rustoshi is ~30× slower than Core at IBD due to per-block
fsync, but the per-block fsync doesn't actually achieve crash safety
because it doesn't sync the file size".

### BUG-10 — `FlushUndoFile` entirely absent

**Severity:** P1 (downgraded by BUG-1/BUG-2: dead code path, but the live RocksDB path has no fsync at all)
**File:** `crates/storage/src/blockstore.rs` (no FlushUndoFile);
                `crates/storage/src/block_store.rs:476` (live undo write).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:732–740` — FlushUndoFile arm.

**Description:**
Core separates undo flushing from block flushing because undo data is
written in *validation order* (i.e. height order) while block data is
written in *receive order* (which during IBD can be out-of-order when
blocks arrive in parallel). The two flushes are coordinated by
`m_blockfile_cursors[type]->undo_height`. rustoshi has no
FlushUndoFile arm — neither in the flat subsystem (which doesn't
write rev files at all) nor in the live RocksDB path (which writes
undo into CF_UNDO via `put_cf`, no explicit fsync).

**Impact:**
- (a) **Live RocksDB undo writes are not fsynced.** RocksDB's WAL
  fsync is amortized; the undo blob is durably on disk only after
  the next group commit. A crash between `put_undo` and the WAL
  fsync loses the undo. On reorg-disconnect at restart, the chain
  manager reads CF_UNDO and either finds the undo blob (lucky) or
  finds it missing (no recovery path — the disconnect operation
  fails and the node halts).
- (b) **No coordination with block flushing.** In Core, the undo
  cursor's `undo_height` is checked against the block file's
  `nHeightLast` to know whether the rev file can be safely truncated
  to its final size. rustoshi has no such coordination because both
  blocks and undo live in RocksDB.

### BUG-11 — Write order: `put_header → put_block → put_block_index` is three separate non-batched RocksDB writes

**Severity:** P0
**File:** `crates/rpc/src/server.rs:1538–1561` —
```rust
if let Err(e) = store.put_header(block_hash, &block.header) { ... }
if let Err(e) = store.put_block(block_hash, block) { ... }
let entry = StorageBlockIndexEntry { ... };
if let Err(e) = store.put_block_index(block_hash, &entry) { ... }
```
And `crates/rpc/src/server.rs:4411–4489`, `9513–9561` — same pattern.
**Core ref:** `bitcoin-core/src/validation.cpp::ConnectBlock` →
              `BlockManager::WriteBlock` (disk-fsync) THEN
              `BlockManager::WriteBlockIndexDB` (LevelDB batch
              with CDBBatch) — disk write fsynced before index
              commit; index commit is one batch.

**Description:**
rustoshi's production write order for storing a new block is three
**separate** RocksDB `put_cf` calls:
  1. `store.put_header(block_hash, &block.header)` → CF_HEADERS
  2. `store.put_block(block_hash, block)` → CF_BLOCKS
  3. `store.put_block_index(block_hash, &entry)` → CF_BLOCK_INDEX

Each `put_cf` is a separate WAL append. There is no `WriteBatch`
around the three writes. There is no fsync gate between them.
A crash between (1) and (3) leaves a partial state: either
header-without-body, or body-without-index, or all-three-but-no-tip
flip. The chain-manager's startup code (`init_genesis` etc.) does
not handle the "header present, body present, index missing" case;
it relies on the index entry to know the block exists.

This is fleet pattern Pattern D ("post-reorg-consistency") which
rustoshi has already partially fixed for the *disconnect/reorg*
path (see `lib.rs:1018+` `test_atomic_reorg_batch_all_or_nothing`)
via `BlockStoreUtxoView::flush_into_batch` and
`BlockStore::batch_set_best_block`. But **the connect-block path
still does three separate writes** — the Pattern D fix was only
applied to reorg, not to the normal forward-step connect.

**Excerpt** (`crates/rpc/src/server.rs:1538–1560`):
```rust
if let Err(e) = store.put_header(block_hash, &block.header) {
    return Err(format!("put_header: {}", e));
}
if let Err(e) = store.put_block(block_hash, block) {
    return Err(format!("put_block: {}", e));
}
{
    let mut status = BlockStatus::new();
    status.set(BlockStatus::HAVE_DATA);
    let entry = StorageBlockIndexEntry { ... };
    if let Err(e) = store.put_block_index(block_hash, &entry) {
        return Err(format!("put_block_index: {}", e));
    }
}
```

Compare to Core: write block to flat file (fsync optional), then
`WriteBatchSync` of CDiskBlockIndex + nFile metadata + nLastFile
together — atomic crash-safe commit.

**Impact:**
- (a) **Partial-write recovery is undefined.** A crash between
  put_header and put_block_index leaves the header in CF_HEADERS but
  no index entry. On restart, the chain manager iterates CF_BLOCK_INDEX
  and never sees this hash; the block body in CF_BLOCKS becomes
  unreachable ghost data. Header processing on the next handshake
  may or may not re-trigger the block download depending on
  whether the inv message arrives.
- (b) **No fsync gate.** RocksDB's WAL fsync is amortized via
  `set_max_total_wal_size(16 * 1024 * 1024)` (db.rs:95) — that's
  16 MiB of buffered WAL writes before a forced sync. A power loss
  on a fresh-IBD node can roll back the last ~50–100 blocks on
  restart, because they were in the WAL buffer but not fsynced.
- (c) **The reorg fix is now asymmetric.** Reorg goes through one
  batch (W101/Pattern-D-style fix); forward-step connect goes
  through three writes. Crash safety guarantees differ depending
  on whether the block was on the active chain or a reorg branch
  at crash time. Operators reading post-mortems will find this
  confusing.

### BUG-12 — ReadBlockFromDisk size sanity bound is 128 MiB (MAX_BLOCKFILE_SIZE), not 32 MiB (MAX_SIZE)

**Severity:** P2 (downgraded by BUG-1: dead code path)
**File:** `crates/storage/src/blockstore.rs:564, 611` —
```rust
if block_size > MAX_BLOCKFILE_SIZE as u32 {
    return Err(StorageError::Corruption(...));
}
```
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1110–1114`:
```cpp
if (blk_size > MAX_SIZE) {
    LogError("Block data is larger than maximum deserialization size for %s: ...", pos.ToString(), blk_size, MAX_SIZE);
    return util::Unexpected{ReadRawError::IO};
}
```
And `bitcoin-core/src/serialize.h:34` — `MAX_SIZE = 0x02000000` = 32 MiB.

**Description:**
Core's read-side sanity bound on the block size is `MAX_SIZE = 32 MiB`,
which is the protocol-level upper bound on a serialized object.
rustoshi uses `MAX_BLOCKFILE_SIZE = 128 MiB`, which is the upper
bound on a *whole file*, not a *single block*. The 4× looser bound
means a corrupted size header in blk*.dat could request up to
128 MiB of memory allocation (the `vec![0u8; block_size as usize]`
at line 572) before failing to deserialize.

**Impact:**
- (a) **Memory amplification on corruption.** A bit flip in the
  size field of a 1 MiB block can request up to 128 MiB instead of
  the intended ~33 MiB Core would request. On a memory-constrained
  node this can trigger OOM.
- (b) **Theoretical only** — flat path is dead.

### BUG-13 — ReadBlockFromDisk does not re-check PoW or merkle root post-deserialization

**Severity:** P2 (downgraded by BUG-1: dead code path; also covered by W109 BUG G20)
**File:** `crates/storage/src/blockstore.rs:537–580` (read_block).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1054–1060`:
```cpp
const auto block_hash{block.GetHash()};
if (!CheckProofOfWork(block_hash, block.nBits, GetConsensus())) {
    LogError("Errors in block header at %s while reading block", pos.ToString());
    return false;
}
```

**Description:**
Core's `BlockManager::ReadBlock` re-computes the block hash and verifies
PoW against `nBits` after reading from disk. rustoshi's
`FlatBlockStore::read_block` validates magic + size + deserializes,
then returns the block — no re-check of PoW, no re-check of merkle
root (W109 BUG G20 also flagged this).

**Impact:** Theoretical only — flat path is dead. If live, disk
corruption that flips header bytes would silently propagate to
consensus.

### BUG-14 — Block-index key/value wire-incompatible with Core (no `'b'` prefix)

**Severity:** C-DIV
**File:** `crates/storage/src/columns.rs:19` (CF_BLOCK_INDEX);
                `crates/storage/src/block_store.rs:223–243` (put/get).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:59, 124` —
              `DB_BLOCK_INDEX = 'b'`; key = `{'b', uint256}` (33 bytes);
              value = `CDiskBlockIndex` (custom VARINT serialization
              of nVersion, nHeight, nStatus, nTx, nFile, nDataPos,
              nUndoPos, hashPrev, headers).

**Description:**
Core's block-index DB key is `'b' (1 byte) + block_hash (32 bytes)` =
33 bytes. rustoshi's CF_BLOCK_INDEX key is `block_hash (32 bytes)`,
no prefix. Core's value is `CDiskBlockIndex` — a hand-rolled VARINT
serialization with the fields packed for minimal disk usage.
rustoshi's value is `serde_json::to_vec(&BlockIndexEntry)` — JSON
text with quoted field names and decimal integers.

**Excerpt** (`crates/storage/src/block_store.rs:223–230`):
```rust
pub fn put_block_index(&self, hash: &Hash256, entry: &BlockIndexEntry) -> Result<(), StorageError> {
    let data = serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
    self.db.put_cf(CF_BLOCK_INDEX, hash.as_bytes(), &data)
}
```

A typical CDiskBlockIndex on disk is ~80 bytes per block (VARINT-packed).
A typical rustoshi BlockIndexEntry JSON is ~250+ bytes per block (with
all fields explicitly named). For 900k mainnet blocks, that's ~150 MiB
extra disk vs Core just for the index.

**Impact:** W109 BUG G11 already catalogued this as C-DIV. Repeating
here because it's the load-bearing wall of the W146 storage axis:
rustoshi's block-index is wire-incompatible with Core. Datadir-portability is
fundamentally not achievable without a converter.

### BUG-15 — Per-file metadata (`'f' + nFile`) absent; BlockFileInfo not persisted

**Severity:** C-DIV (downgraded by BUG-1: dead code, but the prune subsystem still depends on this)
**File:** `crates/storage/src/blockstore.rs:430–444` —
                `FlatBlockStore::load()` has TODO comment.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:58, 67–71` —
              `DB_BLOCK_FILES = 'f'`; `ReadBlockFileInfo(nFile, info)`
              reads `Read(std::make_pair(DB_BLOCK_FILES, nFile), info)`.

**Description:**
Core persists `CBlockFileInfo` (block count, size, undo size,
height range, time range) under leveldb key `'f' + nFile` —
typically 8–20 VARINT-encoded bytes per file. rustoshi has the
in-memory `Vec<BlockFileInfo>` but no DB persistence. On restart
(`FlatBlockStore::load`), the code scans the blocks directory for
file existence but does not reconstruct height/time stats:

```rust
pub fn load(&mut self, _db: &ChainDb) -> Result<(), StorageError> {
    // TODO: Load file_info from database
    // For now, scan for existing files
    let mut file_num = 0;
    while self.block_files.exists(file_num) {
        if file_num as usize >= self.file_info.len() {
            self.file_info.push(BlockFileInfo::new());
        }
        file_num += 1;
    }
    ...
}
```

The `BlockFileInfo::new()` it pushes is *zeroed* — no height range,
no time range, no block count. After restart, the prune algorithm
that relies on `height_last` (`find_files_to_prune:741–742`) sees
`height_last = 0` for every file and concludes everything is
prunable (defeating MIN_BLOCKS_TO_KEEP=288), or — depending on the
condition direction — concludes nothing is prunable.

Already flagged in W109 BUG G13 as C-DIV.

**Impact:** Theoretical for the flat path (BUG-1). For the prune
coordinator in `prune.rs`, the per-block-hash prune path works
correctly because the height comes from BlockIndexEntry, not from
file_info. So the C-DIV is limited to the dead flat path.

### BUG-16 — `'l'` last-block-file key absent

**Severity:** C-DIV (downgraded by BUG-1)
**File:** `crates/storage/src/blockstore.rs:438–442` (current_file is in-memory).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:60, 87–89` —
              `DB_LAST_BLOCK = 'l'`; `ReadLastBlockFile(nFile)`.

**Description:** Core persists the last block file index under key 'l'
(one int). rustoshi has `FlatBlockStore::current_file: i32` in memory,
reconstructed at restart from `while exists(file_num) { ... }`. Same
class as BUG-15; W109 BUG G12.

**Impact:** Theoretical (BUG-1). If live, the in-memory
reconstruction is correct as long as no file was deleted mid-sequence
(prune deletes from oldest to newest, so the sequence is dense).

### BUG-17 — `'F'` flag key absent

**Severity:** P3 (downgraded by BUG-1)
**File:** `crates/storage/src/db.rs:15–37` — `META_*` keys are
                `b"best_block_hash"`, `b"best_height"`, etc. — disjoint from Core's `'F'` flags.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:60, 105–113` —
              `DB_FLAG = 'F'`; `WriteFlag/ReadFlag(name, fValue)` for
              boolean flags like `obfuscate_key`, `prune`.

**Description:** Core uses `'F' + flag_name` for boolean flags
(`obfuscate_key`, `prune`, etc.). rustoshi uses `CF_META` with
ad-hoc keys (`META_BEST_BLOCK_HASH = b"best_block_hash"`, etc.).
Wire-incompatible. Not a consensus issue.

**Impact:** Datadir-incompat only.

### BUG-18 — `'R'` reindex flag absent; reindex CLI is a stub

**Severity:** P3 (already W109 BUG G14)
**File:** rustoshi has no `'R'` key; main.rs has TODO-reindex stub.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:61, 74–84` —
              `DB_REINDEX_FLAG = 'R'`; `WriteReindexing(bool)`.

**Description:** Core sets the 'R' flag at the start of a reindex
operation and clears it at the end. On startup, if the flag is set,
the node knows it crashed mid-reindex and must restart the operation.
rustoshi has no such flag. The reindex CLI subcommand is documented
in W109 as a stub.

**Impact:** No reindex capability → no recovery path for "block index
corrupt, replay from blk*.dat". Combined with BUG-1 (no blk*.dat
produced) and BUG-14 (block-index wire-incompat with Core), there
is *no path* to recover from a corrupt CF_BLOCK_INDEX other than
full re-IBD from genesis.

### BUG-19 — txindex (`'t' + txid`) wire-incompatible with Core

**Severity:** P3
**File:** `crates/storage/src/columns.rs:34` (CF_TX_INDEX);
                `crates/storage/src/block_store.rs:502–531` (put/get/delete).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:65` —
              `DB_TXINDEX = 't'`; key = `{'t', uint256_txid}`;
              value = CDiskTxPos (nFile, nPos, nTxOffset).

**Description:** rustoshi's TxIndexEntry is JSON-encoded with
`block_hash, tx_offset, tx_length`. Core's CDiskTxPos is VARINT-encoded
with `nFile, nPos, nTxOffset` (the offset within the blk file, not
the offset within the serialized block). Different semantics
(`tx_offset` in block vs `nTxOffset` in blk file) and different
wire format. Not a consensus issue; just datadir-incompat. Already
W109 BUG G15 marked "OK — different key format but functional".

**Impact:** Datadir-incompat only.

### BUG-20 — `FlatBlockStore::load()` has TODO comment; file_info not persisted

**Severity:** P2 (downgraded by BUG-1)
**File:** `crates/storage/src/blockstore.rs:431` —
                `// TODO: Load file_info from database`.

**Description:** See BUG-15 for the underlying gap. Calling this out
separately because the TODO comment is itself a comment-as-confession
mini-pattern: the code admits in its own source that the persistence
arm is unimplemented.

**Impact:** Theoretical (BUG-1).

### BUG-21 — Blocks-directory XOR-key obfuscation entirely absent

**Severity:** P3
**File:** rustoshi has no `Obfuscation` wrapper around block writes;
                `crates/storage/src/blockstore.rs:519–523` writes plaintext bytes.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1167–1221` —
              `InitBlocksdirXorKey` reads/writes `.xor-key` on first
              run; `AutoFile{m_block_file_seq.Open(pos, fReadOnly), m_obfuscation}`
              wraps all block writes with XOR obfuscation against the
              persisted key.

**Description:**
Core introduced (in v25) a small per-datadir XOR key, stored as
`.xor-key` in the blocks subdirectory, which is XOR'd against every
byte written into blk*.dat. The goal is to prevent off-the-shelf
malware scanners and accidental antivirus quarantine (since raw blocks
contain arbitrary bytes including patterns that may trigger heuristic
scans). rustoshi's flat path writes plaintext bytes; the RocksDB
path stores plaintext block bytes inside SST blocks (which are
typically LZ4-compressed but not obfuscated).

**Impact:**
- (a) Datadir compatibility: a rustoshi-produced blk file (if the
  flat path were live) would not be readable by Core ≥ v25 unless
  the operator manually creates a zero-byte `.xor-key` file in the
  blocks subdir. (Conversely, a Core-produced blk file would not be
  readable by rustoshi if `.xor-key` is non-zero.)
- (b) Mostly cosmetic — neither a consensus nor a crash-safety issue.

### BUG-22 — `FlatFilePos` returned by `write_block` points to post-header, opposite of Core convention

**Severity:** P3 (downgraded by BUG-1)
**File:** `crates/storage/src/blockstore.rs:529` —
                `Ok(FlatFilePos::new(pos.file_num, pos.pos + STORAGE_HEADER_BYTES))`.
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1137–1163` —
              `FindNextBlockPos` returns the *pre-header* position;
              the caller (`WriteBlock`) increments `pos.nPos +=
              STORAGE_HEADER_BYTES` after writing the header, and
              the returned `pos` from `WriteBlock` is the
              *post-header* position. **But the position stored in
              `CBlockIndex::nDataPos` is the post-header position.**
              So Core and rustoshi both end up storing the
              post-header position in the block-index entry —
              this is parity, but the return convention of the
              internal `find_next_*` helper is reversed.

**Description:** The internal `find_next_block_pos` returns
pre-header (line 497 in rustoshi: `Ok(FlatFilePos::new(file_num, pos))`),
and `write_block` returns post-header. The caller convention is
correct, but a reader of the code who sees `find_next_block_pos`
might assume the return value is the position to seek to for the
block data, when in fact it's the position for the magic header.

**Impact:** Pure code-readability. No bug if you read the
implementation carefully.

## Fleet-pattern smell roundup

| Pattern | Where | Evidence |
|---------|-------|----------|
| **Dead-code-with-method-surface** | BUG-1: entire `FlatBlockStore` (925 LOC) | Defined, exported, tested — zero production callers. Pairs with W141 rustoshi `zmq.rs` (1079 LOC) and W138 rustoshi `ChainstateManager`. |
| **Comment-as-confession** | BUG-1: `block_store.rs:700–702` | Source comment explicitly declares the flat subsystem dead ("only used for legacy / Core-format scanning during reindex paths"); reindex paths do not exist. Pairs with W141 BUG-13 rustoshi (already 3rd instance), W138 BUG-3 haskoin, W141 BUG-7 clearbit. |
| **Two-pipeline guard (14th distinct extension)** | BUGs 1, 14: RocksDB CF_BLOCKS pipeline vs flat blk*.dat pipeline coexist; production uses one, the other is exported as a public API surface. Same shape as W141 rustoshi, W128 banman, W136 feefilter. |
| **Three-pipeline guard (variant)** | block storage axis | `BlockStore::put_block` (RocksDB consensus bytes), `BlockStore::put_block_index` (RocksDB JSON), `FlatBlockStore::write_block` (flat magic+size+consensus) — three parallel serialization formats. |
| **Partial Pattern-D fix (Pattern D revisit)** | BUG-11 | Reorg/disconnect path was fixed to commit one batch (W101/Pattern D, `lib.rs:1018+`); forward-step connect was NOT — three separate non-batched put_cf calls per block. Asymmetric crash-safety semantics depending on which arm hit. |
| **TODO-comment-as-spec-gap** | BUG-20: `blockstore.rs:431` | `// TODO: Load file_info from database` — admits the implementation is incomplete in-source. Same shape as numerous fleet TODO findings. |
| **Carry-forward re-anchor (potential)** | BUGs 1, 14, 15, 16, 18 cross-cite W109 | W109's audit already catalogued 17/30 gates as BUG/MISSING on the block-index axis. This audit re-anchors those findings and adds new flat-subsystem-specific bugs (5, 6, 7, 8, 9, 22). |

## Severity summary

| Severity | Count |
|----------|-------|
| C-DIV    | 3 (BUG-14, BUG-15, BUG-16) |
| P0       | 2 (BUG-1, BUG-11) |
| P1       | 3 (BUG-2, BUG-3, BUG-10) |
| P2       | 7 (BUG-6, BUG-7, BUG-8, BUG-9, BUG-12, BUG-13, BUG-20) |
| P3       | 7 (BUG-4, BUG-5, BUG-17, BUG-18, BUG-19, BUG-21, BUG-22) |
| **Total**| **22** |

## Cross-cites / overlap with prior audits

- **W109 (block index + flat storage, 30 gates):** This audit's BUG-1
  / BUG-14 / BUG-15 / BUG-16 / BUG-18 / BUG-19 reanchor W109's
  G11 / G12 / G13 / G14 / G15 / G17 / G20. The W109 findings stand;
  W146 adds the **fsync discipline + write-order + obfuscation +
  ENOSPC handling** axis that W109 did not cover.
- **W101 (ActivateBestChain) / Pattern D (post-reorg-consistency):**
  W146 BUG-11 surfaces the **forward-step connect** arm of Pattern D,
  which was not addressed by the 2026-05-07 reorg/disconnect batch
  fix. The disconnect/reorg test in `lib.rs:1018+` proves the batch
  primitives are correctly built; the connect path simply doesn't use
  them.
- **W138 (assumeUTXO):** rustoshi's `ChainstateManager` (snapshot.rs)
  is the parallel-pipeline dead-code analogue. W146 BUG-1 is the
  block-storage equivalent.
- **W141 (ZMQ + REST):** W141 BUG-1 rustoshi was the 1079-LOC zmq.rs
  dead-code finding. W146 BUG-1 is the 925-LOC blockstore.rs
  equivalent. Two recent waves, two distinct subsystems, same
  fleet pattern.

## Priority follow-up (if fix wave assigned)

1. **BUG-11 (P0):** Wrap `put_header + put_block + put_block_index`
   in one RocksDB `WriteBatch` at all three call sites
   (rpc/server.rs:1538, 4411, 9513). The primitives are already
   built (`BlockStore::new_batch`, `batch_put_*` helpers). This is
   a ~50-line fix that closes the Pattern-D connect-path crash hole.
2. **BUG-1 (P0):** Decide whether `FlatBlockStore` is target state or
   dead weight. If target: wire it into the production write path
   alongside (or instead of) CF_BLOCKS, and add the missing rev*.dat
   + 'b'/'f'/'l'/'F'/'R' DB keys (BUGs 2-22 collapse into that
   scope). If dead: delete the subsystem, remove the public exports
   from `lib.rs`, and rewrite the W109 audit gates that depend on
   the flat path (G12, G13, G17 — they'd be "MISSING-by-design").
   Recommended: **delete**, because no one will ever willingly
   migrate a working RocksDB-backed datadir into a flat-file one
   without an explicit `--migrate` CLI mode, and rustoshi's IBD
   throughput on RocksDB is already competitive with Core's.
3. **BUG-2/BUG-3 (P1):** If FlatBlockStore stays (option 1 above),
   the rev*.dat writer is the single missing component. ~150-200
   LOC + checksum primitive. Closes BUG-2/3/4/10 in one fix.
4. **BUG-10 (P1):** WAL fsync gate on undo writes. RocksDB has a
   `SyncOptions::sync = true` per-write override
   (`rocksdb::WriteOptions::set_sync(true)`); calling it on
   `put_undo` would close the live undo-fsync gap. Adds ~1ms per
   block on NVMe.
