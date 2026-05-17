# W126 — BIP-152 Compact Blocks audit (rustoshi)

**Wave:** W126 — BIP-152 Compact Block Relay (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:**
- `crates/network/src/compact_blocks.rs` (2080 LOC) — `CmpctBlock`,
  `PrefilledTx`, `BlockTxnRequest`, `BlockTxn`, `PartiallyDownloadedBlock`,
  `PeerCompactBlockState`, `CompactBlockRelay`, `is_block_mutated`.
- `rustoshi/src/main.rs:3814-4058` — incoming `sendcmpct` / `cmpctblock` /
  `getblocktxn` / `blocktxn` dispatch arms.
- `crates/network/src/peer.rs:1015-1026, 1241-1254, 1945-1957` — outbound
  `sendcmpct(announce=false, version=2)` after both the v1 and v2 handshakes.
- `crates/network/src/message.rs:213-215, 332-339, 1051-1063` — wire codec.
- `crates/network/src/peer_manager.rs::handle_event(PeerEvent::Message)` —
  the peer-manager fall-through that consumes the `SendCmpct` forwarded from
  `main.rs:3822` without acting on it.
- W112 prior audit (`rustoshi/tests/test_w112_compact_blocks.rs`, 936 LOC) and
  W123 G14/G15/G16 follow-up findings.

**Reference:**
- BIP-152: <https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki>
- `bitcoin-core/src/blockencodings.{h,cpp}` (lines 1-237) — codec +
  `PartiallyDownloadedBlock`.
- `bitcoin-core/src/net_processing.cpp` —
  - lines 138-141 (depth constants), 199 (version constant),
  - 1272-1329 (`MaybeSetPeerAsAnnouncingHeaderAndIDs`, 3-peer cap),
  - 2105-2152 (`NewPoWValidBlock` fast-announce SEND side),
  - 2598-2614 (`SendBlockTransactions`),
  - 2960-3100 (header-handler punishment incl. `via_compact_block`),
  - 3441-3526 (`ProcessCompactBlockTxns` fill-block leg),
  - 3864-3870 (`SENDCMPCT` sent on `verack`),
  - 3901-3917 (incoming `SENDCMPCT` handler),
  - 4245-4304 (`GETBLOCKTXN` handler + `MAX_BLOCKTXN_DEPTH=10`),
  - 4466-4712 (`CMPCTBLOCK` handler — anti-DoS, reconstruction, fallback,
    optimistic-reconstruction),
  - 4714-4726 (`BLOCKTXN` thin dispatch into `ProcessCompactBlockTxns`),
  - 5891-5928 (`SendMessages` HB-announce SEND side).
- `net_processing.h:47` (`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`).

**Production code changes:** 0 (pure audit).
**Test file:** `crates/network/tests/test_w126_bip152_compact_blocks.rs` —
30 gates: 13 PASS regression pins + 17 `#[ignore]`-pinned `BUG-N` stubs.

## Why this matters

Compact-block relay is THE block-relay fast path between modern Bitcoin
nodes. BIP-152 was deployed in 2016 and Core only supports
`CMPCTBLOCKS_VERSION = 2` (segwit-aware) since 2017. A correct compact-block
implementation has three observable surfaces:

1. **Receive (decode + reconstruct).** `cmpctblock` →
   `PartiallyDownloadedBlock::InitData` → `getblocktxn` round-trip →
   `BLOCKTXN` → `FillBlock` → `ProcessNewBlock`. Failures here mean falling
   back to a full-block `getdata`, which is slower but not consensus-breaking.
2. **Send (announce side).** After we validate a new block, Core's
   `NewPoWValidBlock` immediately pushes `cmpctblock` to every HB peer
   (and ONLY the 3 HB peers). This is *the* low-latency block-relay path that
   most of the network depends on; if our node never sends `cmpctblock` it
   silently degrades the network — peers stay on slower legacy
   `headers` → `getdata` round-trips when fetching from us.
3. **Anti-DoS.** Core treats malformed compact blocks (`READ_STATUS_INVALID`,
   short-ID collision survivors that fail merkle, header-via-cmpctblock with
   < anti-DoS chainwork) as misbehaviour. Missing checks open us to DoS
   amplification.

W112 (March 2026) identified 8 gates and confirmed two structural gaps:
- `CmpctBlock::from_block` is only called from `#[cfg(test)]`, never in
  production (`compact_blocks.rs:109` constructor + 9 unit-test call sites,
  all under `#[cfg(test)]` at lines 1230, 1249, 1270, 1289, 1326, 1351, 1376,
  1471, 1622, 1644, 1664, 1736, 1858, 1987).
- The `CompactBlockRelay` manager type (`compact_blocks.rs:1001-1146`) is
  defined as `pub` but never instantiated outside its own test module.

W123 G14 + G16 re-affirmed the SEND-side gap and added "no dynamic HB-promote
via `sendcmpct(announce=true)`". W126 expands the audit to a 30-gate matrix
covering BOTH receive- and send-side surfaces in depth, looking for further
PARTIAL/MISSING gates around the well-engineered helpers.

## Headline findings (5 top)

1. **BUG-1 — `CmpctBlock::from_block` dead-helper in production
   (P1, dead-helper-at-call-site, 34-wave-streak continues).**
   `compact_blocks.rs:109` is *only* called from `#[cfg(test)]` (lines
   1234, 1249, 1270, 1289, 1326, 1351, 1376, 1471, 1512, 1544, 1556, 1576,
   1622, 1644, 1664, 1736, 1858, 1987). `main.rs` never serializes a
   `cmpctblock` to push to peers — neither in `NewPoWValidBlock`-equivalent
   nor as a `getdata`-served response (see BUG-2). Net effect: rustoshi
   *receives* compact blocks but is incapable of *sending* them. This is the
   send-side counterpart to W112's BUG-G29 ("CompactBlockRelay dead helper")
   and W123's G14.

2. **BUG-2 — `getdata(MSG_CMPCT_BLOCK)` silently dropped
   (P1, missing-case-fall-through).**
   `main.rs:3343-3384` matches `MsgBlock | MsgWitnessBlock | MsgTx |
   MsgWitnessTx` in the `GetData` handler and falls through `_ => {}` for
   `MsgCmpctBlock`. Core (`net_processing.cpp:2466-2471`) responds to such
   getdata with a fresh `cmpctblock` when `pindex->nHeight >= tip->nHeight -
   MAX_CMPCTBLOCK_DEPTH`. Combined with BUG-1, rustoshi cannot answer
   *any* request for a compact block.

3. **BUG-3 — `sendcmpct(version=1)` silently accepted
   (P2-DoS-divergence).**
   `compact_blocks.rs:957-969` (`PeerCompactBlockState::handle_sendcmpct`)
   accepts `version == CMPCT_VERSION_1` and registers the peer as
   "supports compact blocks". Core (`net_processing.cpp:3907`):
   `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;` — silently
   ignores any version != 2. A malicious peer can register itself as a
   compact-block peer using v1 (no-segwit witness), and on a future
   "send" hook (today: BUG-1 dead, but post-fix this risk lights up) we
   would emit non-segwit `cmpctblock`s. Pure spec-divergence today, gun
   pointed at our foot once BUG-1 lands.

4. **BUG-4 — Anti-DoS chain-work check missing on incoming `cmpctblock`
   (P0).** Core (`net_processing.cpp:4490-4494`) gates incoming
   `cmpctblock` headers via
   `prev_block->nChainWork + GetBlockProof(cmpctblock.header) <
   GetAntiDoSWorkThreshold()` and quietly drops the message. Rustoshi
   (`main.rs:3826-3914`) does **no** chain-work pre-check; the header is
   decoded and passed straight into reconstruction. Spam path: a peer
   feeds us a stream of low-work header-bearing `cmpctblock` messages
   forcing us to walk the mempool every time. Misbehaving is only fired
   on decode error or merkle mismatch.

5. **BUG-5 — Header-disconnect-or-getheaders branch missing
   (P1).** Core (`net_processing.cpp:4483-4489`) on a `cmpctblock`
   whose `hashPrevBlock` we don't have looks up
   `prev_block = LookupBlockIndex(hashPrevBlock)`; if null and we're not
   in IBD it calls `MaybeSendGetHeaders` to ask the peer for the missing
   parent. Rustoshi has no equivalent — an orphan-prev `cmpctblock`
   triggers `init_data` to return `ReadStatus::Invalid` (the empty short
   IDs *and* prefilled-txn check at `compact_blocks.rs:643`), and we
   reply with a full-block `getdata` (`main.rs:3890-3896`). Net effect:
   we always pull the full block instead of catching up via
   `getheaders`, even when the peer holds the missing ancestor.

(See full bug list under "Bug summary" below for the other 12.)

## Gate summary (30 gates)

| # | Surface | Status | Bug | Severity |
|---|---------|--------|-----|----------|
| G1 | `SHORTTXIDS_LENGTH == 6` constant + 6-byte short-id wire layout | OK | — | — |
| G2 | `CMPCTBLOCKS_VERSION == 2` matches Core (segwit-aware) | OK | — | — |
| G3 | `MAX_CMPCTBLOCK_PEERS_HB == 3` constant matches Core | OK | — | — |
| G4 | SipHash key derivation: SHA256(header ‖ nonce), k0/k1 from bytes [0..16] | OK | — | — |
| G5 | Short-id always uses `wtxid` (v2; v1-txid not supported) | OK | — | — |
| G6 | `sendcmpct` wire codec — 1B announce + 8B LE version | OK | — | — |
| G7 | `CmpctBlock` decode: header‖nonce‖shortid-vec‖prefilled-vec | OK | — | — |
| G8 | `PrefilledTx` differential-index encode/decode | OK | — | — |
| G9 | `BlockTransactionsRequest` (getblocktxn) differential indexes | OK | — | — |
| G10 | `BlockTransactions` (blocktxn) full-tx vector codec | OK | — | — |
| G11 | DoS cap: `MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` on shortid + prefilled vec sizes (Core `blockencodings.cpp:64`) | OK | — | — |
| G12 | `PartiallyDownloadedBlock::InitData` empty/null guard (Core line 62-67) | OK | — | — |
| G13 | InitData bucket-load DoS guard (Core `blockencodings.cpp:110-111`, "12 elements per bucket") | OK | — | — |
| G14 | InitData short-id exact-collision detection returns `READ_STATUS_FAILED` (Core line 115-116) | OK | — | — |
| G15 | InitData mempool walk: first-match fill, second-match permanent-suppress (Core line 121-145) | OK | — | — |
| G16 | InitData extra-txn walk: wtxid-different collision discriminator (Core line 147-176) | OK | — | — |
| G17 | `FillBlock` mutation check (`IsBlockMutated`) runs after fill (Core line 218-222) | OK | — | — |
| G18 | `FillBlock` `SetNull()` resets header/txn_available even on failure (Core line 211) | OK | — | — |
| G19 | `peer.rs` sends `sendcmpct(announce=false, version=2)` on outgoing v1 + v2 handshake (Core `net_processing.cpp:3870`) | OK | — | — |
| G20 | Incoming `cmpctblock` handler decode + Misbehaving-on-bad-decode | OK | — | — |
| G21 | Incoming `getblocktxn` handler — serves block.transactions slice if block known | PARTIAL | BUG-6 / BUG-7 | P2 / P2 |
| G22 | Incoming `blocktxn` handler — finishes reconstruction + block submission | OK | — | — |
| G23 | Send-side `CmpctBlock::from_block` called in production (NewPoWValidBlock-equivalent) | **MISSING** | **BUG-1** | **P1** |
| G24 | `getdata(MSG_CMPCT_BLOCK)` served with a `cmpctblock` response | **MISSING** | **BUG-2** | **P1** |
| G25 | `sendcmpct` v1 rejected (Core only accepts version == 2) | **BUG** | **BUG-3** | **P2** |
| G26 | Incoming `cmpctblock` anti-DoS chain-work pre-check (Core line 4490) | **MISSING** | **BUG-4** | **P0** |
| G27 | Incoming `cmpctblock` orphan-prev → `MaybeSendGetHeaders` (Core line 4483-4489) | **MISSING** | **BUG-5** | **P1** |
| G28 | Incoming `cmpctblock` loading/IBD guard ("LoadingBlocks") (Core line 4468-4472) | **MISSING** | **BUG-8** | **P2** |
| G29 | Incoming `cmpctblock` `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK == 3` constant + enforcement (Core `net_processing.h:47`, `net_processing.cpp:4577`) | **MISSING** | **BUG-9** | **P2** |
| G30 | `MAX_BLOCKTXN_DEPTH == 10` cap on `getblocktxn` responses (Core `net_processing.cpp:138-141, 4276-4302`) | **MISSING** | **BUG-7** | **P2** |

Counter row totals: **OK 13 / PARTIAL 1 / MISSING 16 / BUG 17 distinct findings.** (G21 PARTIAL accounts for two MISSING checks BUG-6 + BUG-7; the gate row is counted as PARTIAL once.)

## Bug summary

| Bug | Gate | Severity | One-liner |
|-----|------|----------|-----------|
| BUG-1 | G23 | P1 (dead-helper) | `CmpctBlock::from_block` only invoked from `#[cfg(test)]`; rustoshi never sends a `cmpctblock` to peers. |
| BUG-2 | G24 | P1 (missing-case) | `GetData` handler at `main.rs:3343` falls through `_ => {}` for `MsgCmpctBlock`. |
| BUG-3 | G25 | P2 (spec-divergence) | `PeerCompactBlockState::handle_sendcmpct` accepts `version == 1`; Core ignores any version != 2. |
| BUG-4 | G26 | P0 (DoS) | Incoming `cmpctblock` does not check `prev_block->nChainWork + GetBlockProof < GetAntiDoSWorkThreshold()`. |
| BUG-5 | G27 | P1 (efficiency) | `cmpctblock` with unknown prev-hash never triggers `getheaders`; falls back to full-block getdata. |
| BUG-6 | G21 | P2 (DoS) | `getblocktxn` handler does not Misbehaving on out-of-range index (Core net_processing.cpp:2603 sends `"getblocktxn with out-of-bounds tx indices"`). |
| BUG-7 | G21 / G30 | P2 (DoS) | No `MAX_BLOCKTXN_DEPTH=10` cap; an attacker can request `getblocktxn` for arbitrarily-deep blocks forcing disk reads. |
| BUG-8 | G28 | P2 (state-leak) | No `LoadingBlocks`/IBD guard on incoming `cmpctblock`; we run the full reconstruction path during importing. |
| BUG-9 | G29 | P2 (DoS) | `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3` constant not defined; per-block in-flight cap never enforced. |
| BUG-10 | G23 | P3 | `peer_manager.rs::handle_event(PeerEvent::Message(SendCmpct))` is a no-op — main.rs forwards the message but the manager has no `SendCmpct` arm. |
| BUG-11 | — | P3 | `CompactBlockRelay` defined `pub` (`compact_blocks.rs:1001-1146`) but never instantiated outside `#[cfg(test)]`. Same shape as W112 BUG-G29; pinned here for fleet-wide cross-ref. |
| BUG-12 | — | P3 | `PeerCompactBlockState::last_cmpctblock` written but never read (W112 BUG-G30; pinned). |
| BUG-13 | G24 | P3 | `CompactBlockRelay::create_cmpctblock_inv` is a public free function never called from production. |
| BUG-14 | — | P3 | `main.rs:3865` falls back to full-block `getdata` when `miss_pct > 50%`; Core does not have such a heuristic — it always rolls forward through `getblocktxn` and only falls back on `READ_STATUS_FAILED`. Cosmetic-perf drift; flagged for parity. |
| BUG-15 | G21 | P3 | `getblocktxn` handler reads block from `block_store` only; Core consults `m_most_recent_block` (the in-RAM tip cache) first (line 4253-4264) to avoid disk I/O on hot path. |
| BUG-16 | — | P3 | No `vExtraTxnForCompact`-equivalent: `main.rs:3841` passes `&[]` to `init_data`. Core walks an orphan-tx ring buffer (`net_processing.cpp::vExtraTxnForCompact`) so recently-seen-but-evicted orphans still resolve short-ids. |
| BUG-17 | — | P3 | `peer.rs:1015, 1241, 1945` always sends `announce=false`; rustoshi never proactively promotes a peer to high-bandwidth via a follow-up `sendcmpct(announce=true)` (matches W123 G16; pinned). |

**Comment-as-confession streak:** W126 finds 0 confessional comments in the
production path. Streak continues at 12 waves.
**Dead-helper-at-call-site streak:** W126 reaffirms `CmpctBlock::from_block`
+ `CompactBlockRelay` + `create_cmpctblock_inv` + `PeerCompactBlockState::
last_cmpctblock` as four dead-helper sub-instances. Streak continues at
34 waves.

## Detailed gate-by-gate notes

### G1-G10 — Wire codec layer (all PRESENT)

The wire-level codec at `compact_blocks.rs:254-528` is faithful to Core's
`blockencodings.h`:

- **G1** — `SHORTTXIDS_LENGTH = 6` (`compact_blocks.rs:30`); each short-id
  is encoded as 6 little-endian bytes (line 263-264).
- **G2** — `CMPCT_VERSION_2 = 2` (`compact_blocks.rs:39`); outgoing
  `sendcmpct` always sends `version=2` (`peer.rs:1020`).
- **G3** — `MAX_CMPCTBLOCK_PEERS_HB = 3` (`compact_blocks.rs:33`).
- **G4** — SipHash key derivation at `compact_blocks.rs:194-208`:
  `SHA256(header.serialize() ‖ nonce.to_le_bytes())`, k0/k1 = bytes [0..8]
  and [8..16]. Matches Core `blockencodings.cpp:35-44` (single SHA256).
- **G5** — `compact_blocks.rs:131, 179, 227-235`: short-id is always
  computed from `wtxid`. The Core spec only ever supports v2 (wtxid-based);
  rustoshi never uses txid even when handling `CMPCT_VERSION_1` from a
  remote peer — see BUG-3 for the related divergence (v1 is silently
  accepted but the wire format is v2 regardless).
- **G6** — `sendcmpct` payload: 1B announce + 8B LE version
  (`message.rs:1051-1059`). Bit-for-bit Core compatible.
- **G7** — `CmpctBlock::decode` at `compact_blocks.rs:285-357`. Order:
  header (80B), nonce (8B LE), shortid-vec, prefilled-vec. Matches Core
  `blockencodings.h:121-130`.
- **G8** — Differential index decoded with overflow guards
  (`compact_blocks.rs:321-334`).
- **G9** — `BlockTxnRequest` differential index codec at
  `compact_blocks.rs:382-448`.
- **G10** — `BlockTxn` at `compact_blocks.rs:459-528`.

### G11-G18 — Reconstruction layer (all PRESENT, comprehensive)

`PartiallyDownloadedBlock::init_data` at `compact_blocks.rs:636-798` is one
of the most carefully-Core-aligned modules in the codebase — visible from
the inline `// Core blockencodings.cpp:XXX-YYY` reference comments at
lines 679, 704, 712, 729, 763, 778, and from the explicit collision-
permanent-suppress logic. This is the *opposite* of dead-helper: it is wired
into `main.rs:3840`, and exercised by the integration test
`test_w112_compact_blocks::integration_full_reconstruction_from_mempool`.

The same goes for `is_block_mutated` at `compact_blocks.rs:540-600`
(coinbase witness commitment + merkle root check) — matches Core
`validation.cpp:4027-4056`.

### G19-G20 — Peer-side handshake + incoming-decode (PRESENT)

- **G19** — `peer.rs:1015-1026` (v1 outbound), `peer.rs:1241-1254` (v1
  inbound), `peer.rs:1945-1957` (v2 BIP-324 inbound). All three sites send
  `SendCmpctMessage { announce: false, version: 2 }`. The `announce:false`
  is canonical: Core `net_processing.cpp:3870` "we do not request new
  block announcements using cmpctblock messages" — we ask the peer to send
  us inv/headers first, then we round-trip via getblocktxn.
- **G20** — `main.rs:3826-3914` decodes `CmpctBlock` and on decode error
  bumps `MisbehaviorReason::InvalidCompactBlock` (100-pt instant ban via
  `peer_manager.rs::misbehaving`, line 3905-3911).

### G21 — `getblocktxn` handler (PARTIAL)

`main.rs:3916-3935` decodes the request and serves
`block.transactions[idx]` for each requested index. Two gaps:

- **BUG-6** — No bounds check before indexing. The current code uses
  `block.transactions.get(idx as usize).map(...)` which returns `None`
  silently if out-of-range; Core (`net_processing.cpp:2602-2604`) fires
  `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` on the
  same condition. A peer can spam getblocktxn with bogus indices without
  consequence.
- **BUG-7** — No `MAX_BLOCKTXN_DEPTH = 10` cap. Core
  (`net_processing.cpp:4276-4302`) refuses to serve `getblocktxn` for
  blocks older than `tip - 10` and instead forces the requester onto a
  full-block `getdata` (intentional: to make the attacker pay for the disk
  read). Rustoshi serves every request unconditionally. Pinned as a
  P2 DoS gap; matches W112 BUG-G27's MAX_BLOCKTXN_DEPTH leg.
- **BUG-15** — Reads via `block_store.get_block` (disk I/O) even when
  the requested block is the most recent tip in RAM. Core
  (`net_processing.cpp:4254-4264`) caches the most-recent block under
  `m_most_recent_block_mutex` to avoid the disk path.

### G22 — `blocktxn` handler (PRESENT, recent fix)

`main.rs:3937-4058` (added some time after W112's "BUG-G20: blocktxn
handler dead"; this is now a complete leg). Looks up the in-flight
`PartiallyDownloadedBlock` keyed by `(peer_id, block_hash)` via
`inflight_partial_blocks: HashMap<(u64, Hash256), PartiallyDownloadedBlock>`,
calls `partial.fill_block(blocktxn.transactions, segwit_active)`, and on
`Ok` invokes `block_downloader.block_received(peer_id, block)`. On
`ReadStatus::Failed` (merkle mismatch) it fires `MisbehaviorReason::
InvalidCompactBlock` and falls back to a full-block getdata. The
`inflight_partial_blocks` map is also retained-cleared on `Disconnected`
(`main.rs:4076`).

### G23 — SEND-side `CmpctBlock` construction (MISSING) → BUG-1

`grep -nE "CmpctBlock::from_block" rustoshi/ crates/ --include="*.rs"` finds
zero matches outside `#[cfg(test)]`. Specifically:

```
crates/network/src/compact_blocks.rs:109:    pub fn from_block(...)
crates/network/src/compact_blocks.rs:142:    pub fn from_block_with_prefilled(...)
crates/network/src/compact_blocks.rs:1234:        let compact = CmpctBlock::from_block(&block, nonce);  // #[cfg(test)]
crates/network/src/compact_blocks.rs:1249:        let compact = CmpctBlock::from_block(&block, nonce);  // #[cfg(test)]
...  (12 more #[cfg(test)] sites)
```

Plus the *callees* `CompactBlockRelay::get_high_bandwidth_peers`,
`CompactBlockRelay::store_partial_block`, `CompactBlockRelay::
record_success`, `CompactBlockRelay::create_cmpctblock_inv` are all
`pub` but never invoked outside the same `#[cfg(test)]` module.

Core's symmetric site is `net_processing.cpp::NewPoWValidBlock`
(line 2105-2152): when chain tip advances past `m_highest_fast_announce`,
build a fresh `CBlockHeaderAndShortTxIDs` with a random nonce and push it
to every HB peer via `ForEachNode`. Rustoshi's equivalent hook in
`block_received` / chain-extend never runs this code.

Same gap from W112 BUG-G29 (P1) and W123 G14 (PARTIAL P1). Pinned here
under W126 BUG-1 as a 30-gate audit must-include.

### G24 — `getdata(MSG_CMPCT_BLOCK)` served (MISSING) → BUG-2

`main.rs:3339-3386` matches `MsgBlock | MsgWitnessBlock | MsgTx |
MsgWitnessTx` and **falls through `_ => {}` for `MsgCmpctBlock`**. Core
(`net_processing.cpp:2466-2471`) serves recent cmpctblocks for requests
within `MAX_CMPCTBLOCK_DEPTH = 5` of the tip, and uses
`a_recent_compact_block` (the cached `most_recent_compact_block` shared with
HB-announce) when the hash matches.

This is also blocked behind BUG-1: even if we added the arm here, we have
no `most_recent_compact_block` cache to serve from, and we have to
construct one on demand. The fix is a single block of code, but its
upstream prerequisite (BUG-1) makes it order-dependent.

### G25 — `sendcmpct(version != 2)` rejected (BUG) → BUG-3

`compact_blocks.rs:946-969`:

```rust
pub fn handle_sendcmpct(&mut self, announce: bool, version: u64) {
    if version == CMPCT_VERSION_2 {
        self.enabled = true;
        self.version = version;
        ...
    } else if version == CMPCT_VERSION_1 {
        // Accept version 1 but we prefer version 2
        if self.version == 0 {
            self.enabled = true;
            ...
        }
    }
}
```

Core (`net_processing.cpp:3907`):

```cpp
// Only support compact block relay with witnesses
if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
```

Effect: rustoshi accepts a v1 peer and stores `version = 1` in
`PeerCompactBlockState`. Once BUG-1 lands and we start emitting
cmpctblocks, the `get_version(peer_id)` query will report 1, which (if
honored as a serialization-version dispatch) would emit non-segwit
short-ids — a quiet wire-format break with that peer.

### G26 — anti-DoS chain-work pre-check (MISSING) → BUG-4 (P0)

`main.rs:3826-3914` decodes the `cmpctblock` and immediately enters
`PartiallyDownloadedBlock::init_data`. There is no equivalent of Core's
gate at `net_processing.cpp:4490-4494`:

```cpp
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) <
           GetAntiDoSWorkThreshold()) {
    // If we get a low-work header in a compact block, we can ignore it.
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n",
             pfrom.GetId());
    return;
}
```

`GetAntiDoSWorkThreshold` returns max(chainparams.MinimumChainWork,
0.5 × current-tip-chainwork) in Core. A peer can flood us with
*valid-PoW low-work* cmpctblock headers (e.g. mining at testnet
difficulty, or on a sandbox chain) and we will walk the mempool every
time. Pinned P0 because it is the only Core-aligned defense against the
"flood low-work compact blocks" path; the mempool walk in `init_data`
is O(mempool size).

### G27 — orphan-prev → `MaybeSendGetHeaders` (MISSING) → BUG-5

Core (`net_processing.cpp:4483-4489`):

```cpp
const CBlockIndex* prev_block =
    m_chainman.m_blockman.LookupBlockIndex(cmpctblock.header.hashPrevBlock);
if (!prev_block) {
    // Doesn't connect (or is genesis), instead of DoSing in AcceptBlockHeader,
    // request deeper headers
    if (!m_chainman.IsInitialBlockDownload()) {
        MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer);
    }
    return;
}
```

Rustoshi has no equivalent. On orphan-prev, `init_data` returns
`ReadStatus::Invalid` (the empty-shortid+prefilled check, but more
typically just an unrelated decode error), and main.rs falls back to a
full-block getdata at line 3890-3896 — wasting bandwidth when a single
getheaders would let us catch up.

### G28 — `LoadingBlocks` / IBD guard on incoming `cmpctblock` (MISSING) → BUG-8

Core (`net_processing.cpp:4468-4472`):

```cpp
// Ignore cmpctblock received while importing
if (m_chainman.m_blockman.LoadingBlocks()) {
    LogDebug(BCLog::NET, "Unexpected cmpctblock message received from peer %d\n",
             pfrom.GetId());
    return;
}
```

Rustoshi's `main.rs:3826` always proceeds. Net effect during a fresh-IBD
phase: a peer can drive the mempool walk in `init_data` while we're
trying to deserialize the on-disk block files. Low-impact (we'd just be
slow), but a missing parity gate.

### G29 — `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` cap (MISSING) → BUG-9

Core (`net_processing.h:47`): `static const unsigned int
MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;`
Core (`net_processing.cpp:4577`):

```cpp
if ((already_in_flight < MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK &&
     nodestate->vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER) ||
    requested_block_from_this_peer) {
```

Rustoshi's `inflight_partial_blocks: HashMap<(u64, Hash256),
PartiallyDownloadedBlock>` (main.rs:2282-2285) has neither this constant
nor the cap. A peer could in theory open 1000 partial-block reconstructions
in parallel (one per distinct hash) and consume O(mempool size × 1000)
memory. Practical impact bounded by peer's outbound msgrate, but no spec-
aligned cap exists.

### G30 — `MAX_BLOCKTXN_DEPTH = 10` constant + enforcement (MISSING) → BUG-7

Already discussed under G21 / BUG-7. Pinned again as a standalone gate
because the constant itself is missing from the rustoshi tree (`grep -rn
"MAX_BLOCKTXN_DEPTH\b" rustoshi/ crates/` → 0 matches).

## Closing notes

This is a discovery audit only. No production code changes. All test
stubs are `#[ignore]`-marked with explicit `BUG-N` references back to
this file, so when the eventual fix wave lands the operator can simply
unignore each gate test and verify it transitions PASS.

**Cross-wave bug-ref summary:**

- **W112** BUG-G27 (MAX_CMPCTBLOCK_DEPTH/MAX_BLOCKTXN_DEPTH) → W126 BUG-7
  (+ formal G30 standalone gate).
- **W112** BUG-G29 (CompactBlockRelay dead helper) → W126 BUG-1, BUG-11,
  BUG-13 (sub-instance breakdown).
- **W112** BUG-G30 (last_cmpctblock unused) → W126 BUG-12 (pin).
- **W123** G14 (cmpctblock_construction_only_tests) → W126 BUG-1 (same
  finding, formally re-raised in this 30-gate audit).
- **W123** G16 (no dynamic HB-promote) → W126 BUG-17 (pin).

**Fix sequencing recommendation (when the wave lands):**

1. **BUG-4 (P0)** — anti-DoS chain-work check. One-line guard, no upstream
   deps. Always fix P0 first.
2. **BUG-1 (P1)** — wire `CmpctBlock::from_block` into the new-tip path
   (mirrors Core `NewPoWValidBlock`). Required prerequisite for BUG-2,
   BUG-13.
3. **BUG-2 (P1)** — `getdata(MSG_CMPCT_BLOCK)` handler. Trivial once BUG-1
   lands.
4. **BUG-5 (P1)** — orphan-prev `getheaders` instead of full-block
   `getdata`.
5. **BUG-3 (P2)** — reject `sendcmpct(version != 2)`. One-line.
6. **BUG-6, BUG-7, BUG-8, BUG-9** — P2 DoS gates; bundled together makes
   sense.
7. **BUG-10 — BUG-17** — P3 cleanup, mostly cosmetic + dead-state pruning.

Total estimated: 4 P1 + 1 P0 (anti-DoS) + 4 P2 + 8 P3 = 17 findings on
30 gates.
