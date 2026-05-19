# W156 — BIP-152 wire-level deep-dive: sendcmpct + cmpctblock + getblocktxn + blocktxn (rustoshi)

**Wave:** W156 — BIP-152 compact-block relay wire layer (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi BIP-152 wire surface — short-ID derivation,
PrefilledTransaction differential codec, getblocktxn / blocktxn round-trip,
PartiallyDownloadedBlock reconstruction loop, MAX_BLOCKTXN_DEPTH / depth
gates, HB-peer selection, version negotiation, and the
production-side dispatchers in `main.rs` that drive the four wire messages.

**Scope vs prior waves:** **W126** (May 17 2026) covered BIP-152 fundamentals
on rustoshi — the 30-gate audit (`crates/network/tests/test_w126_bip152_compact_blocks.rs`
+ `audit/w126_bip152_compact_blocks.md`) catalogued 17 BUGs at the policy and
peer-state level. **W156** is the wire-level deep-dive: this is a re-audit
two days later that re-examines the same code through the wire-codec lens
(symmetric encode/decode, differential-encoding overflow, witness-format
asymmetry, recent-block cache, DoS surface on the partial-block map,
duplicate-key timeout), and also picks up gaps W126 left on the table
(`u16` `BlockTxCount()` total-count check; cast-to-`i32` from `u64`;
short-id `txns_randomized` iteration order; depth caps on **both** sides of
the request; assume-valid scope interactions; dead-data plumbing).

**Files audited:**
- `crates/network/src/compact_blocks.rs` (2080 LOC) — `CmpctBlock`,
  `PrefilledTx`, `BlockTxnRequest`, `BlockTxn`, `PartiallyDownloadedBlock`,
  `PeerCompactBlockState`, `CompactBlockRelay`, `is_block_mutated`.
- `crates/network/src/message.rs:75-112, 213-219, 332-339, 790-802,
  1051-1063` — wire codec, InvType enum, NetworkMessage variants.
- `crates/network/src/peer.rs:1015-1026, 1241-1254, 1945-1957` — outbound
  `sendcmpct` send sites on three handshake paths (v1 inbound, v1 outbound,
  v2 BIP-324).
- `crates/network/src/peer_manager.rs:1733-1760, 2017-2161, 1942-2172` —
  `announce_block` (BIP-130 only, never cmpctblock), `handle_event` (no
  `SendCmpct` arm), forwarded-message swallow.
- `rustoshi/src/main.rs:2282-2285, 3061-3096, 3339-3386, 3814-4076` —
  `inflight_partial_blocks` HashMap, `Inv`/`GetData` handlers (no
  `MsgCmpctBlock` case), `SendCmpct`/`CmpctBlock`/`GetBlockTxn`/`BlockTxn`
  arms.
- `crates/consensus/src/mempool.rs:3214-3221` — `collect_for_compact_block`.
- `crates/network/src/misbehavior.rs:48, 85, 111, 133` —
  `INVALID_COMPACT_BLOCK = 100` penalty.

**Bitcoin Core references:**
- `bitcoin-core/src/blockencodings.{h,cpp}` (lines 1-237):
  - `CBlockHeaderAndShortTxIDs(const CBlock& block, uint64_t nonce)` ctor
    (cpp:20-33) — `shorttxids[i-1] = GetShortID(tx.GetWitnessHash())` (v2
    is always wtxid).
  - `FillShortTxIDSelector` (cpp:35-44) — `DataStream stream{}; stream <<
    header << nonce; CSHA256.Write(...).Finalize(...); k0 =
    hash.GetUint64(0); k1 = hash.GetUint64(1)`. SipHash-2-4 with the
    presalted-key.
  - `GetShortID` (cpp:46-50) — `(*m_hasher)(wtxid.ToUint256()) &
    0xffffffffffffL` — top 48 bits truncated.
  - `InitData` (cpp:59-181) — DoS caps (`tx_count >
    MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TRANSACTION_WEIGHT`), prefilled
    differential decode, bucket-size DoS guard ≤12 (cpp:110-111), exact
    short-id collision (cpp:115-116), mempool walk via
    `pool->txns_randomized` (cpp:121) with first-match-fills /
    second-match-clears (cpp:125-137), extra-txn walk with witness-hash
    discriminator (cpp:163-164).
  - `FillBlock` (cpp:191-237) — fills missing slots, `header.SetNull()` to
    prevent re-fill (cpp:211), `IsBlockMutated(block, segwit_active)`
    post-check (cpp:218-222) to catch short-id collision survivors.
  - SERIALIZE_METHODS for `CBlockHeaderAndShortTxIDs` (h:121-130) —
    `obj.header, obj.nonce, Using<VectorFormatter<CustomUintFormatter<6>>>(
    obj.shorttxids), obj.prefilledtxn`. **Decoder check at h:125-127:
    `if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max())
    throw "indexes overflowed 16 bits"`.**
  - `SERIALIZE_METHODS(PrefilledTransaction, ...)` (h:80) —
    `COMPACTSIZE(obj.index), TX_WITH_WITNESS(Using<TransactionCompression>(
    obj.tx))`. The `index` is differential at encode-time, absolute at
    decode-time, via `DifferenceFormatter` (h:23-43) which strictly checks
    `m_shift < n` overflow and target-type bounds.
  - `BlockTransactionsRequest` (h:45-55) —
    `READWRITE(obj.blockhash, Using<VectorFormatter<DifferenceFormatter>>(
    obj.indexes))`. **Vector of `uint16_t` with differential encoding.**
  - `BlockTransactions` (h:57-71) —
    `READWRITE(obj.blockhash, TX_WITH_WITNESS(Using<VectorFormatter<
    TransactionCompression>>(obj.txn)))`. **Vector of full transactions
    WITH WITNESS.**
- `bitcoin-core/src/net_processing.cpp`:
  - line 138-141 — `MAX_CMPCTBLOCK_DEPTH = 5` (send-side serve cap),
    `MAX_BLOCKTXN_DEPTH = 10` (receive-side getblocktxn cap),
    `static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP)`.
  - line 199 — `static constexpr uint64_t CMPCTBLOCKS_VERSION{2}` (the
    only supported version; v1 is rejected outright).
  - lines 1272-1329 — `MaybeSetPeerAsAnnouncingHeaderAndIDs` — picks up
    to 3 HB peers, **lNodesAnnouncingHeaderAndIDs.size() >= 3** cap,
    sends `sendcmpct(announce=true, version=2)` to promote.
  - lines 2103-2152 — `NewPoWValidBlock` — the SEND-side fast-announce
    that builds a fresh `CBlockHeaderAndShortTxIDs` on every new tip and
    pushes it to every HB-set peer.
  - lines 2466-2471 — `getdata(MSG_CMPCT_BLOCK)` responds with
    `m_most_recent_compact_block` cache when within `MAX_CMPCTBLOCK_DEPTH`,
    else falls back to full block.
  - lines 2598-2615 — `SendBlockTransactions` — out-of-range index →
    `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")`
    (100-pt).
  - lines 3441-3526 — `ProcessCompactBlockTxns` — fill-block, mutated
    check, `mapBlockSource.emplace(... false)` so "valid headers, bad
    block" doesn't punish.
  - lines 3901-3917 — `SENDCMPCT` handler: **if (sendcmpct_version !=
    CMPCTBLOCKS_VERSION) return** — silently drops v1 (or v0, v3, …).
  - lines 4245-4304 — `GETBLOCKTXN` handler with depth gate at line 4276
    (`pindex->nHeight >= ActiveChain().Height() - MAX_BLOCKTXN_DEPTH` —
    older blocks served via full-block getdata instead).
  - lines 4466-4712 — `CMPCTBLOCK` handler (anti-DoS chainwork gate,
    LoadingBlocks/IBD gate, optimistic-reconstruction branch).
  - lines 4714-4726 — `BLOCKTXN` thin dispatch into
    `ProcessCompactBlockTxns`.
- `bitcoin-core/src/net_processing.h:47` —
  `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` (per-block in-flight cap; not
  per-peer cap).
- `bitcoin-core/src/net_processing.h:43, 84` —
  `DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100` — the
  `vExtraTxnForCompact` ring-buffer of recently-seen orphan txs that gets
  passed into `InitData` so an orphan we've already heard about can
  resolve a short-id without a getblocktxn round-trip.

**BIPs / specs:**
- BIP-152: <https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki>
- BIP-141 (witness): used for v2 short-ID = SipHash-2-4(wtxid).
- BIP-339 (wtxidrelay) cross-ref: same wtxid used as short-id key.

**Production code changes:** 0 (pure audit).

---

## Why this matters

W126 already established that rustoshi cannot SEND compact blocks
(BUG-1: `CmpctBlock::from_block` only called from `#[cfg(test)]`;
BUG-2: `getdata(MSG_CMPCT_BLOCK)` falls through). W156 takes a
wire-codec scalpel to what remains — the *receive* path and the
*serve* path for getblocktxn — and finds a second band of dead-data
plumbing (CompactBlockRelay struct never instantiated, peer-state never
tracked outside the local test module), three wire-codec
under-rejections (no `BlockTxCount() > u16::MAX` total check on
deserialize; `read_compact_size as i32` wrap on differential-decode;
`saturating_add` instead of Core's strict overflow check), and a
DoS-amplification primitive on the `inflight_partial_blocks` HashMap.

Three failure modes recur and all three are fleet-wide patterns:

1. **"Dead-data plumbing" (fleet pattern, instances now in W122/W138/
   W140/W141/W144/W145, and this wave).** `CompactBlockRelay` defines
   per-peer state (enabled / version / wants_high_bandwidth / partial
   blocks / cmpctblock_count / successful_reconstructions) but is never
   instantiated outside `compact_blocks.rs` tests. The production
   `inflight_partial_blocks` HashMap in `main.rs:2282` is a parallel
   bypass. Same as fleet-wide "wiring-look-but-no-wire" archetype.

2. **"Comment-as-confession" (fleet pattern; 5th rustoshi instance
   tracked, prior at W141 BUG-4).** `main.rs:3878-3879` literally
   comments *"Key: (peer_id, block_hash) — one in-flight block per peer
   (Core net_processing.cpp:5028)"* — but the impl uses
   `(peer_id, block_hash)` which is N entries per peer (one per distinct
   block), not "one per peer". The comment documents what Core does, the
   impl ignores it, and the map has no per-peer cap, no global cap, no
   TTL.

3. **"Two-pipeline guard" (fleet pattern, 16th distinct extension across
   waves).** Same primitive lives in two places: the production
   `inflight_partial_blocks` HashMap in `main.rs:2282` AND the unused
   `CompactBlockRelay::peer_states[..].partial_blocks` in
   `compact_blocks.rs:917`. The unused side has eviction hooks
   (`remove_partial_block` at 1098-1102), the live side has none.

The 21 BUGs below split between the two halves of the audit and
extend W126 with wire-codec and DoS-surface findings W126 left on the
table.

---

## Gate matrix (30 sub-gates / 12 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | sendcmpct version negotiation | G1: ONLY accept `version=2`; drop v1/v0/v3 silently | **BUG-1 (P2)** — `compact_blocks.rs:957-969` explicitly enables `v1` when `self.version == 0`. Core's `net_processing.cpp:3907` `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;` drops everything except 2. Carry-forward from W126 BUG-3; the v1 branch is in dead code (BUG-2) so the only observable today is the misleading test surface. |
| 1  | … | G2: Track `m_provides_cmpctblocks` per-peer for SEND-side promote decisions | **BUG-2 (P0-DEAD)** — `CompactBlockRelay` (compact_blocks.rs:1001-1146) is **never instantiated outside `#[cfg(test)]`** (grep `CompactBlockRelay::new` returns 3 hits, all in the test module). The forwarded SendCmpct event from `main.rs:3822` hits `peer_manager.rs::handle_event(PeerEvent::Message)` which has no `SendCmpct` arm — falls through silently. The peer-state side of BIP-152 is **wholly dead**. |
| 1  | … | G3: Track `m_bip152_highbandwidth_from` (peer told us HB) and `m_bip152_highbandwidth_to` (we told peer HB) | **BUG-3 (P1)** — neither flag exists. `PeerCompactBlockState.wants_high_bandwidth` (compact_blocks.rs:913) is the would-be `m_bip152_highbandwidth_from`; it lives in the dead struct (BUG-2). No equivalent on the live `PeerInfo` in `peer.rs`. The receiver path therefore cannot decide later whether to send a follow-up `sendcmpct(announce=true)` (Core does this in `MaybeSetPeerAsAnnouncingHeaderAndIDs`). |
| 2  | sendcmpct outbound | G4: Send `sendcmpct(announce=false, version=2)` after VERSION + ≥ SENDCMPCT_VERSION | PASS — three handshake sites in `peer.rs:1015-1026, 1241-1254, 1945-1957` all gate on `their_version.version >= SENDCMPCT_VERSION (= 70014)` and send announce=false, version=2. |
| 2  | … | G5: Re-issue `sendcmpct(announce=true, version=2)` to promote a peer to HB after they relay a useful block | **BUG-4 (P1)** — no equivalent of Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs` (net_processing.cpp:1272-1329). rustoshi never sends `announce: true` (`grep "announce: true"` in non-test code = 0). Net effect: every peer-relay round-trip pays the full inv/getdata cost; rustoshi is a permanent low-bandwidth-mode receiver. Carry-forward from W126 BUG-17. |
| 3  | short-ID derivation | G6: SipHash-2-4 keys = sha256(header ‖ nonce); k0 = bytes[0..8], k1 = bytes[8..16] | PASS — `compact_blocks.rs:193-208` matches Core `blockencodings.cpp:35-44`. |
| 3  | … | G7: Short-id = SipHash(wtxid) & 0x0000_FFFF_FFFF_FFFF (top 48 bits) | PASS — `compact_blocks.rs:227-235`. |
| 3  | … | G8: v2 always uses wtxid (never txid) | PASS — `compact_blocks.rs:131` uses `tx.wtxid()` in `from_block`. v1 wire-code-path is dead (would still use wtxid in this impl — divergent from BIP-152 v1 which uses txid; harmless because `from_block` is dead per BUG-12 below). |
| 4  | CmpctBlock wire codec | G9: 80B header + 8B nonce + COMPACTSIZE shortids + 6B-each shortids + COMPACTSIZE prefilled + (COMPACTSIZE diff + tx) prefilleds | PASS — `compact_blocks.rs:253-282 / 285-345`. |
| 4  | … | G10: Decoder rejects `prefilled_idx > u16::MAX` (per-tx) | PASS — `compact_blocks.rs:325-329`. |
| 4  | … | G11: Decoder rejects `BlockTxCount() > u16::MAX` (TOTAL, post-decode) | **BUG-5 (P2-CDIV)** — Core enforces `if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) throw "indexes overflowed 16 bits"` at `blockencodings.h:125-127`. rustoshi's `CmpctBlock::decode` (compact_blocks.rs:285-356) only checks the individual `prefilled` index ≤ u16::MAX and the joint `short_ids + prefilled ≤ MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT (= 66_666)`. So a peer can ship a syntactically-valid cmpctblock with 60_000 short_ids + 6_000 prefilled = 66_000 entries (well above u16::MAX=65_535 → indices would alias). |
| 4  | … | G12: Differential-decode of prefilled index uses signed-i32 wrap-safe arithmetic | **BUG-6 (P2)** — `compact_blocks.rs:323` does `let diff = read_compact_size(reader)? as i32`. `read_compact_size` returns `u64`; values > `i32::MAX` (2^31-1) silently wrap. A malicious peer can craft a sequence of COMPACTSIZE-encoded `diff` values that wrap below 0 then `saturating_add` over them, eventually producing a `last_index` that *passes* the `> u16::MAX as i32` check while pointing past `txn_available`. Same shape applies to `BlockTxnRequest::decode` at line 422. Core's `DifferenceFormatter::Unser` (blockencodings.h:35-42) reads as `uint64_t`, accumulates into `m_shift` with explicit overflow check (`if (m_shift < n) throw`), and validates bounds against the *target* type (uint16_t). |
| 5  | PrefilledTx index semantics | G13: `prefilledtxn[0].index = 0` (always coinbase) | PASS — `compact_blocks.rs:122-127`. |
| 5  | … | G14: Strict-increasing-after-differential-add (no two prefilled at same index) | PASS — `compact_blocks.rs:668-671` rejects `ptx.index as i32 <= last_index`. |
| 5  | … | G15: `init_data` validates `index < tx_count` | PASS — `compact_blocks.rs:664-667`. |
| 6  | BlockTxnRequest (getblocktxn) | G16: 32B blockhash + COMPACTSIZE count + (COMPACTSIZE diff each) | PASS — `compact_blocks.rs:388-403`. |
| 6  | … | G17: Decode rejects index overflow per-step | PARTIAL — bounds check at `compact_blocks.rs:424-429` mirrors the wire-codec, but the `as i32` cast bug from G12 applies symmetrically. |
| 6  | … | G18: Out-of-range index in `SendBlockTransactions` → `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` | **BUG-7 (P1)** — `main.rs:3920-3930` uses `block.transactions.get(idx as usize)` → `None` silently filtered with `filter_map`. Core (`net_processing.cpp:2602-2604`) fires `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` (100-pt). Net effect: rustoshi silently returns a *short* blocktxn (or empty) to a malicious peer, the peer sees us as buggy and we lose nothing — but the DoS-amplification surface (the peer can repeat the malformed request indefinitely with no rate limit) stays open. Carry-forward from W126 BUG-6. |
| 7  | BlockTxn (blocktxn) | G19: 32B blockhash + COMPACTSIZE count + TX_WITH_WITNESS each | PASS — `compact_blocks.rs:476-514`. (Note: `Transaction::encode` emits witness data ONLY when `has_witness()` returns true. For a v2 cmpctblock follow-up, Core's `TX_WITH_WITNESS` always emits the witness marker+flag bytes even on empty-witness txns. See BUG-8 below.) |
| 7  | … | G20: Encoder writes BIP-141 witness marker+flag unconditionally (TX_WITH_WITNESS semantics) | **BUG-8 (P2-CDIV)** — `Transaction::encode` (`crates/primitives/src/transaction.rs:327-360`) sets `has_witness = self.inputs.iter().any(|i| !i.witness.is_empty())` and only writes 0x00 0x01 marker+flag if true. Core's `TX_WITH_WITNESS` wrapper always emits the marker+flag in segwit-aware contexts (`primitives/transaction.h::SerializeTransaction` with `fAllowWitness=true`). On the wire this matters for `blocktxn` and `cmpctblock` prefilled coinbase: a coinbase with `vec![witness_nonce]` carries witness data so we'd emit marker+flag; but if a peer prefilled a *witness-stripped* tx (e.g. pre-segwit pruned coinbase) we'd silently emit the legacy format, which Core would reject. Asymmetric wire round-trip. |
| 7  | … | G21: BlockTxn DoS cap = `MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` | PASS — `compact_blocks.rs:497-502`. |
| 8  | PartiallyDownloadedBlock reconstruction | G22: Bucket-size DoS guard ≤12 entries per bucket | PASS — `compact_blocks.rs:704-710` mirrors Core `blockencodings.cpp:110-111`. |
| 8  | … | G23: Exact short-id collision → `ReadStatus::Failed` | PASS — `compact_blocks.rs:712-716` (W89 fix). |
| 8  | … | G24: Mempool collision: first-match fills, second-match clears, third-match doesn't re-fill (`have_txn[i]` permanent-suppress) | PASS — `compact_blocks.rs:734-757` explicitly keeps `have_txn[index] = true` in the collision branch (W126 G19/G20 fix). |
| 8  | … | G25: Extra-txn walk discriminates by wtxid before suppressing | PASS — `compact_blocks.rs:767-793` with comment-as-Core-cite at line 778-779. |
| 8  | … | G26: Mempool iteration order is **randomized** to make DoS short-id collisions infeasible | **BUG-9 (P2)** — `mempool.rs::collect_for_compact_block` (line 3216-3221) does `self.transactions.values()` — a `HashMap` walk that yields an iteration order determined by Rust's default `RandomState`, NOT by Bitcoin Core's per-tx `txns_randomized` shuffled vector (`txmempool.h::MempoolEntryRef`; rebuilt on every insert/remove). The Rust `RandomState` order is process-stable for the lifetime of the map — a long-running rustoshi node's iteration order doesn't reshuffle, so a peer who learns it once can exploit short-id collisions deterministically. Defensive depth lost. |
| 8  | … | G27: Pass `vExtraTxnForCompact` ring-buffer (last 100 recently-seen orphan txs) into `init_data` | **BUG-10 (P3)** — `main.rs:3841` passes `&[]` to `init_data`. Core ships a per-node 100-entry ring buffer of recently-seen orphans (`net_processing.cpp:1887-1890`, `DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100`) so an orphan we already heard about resolves a short-id without round-tripping. Carry-forward from W126 BUG-16. |
| 9  | FillBlock post-check | G28: `IsBlockMutated(block, segwit_active)` runs after the fill loop | PASS — `compact_blocks.rs:881-883`. |
| 9  | … | G29: `header.SetNull() + txn_available.clear()` BEFORE the mutated-check so a failed fill cannot be retried | PASS — `compact_blocks.rs:872-874`. |
| 9  | … | G30: `segwit_active` derived from chainparams + height (DeploymentActiveAfter), not from a global flag | PASS — `main.rs:3835/3969-3972` checks `rpc.params.is_segwit_active(rpc.best_height)`. |
| 10 | Inbound dispatch (live code in main.rs) | G31: `getdata(MSG_CMPCT_BLOCK)` is served with a fresh `cmpctblock` from `m_most_recent_block` cache | **BUG-11 (P1)** — `main.rs:3343-3384` GetData handler matches only `MsgBlock | MsgWitnessBlock | MsgTx | MsgWitnessTx`; falls through `_ => {}` for `MsgCmpctBlock`. Core (`net_processing.cpp:2466-2471`) responds with cached `m_most_recent_compact_block`. Carry-forward from W126 BUG-2. **W156 add:** rustoshi has no `m_most_recent_block` / `m_most_recent_compact_block` cache at all (`grep "most_recent_block\|recent_compact" rustoshi/src/main.rs` = 0). |
| 10 | … | G32: `Inv` of `MsgCmpctBlock` (peer announcing via cmpctblock-inv) triggers headers-or-cmpctblock fetch | **BUG-12 (P2)** — `main.rs:3061-3096` Inv handler matches only Block / WitnessBlock / Tx / WitnessTx; falls through `_ => {}` for `MsgCmpctBlock`. Net effect: a peer announcing a new block via `inv MsgCmpctBlock` (Core does this for non-HB peers post-relay) is silently ignored. **NEW (W126 did not catch this; was focused on getdata side).** |
| 10 | … | G33: `cmpctblock` decode-failure → `Misbehaving(InvalidCompactBlock = 100pt)` | PASS — `main.rs:3900-3912`. |
| 10 | … | G34: `cmpctblock` decode-success → anti-DoS chainwork pre-check before init_data | **BUG-13 (P0)** — `main.rs:3826-3914` invokes `init_data` unconditionally. Core (`net_processing.cpp:4486-4494`) gates on `prev_block->nChainWork + GetBlockProof(header) < GetAntiDoSWorkThreshold()` and drops low-work messages. DoS vector: low-work cmpctblock spam forces a full mempool clone on every message. Carry-forward from W126 BUG-4. |
| 10 | … | G35: `LoadingBlocks()`/IBD guard on inbound cmpctblock | **BUG-14 (P2)** — `main.rs:3826` enters `init_data` unconditionally during IBD. Core (`net_processing.cpp:4468-4472`) early-returns. Carry-forward from W126 BUG-8. |
| 11 | Outbound dispatch (SEND side) | G36: `NewPoWValidBlock` SEND-side: build `cmpctblock` on every new validated tip and push to every HB peer | **BUG-15 (P0-DEAD)** — `CmpctBlock::from_block` (compact_blocks.rs:109) has ZERO non-`#[cfg(test)]` call-sites. rustoshi receives compact blocks but never sends them. `announce_block` (peer_manager.rs:1733-1760) uses BIP-130 headers or MsgWitnessBlock inv — never cmpctblock. Carry-forward from W126 BUG-1. |
| 11 | … | G37: `MAX_CMPCTBLOCK_DEPTH = 5` constant defined; getdata(MSG_CMPCT_BLOCK) serves only blocks within 5 of tip | **BUG-16 (P2)** — `grep MAX_CMPCTBLOCK_DEPTH` in rustoshi/* + crates/*/src = 0 production matches. Per-W126 BUG-7 carry-forward + an extension: even if BUG-15 were fixed and we wired the send-side, there's no depth cap on what we'd serve. |
| 11 | … | G38: HB peer count cap = 3 (`MAX_CMPCTBLOCK_PEERS_HB = 3`) | PARTIAL — constant defined at `compact_blocks.rs:33` and consulted at line 1037 in the dead `CompactBlockRelay::handle_sendcmpct` — but `CompactBlockRelay` is never instantiated (BUG-2). Net effect: defined-and-unused. |
| 12 | getblocktxn serving | G39: Look up block from `m_most_recent_block` cache before disk read | **BUG-17 (P1)** — `main.rs:3920-3930` calls `block_store.get_block(&req.block_hash)` directly. Core (`net_processing.cpp:4254-4264`) tries `m_most_recent_block` first; only if the requested hash differs does it fall back to disk via `m_blockman.ReadBlock`. **DoS amplification:** a malicious peer can spam getblocktxn for the tip and force one disk read per request. Carry-forward from W126 BUG-15. |
| 12 | … | G40: `MAX_BLOCKTXN_DEPTH = 10` depth cap: deeper blocks served via `MSG_WITNESS_BLOCK` full-block path instead | **BUG-18 (P2)** — `main.rs:3920-3930` serves *any* depth unconditionally. Core (`net_processing.cpp:4276-4302`) checks `pindex->nHeight >= ActiveChain().Height() - MAX_BLOCKTXN_DEPTH` and falls back to full-block getdata. **DoS amplification:** attacker forces 10+ deep block reads. Carry-forward from W126 BUG-7. |
| 12 | … | G41: `static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP)` | N/A (BUG-18 — constant absent). |
| —  | DoS surface on inflight_partial_blocks HashMap | G42: Per-peer cap on `partial_blocks` map (at most ONE entry per peer) | **BUG-19 (P0)** — `main.rs:2282-2285, 3880-3881` keys the map by `(peer_id, block_hash)` with no per-peer cap. The comment at `3878-3879` says *"Key: (peer_id, block_hash) — one in-flight block per peer (Core net_processing.cpp:5028)"* — **comment-as-confession** (5th rustoshi instance tracked). A malicious peer can send 1000 distinct cmpctblock with different hashes and stuff 1000 `PartiallyDownloadedBlock`s into the global map. Each `PartiallyDownloadedBlock` holds a header + `txn_available: Vec<Option<Arc<Transaction>>>` + `short_id_map: HashMap<u64, usize>`; with 60_000 prefilled+shortids per block, this is megabytes per attack-message. RAM exhaustion. |
| —  | … | G43: TTL / timeout on partial blocks (`getblocktxn` issued, blocktxn never arrived) | **BUG-20 (P1)** — no timeout. `main.rs:4076` only frees on peer disconnect. If the peer never replies, the partial sits forever. Combined with BUG-19: an attacker connects, sends 1000 cmpctblock, never replies to getblocktxn, holds the connection. Per-peer accumulation until peer banscores out (which requires invalid messages, NOT silent withdrawal). |
| —  | … | G44: Global cap on the partial-blocks map | **BUG-19 cross-cite** — absent. |
| —  | Dead-data plumbing inventory | G45: `PeerCompactBlockState.last_cmpctblock`, `.cmpctblock_count`, `.successful_reconstructions`, `.failed_reconstructions` all written but never read | **BUG-21 (P3)** — `compact_blocks.rs:918-925` defines these fields; their setters are called from `record_success`/`record_failure` (lines 973-979); no reader. They live in the dead `PeerCompactBlockState` struct (BUG-2). Pinned for dead-state inventory. |

---

## BUG-1 (P2) — `sendcmpct(version=1)` is silently accepted; Core rejects everything except version 2

**Severity:** P2 (latent — the v1 branch lives in dead code so the
test-surface divergence is the only observable today). If `CompactBlockRelay`
were wired (which would fix BUG-2), rustoshi would happily negotiate v1 with
a buggy or hostile peer, while Core would silently ignore the message.

**File:** `crates/network/src/compact_blocks.rs:946-970`.

```rust
pub fn handle_sendcmpct(&mut self, announce: bool, version: u64) {
    // We only support version 2 (SegWit)
    if version == CMPCT_VERSION_2 {
        ...
    } else if version == CMPCT_VERSION_1 {
        // Accept version 1 but we prefer version 2
        if self.version == 0 {
            self.enabled = true;
            self.version = version;  // <-- enables a v1 peer
            ...
        }
    }
}
```

**Core ref:** `bitcoin-core/src/net_processing.cpp:3901-3917`:

```cpp
if (msg_type == NetMsgType::SENDCMPCT) {
    bool sendcmpct_hb{false};
    uint64_t sendcmpct_version{0};
    vRecv >> sendcmpct_hb >> sendcmpct_version;
    // Only support compact block relay with witnesses
    if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
    ...
}
```

The Core comment **"// Only support compact block relay with witnesses"**
is load-bearing: a v1 cmpctblock would short-id by *txid* not *wtxid*,
breaking BIP-339 wtxidrelay assumptions on top.

**Impact:** Dead today. Live the moment BUG-2 is fixed and the
`CompactBlockRelay` is wired into the live peer-state.

**Carry-forward:** W126 BUG-3 (one wave open, 30 hours).

---

## BUG-2 (P0-DEAD) — `CompactBlockRelay` and `PeerCompactBlockState` are never instantiated outside `#[cfg(test)]`

**Severity:** P0-DEAD ("dead-data plumbing" fleet pattern). Every BIP-152
peer-state surface — version negotiation, HB vs LB mode, the 3-peer HB cap,
the per-peer `partial_blocks` map, success/failure counters, the
`high_bandwidth_peers: HashSet<PeerId>` index — lives in
`CompactBlockRelay` (`compact_blocks.rs:1001-1146`). The struct is `pub` and
fully implemented, but a `grep CompactBlockRelay::new\|CompactBlockRelay::default`
across `rustoshi/src/` + `crates/*/src/` (excluding `tests/`) returns
**zero matches**. The three matches in the file itself are all inside
`#[cfg(test)] mod tests`.

The live forwarding wire is `main.rs:3814-3823`:

```rust
NetworkMessage::SendCmpct(sc) => {
    tracing::debug!(...);
    let mut ps = peer_state.write().await;
    if let Some(ref mut pm) = ps.peer_manager {
        pm.handle_event(PeerEvent::Message(peer_id, NetworkMessage::SendCmpct(sc))).await;
    }
}
```

But `peer_manager.rs::handle_event(PeerEvent::Message)` (lines 2017-2161)
has no `SendCmpct` arm. The message is swallowed by the catch-all
fall-through and lost.

**File:**
- `crates/network/src/compact_blocks.rs:903-991` — `PeerCompactBlockState`
  struct + impl.
- `crates/network/src/compact_blocks.rs:1001-1146` — `CompactBlockRelay`
  struct + impl (only test callers).
- `rustoshi/src/main.rs:3814-3823` — incoming SendCmpct forwarder.
- `crates/network/src/peer_manager.rs:2017-2161` —
  `handle_event(PeerEvent::Message)` with no `SendCmpct` arm.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3909-3915` —
`nodestate->m_provides_cmpctblocks = true; nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;`.
This per-node-state is consulted in `MaybeSetPeerAsAnnouncingHeaderAndIDs`
and `NewPoWValidBlock` (cpp:1283, 2142) to decide which peers to push
cmpctblock to and to track the 3-peer HB cap.

**Impact:**
- We cannot make any send-side decision based on peer support (BUG-4,
  BUG-15 are blocked behind this).
- We cannot count outbound HB peers against the cap of 3 (BUG-2 +
  PARTIAL G38 row).
- All the dead fields (BUG-21) waste no runtime memory but mislead
  readers of `compact_blocks.rs` into thinking the peer-state machinery
  is live.

**Carry-forward:** W126 BUG-11; W112 BUG-G29 ("CompactBlockRelay dead
helper"). Open since at least mid-March 2026 (~2 months).

---

## BUG-3 (P1) — Neither `m_bip152_highbandwidth_from` nor `m_bip152_highbandwidth_to` is tracked on live peer state

**Severity:** P1. Core (`net.h::CNode`) carries two per-peer flags:
- `m_bip152_highbandwidth_from` — set when WE received `sendcmpct(1)` from
  the peer, signalling that THEY want us to push compact blocks
  immediately.
- `m_bip152_highbandwidth_to` — set when WE sent `sendcmpct(1)` to the
  peer, signalling that we want THEM to push to us.

These two are independent (peer-pair could be HB in zero, one, or both
directions). rustoshi tracks neither on the live `PeerInfo` in
`crates/network/src/peer.rs::PeerInfo`. The would-be `wants_high_bandwidth`
on `PeerCompactBlockState` (BUG-2) is dead.

**File:** `crates/network/src/peer.rs::PeerInfo` (grep `bip152\|highbandwidth\|wants_hb` = 0 matches in non-test code).

**Core ref:** `bitcoin-core/src/net.h::CNode` — both fields are members of
the long-lived per-peer object.

**Impact:** The "decide which 3 peers get sendcmpct(announce=true)"
algorithm needs both flags. BUG-4 (no `MaybeSetPeerAsAnnouncingHeaderAndIDs`)
is the proximate cause; this is the foundational gap.

---

## BUG-4 (P1) — No `MaybeSetPeerAsAnnouncingHeaderAndIDs`; rustoshi never promotes a peer to HB

**Severity:** P1. After validating a new tip, Core picks the up-to-3 peers
that delivered the most recent blocks and sends them
`sendcmpct(announce=true, version=2)`. Those peers now know to push the
next compact block directly (BIP-152 high-bandwidth mode). rustoshi never
does this.

**File:** `crates/network/src/peer.rs:1015-1026, 1241-1254, 1945-1957` —
the three `sendcmpct` send-sites all hardcode `announce: false`.
`grep "announce: true"` in non-test code = 0.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329` —
`MaybeSetPeerAsAnnouncingHeaderAndIDs`. The 3-peer cap is at line 1312
(`lNodesAnnouncingHeaderAndIDs.size() >= 3`). The function is called from
`BlockChecked` at line 2220 (every time a new valid block is observed).

**Impact:**
- rustoshi stays in low-bandwidth mode permanently with every peer.
- Every block-relay round-trip costs us at least one extra latency hop
  (peer sends inv → we send getdata → peer sends block) vs the HB fast
  path (peer sends cmpctblock immediately).
- On a peer's view, rustoshi looks like a permanently-stupid receiver —
  no different from a bitcoin-cli polling getblockheader.

**Carry-forward:** W126 BUG-17.

---

## BUG-5 (P2-CDIV) — `CmpctBlock::decode` doesn't enforce `BlockTxCount() ≤ u16::MAX`

**Severity:** P2-CDIV (wire-format divergence). Core's
`CBlockHeaderAndShortTxIDs::SERIALIZE_METHODS` at `blockencodings.h:121-130`
runs an explicit total-count check on decode:

```cpp
if (ser_action.ForRead()) {
    if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
        throw std::ios_base::failure("indexes overflowed 16 bits");
    }
    obj.FillShortTxIDSelector();
}
```

This is THE invariant that makes the `prefilledtxn.index` field a `uint16_t`
safe: a block can have at most 65_535 transactions in BIP-152's index space.

rustoshi's `CmpctBlock::decode` (`crates/network/src/compact_blocks.rs:285-356`)
only checks the joint cap
`short_ids_len + prefilled_len > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT (= 66_666)`
at line 314 and the per-prefilled-tx `index > u16::MAX` at line 325. A
syntactically-valid cmpctblock could carry e.g. 60_000 short_ids + 6_000
prefilled = 66_000 entries, which passes the rustoshi caps but exceeds
65_535. The resulting cmpctblock would have `block_tx_count() = 66_000`
which overflows the `u16` "absolute index" semantics of PrefilledTx.

**File:** `crates/network/src/compact_blocks.rs:285-356`.

**Core ref:** `bitcoin-core/src/blockencodings.h:121-130`.

**Impact:** Indices in `PartiallyDownloadedBlock::txn_available` (a `Vec`)
would alias because the prefilled differential decode at line 322-334 caps
each index at `u16::MAX = 65_535`. Two short_ids could land at the same
index. `is_block_mutated` should catch the corruption on FillBlock, but
the InitData path itself spends time + RAM walking the mempool against
this over-large cmpctblock. **DoS amplification.**

---

## BUG-6 (P2) — `as i32` cast on `read_compact_size` return wraps silently

**Severity:** P2 (DoS / under-rejection). `read_compact_size` returns
`u64`. The differential-decode at `compact_blocks.rs:323` does:

```rust
let diff = read_compact_size(reader)? as i32;
last_index = last_index.saturating_add(diff).saturating_add(1);
if last_index < 0 || last_index > u16::MAX as i32 {
    return Err(io::Error::new(io::ErrorKind::InvalidData, "prefilled index overflow"));
}
```

For `read_compact_size` returning, say, `2^32 + 1`, `as i32` yields `1`
(low 32 bits). `last_index.saturating_add(1).saturating_add(1)` = `1`. The
bounds check at line 325 passes. The decoded prefilled has index `1` even
though the wire bytes encoded `2^32 + 1`.

`BlockTxnRequest::decode` at line 422 has the same shape.

**File:**
- `crates/network/src/compact_blocks.rs:323-329`.
- `crates/network/src/compact_blocks.rs:422-428`.

**Core ref:** `bitcoin-core/src/blockencodings.h:23-43` —
`DifferenceFormatter::Unser`:

```cpp
template<typename Stream, typename I>
void Unser(Stream& s, I& v) {
    uint64_t n = ReadCompactSize(s);
    m_shift += n;
    if (m_shift < n ||
        m_shift >= std::numeric_limits<uint64_t>::max() ||
        m_shift < std::numeric_limits<I>::min() ||
        m_shift > std::numeric_limits<I>::max())
        throw std::ios_base::failure("differential value overflow");
    v = I(m_shift++);
}
```

Core reads `uint64_t`, accumulates into `uint64_t m_shift`, and validates
ALL boundaries (overflow AND target-type-range) BEFORE assigning. The
target-type validation lives in `I` template parameter (uint16_t in our
case), preserving full precision through the entire decode.

**Impact:**
- Decoded `CmpctBlock` and `BlockTxnRequest` accept wire bytes that
  Core rejects. Wire-format divergence.
- Combined with BUG-5: a hostile peer can ship a cmpctblock with `BlockTxCount
  > 65_535` AND wrapped differential indices, and rustoshi will happily
  spend several milliseconds reconstructing it before falling over in
  FillBlock.

---

## BUG-7 (P1) — `getblocktxn` out-of-range index → silent skip; no `Misbehaving`

**Severity:** P1 (DoS surface). Core's `SendBlockTransactions` at
`net_processing.cpp:2602-2604`:

```cpp
for (size_t i = 0; i < req.indexes.size(); i++) {
    if (req.indexes[i] >= block.vtx.size()) {
        Misbehaving(peer, "getblocktxn with out-of-bounds tx indices");
        return;
    }
    resp.txn[i] = block.vtx[req.indexes[i]];
}
```

Out-of-range index → 100-pt Misbehaving (instant ban) + early-return. The
peer cannot construct such a request without buggy intent (they know the
block's tx count from the cmpctblock they were responding to).

rustoshi's getblocktxn handler at `main.rs:3920-3930`:

```rust
if let Ok(Some(block)) = block_store.get_block(&req.block_hash) {
    let txns: Vec<Arc<rustoshi_primitives::Transaction>> = req.indices.iter()
        .filter_map(|&idx| block.transactions.get(idx as usize).map(|tx| Arc::new(tx.clone())))
        .collect();
    let resp = BlockTxn::from_arcs(req.block_hash, txns);
    ...
    pm.send_to_peer(peer_id, NetworkMessage::BlockTxn(resp.serialize())).await;
    ...
}
```

`.get(idx as usize)` returns `None` for out-of-range; `filter_map` silently
drops. We reply with a *short* (or empty) `blocktxn`. No misbehaving.

**File:** `rustoshi/src/main.rs:3916-3935`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2598-2615`.

**Impact:**
- DoS-amplification primitive: an attacker can spam getblocktxn requests
  with out-of-range indices forever; we keep replying with short
  blocktxns AND keep paying the `block_store.get_block` disk read cost
  (BUG-17).
- Cross-impl divergence: a peer that misbehaves against Core gets banned;
  the same peer gets to keep talking to rustoshi indefinitely.

**Carry-forward:** W126 BUG-6.

---

## BUG-8 (P2-CDIV) — `Transaction::encode` only emits SegWit marker+flag when at least one input has witness data

**Severity:** P2-CDIV (wire-format asymmetry). Core's `TX_WITH_WITNESS`
serializer always emits the BIP-141 0x00 0x01 marker+flag in a
witness-aware context (`primitives/transaction.h::SerializeTransaction`
when `fAllowWitness=true`), even if every input's witness vector is
empty. The empty witnesses then serialize as
`compact_size(0)` per input.

rustoshi's `Transaction::encode` (`crates/primitives/src/transaction.rs:327-360`):

```rust
fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
    let has_witness = self.has_witness();
    ...
    if has_witness {
        writer.write_all(&[0x00, 0x01])?;
        ...
    }
    ...
    if has_witness {
        for input in &self.inputs {
            len += input.encode_witness(writer)?;
        }
    }
    ...
}
```

`has_witness = self.inputs.iter().any(|i| !i.witness.is_empty())` (line 238).

Net effect: a transaction with every input witness empty is serialized in
legacy (non-segwit) format. For most live transactions this is
benign — pre-segwit txs in pre-segwit blocks are *supposed* to be legacy
format.

But in a cmpctblock context (which Core uses `TX_WITH_WITNESS`
unconditionally for) this is a wire-format divergence:
- A *pre-segwit*-prefilled tx in a v2 cmpctblock would be wrapped in
  marker+flag by Core but in legacy bytes by rustoshi. A peer rebuilding
  the block from rustoshi's bytes would parse the legacy bytes as
  non-witness (compact-size of inputs would be a normal varint, not 0x00).
  The result would round-trip OK if both ends use rustoshi's `has_witness`
  rule, but it diverges from Core's wire format.
- The asymmetry matters for prefilled coinbase in particular: if the
  coinbase has the witness commitment but the witness nonce is stripped
  (unusual but legal), `has_witness` returns false and we'd emit legacy.

**File:** `crates/primitives/src/transaction.rs:236-240, 327-360`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h` —
`UnserializeTransaction` / `SerializeTransaction` with `fAllowWitness=true`
always emit marker+flag.

**Impact:** Asymmetric wire round-trip in cmpctblock and blocktxn for any
witness-aware-but-empty-witness transaction. Cross-impl interop break with
Core for those edge cases.

---

## BUG-9 (P2) — Mempool iteration order is NOT randomized; Core uses `txns_randomized`

**Severity:** P2 (defensive depth lost). Core's
`PartiallyDownloadedBlock::InitData` walks the mempool in the order
defined by `pool->txns_randomized`
(`bitcoin-core/src/txmempool.cpp`) — a vector that is rebuilt with a
crypto-grade RNG shuffle on every insert/remove. The reason: the
first-match-fills / second-match-clears collision logic
(blockencodings.cpp:125-137) is order-sensitive; if an attacker knows the
iteration order they can construct two mempool txns whose wtxids collide
on the same short_id and ensure THEIR ordering controls which slot gets
populated.

rustoshi's `collect_for_compact_block` (`mempool.rs:3216-3221`):

```rust
pub fn collect_for_compact_block(&self) -> Vec<(Hash256, Arc<Transaction>)> {
    self.transactions.values().map(|entry| {
        let wtxid = entry.tx.wtxid();
        (wtxid, Arc::new(entry.tx.clone()))
    }).collect()
}
```

`self.transactions` is `HashMap<Hash256, MempoolEntry>`. The iteration
order is determined by Rust's `RandomState` keyed at HashMap
construction — process-stable for the lifetime of the map. A long-running
rustoshi node never reshuffles. An attacker who learns the order
(through e.g. timing side-channels on previous cmpctblock interactions)
can exploit it deterministically.

**File:**
- `crates/consensus/src/mempool.rs:3214-3221`.
- `rustoshi/src/main.rs:3833-3839` (consumer).

**Core ref:** `bitcoin-core/src/txmempool.cpp` —
`CTxMemPool::SetTxOrder` / `txns_randomized` (rebuilt per
insert/remove). `blockencodings.cpp:121` consumes it.

**Impact:** Low — exploitation requires the attacker to (a) learn the
specific HashMap iteration order, (b) construct two short-id-colliding
transactions, (c) get both into the local mempool, (d) win a race against
the next cmpctblock arrival. But defensive depth lost vs Core. **NEW
W156 finding (W126 did not catch this);** belongs to the "iteration-order
secrecy" class.

---

## BUG-10 (P3) — `vExtraTxnForCompact` ring buffer is not passed into `init_data`

**Severity:** P3 (efficiency / interop). Core (`net_processing.cpp:1887-1890`)
keeps a 100-entry ring buffer (`DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN`)
of recently-seen orphan or rejected txns. On every cmpctblock receipt the
ring is passed as the `extra_txn` arg to `InitData`. A short_id miss
against the mempool but hit against the orphan ring resolves without a
getblocktxn round-trip.

rustoshi's `main.rs:3841` passes `&[]`:

```rust
match PartiallyDownloadedBlock::init_data(
    &cmpct, mempool_refs.into_iter(), &[],
) {
```

**File:** `rustoshi/src/main.rs:3826-3845`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1887-1890, 4591`.

**Impact:** Minor — slightly worse compact-block reconstruction rate when
the network is full of orphans (a common state during fee-spike periods).
Marginal extra bandwidth.

**Carry-forward:** W126 BUG-16.

---

## BUG-11 (P1) — `getdata(MSG_CMPCT_BLOCK)` silently dropped; no `m_most_recent_block` cache

**Severity:** P1. Two halves:

**(a)** `main.rs:3343-3384` GetData handler only matches `MsgBlock |
MsgWitnessBlock | MsgTx | MsgWitnessTx`. `MsgCmpctBlock` falls through
`_ => {}` (line 3383) silently. Core (`net_processing.cpp:2466-2471`)
responds with the cached compact block or a freshly-built one if the
requested hash is the recent best.

**(b)** rustoshi has no `m_most_recent_block` / `m_most_recent_compact_block`
cache at all. `grep "most_recent_block\|recent_compact" rustoshi/src/main.rs`
returns 0 matches. Every getblocktxn (BUG-17) and every would-be
getdata(MSG_CMPCT_BLOCK) hits the disk via `block_store.get_block`.

**File:**
- `rustoshi/src/main.rs:3343-3386` (GetData fall-through).
- `rustoshi/src/main.rs:3916-3935` (getblocktxn disk read).

**Core ref:** `bitcoin-core/src/net_processing.cpp:2466-2471`,
`bitcoin-core/src/net_processing.cpp:2119-2131` (cache fill in
`NewPoWValidBlock`).

**Impact:**
- Cannot respond to cmpctblock-mode getdata requests.
- Hot-path disk reads for every getblocktxn — DoS amplification when an
  attacker spams getblocktxn for the tip.
- Combined with BUG-15 (no SEND-side): rustoshi is BIP-152-blind in both
  directions for the *push* leg.

**Carry-forward:** W126 BUG-2 + W126 BUG-15. **W156 extends** by
identifying the missing cache as the root cause for both.

---

## BUG-12 (P2) — `Inv(MSG_CMPCT_BLOCK)` from peer is silently ignored

**Severity:** P2 (under-rejection / missing-case-fall-through). When a
non-HB peer announces a new block via `inv MsgCmpctBlock` (the announce
form for compact-block-aware peers without an HB connection), Core fetches
headers from them. rustoshi's `Inv` handler at `main.rs:3061-3096` only
matches `MsgBlock | MsgWitnessBlock | MsgTx | MsgWitnessTx`; falls through
`_ => {}` (line 3083). Net effect: the announcement is dropped on the floor
and rustoshi learns of the new block only via the slower stale-detection
or periodic getheaders.

**File:** `rustoshi/src/main.rs:3061-3096`.

**Core ref:** Implicit in the BIP-152 spec — `cmpctblock` inv is a valid
announcement form for low-bandwidth peers (BIP-152 §"Block relay protocol
flow").

**Impact:** Marginal — most modern peers send `headers` directly via
BIP-130 instead. But the divergence is non-trivial when the network
operates in mixed HB/LB mode. **NEW W156 finding (W126 did not catch this).**

---

## BUG-13 (P0) — No anti-DoS chainwork pre-check on incoming `cmpctblock`

**Severity:** P0. Core's `cmpctblock` handler at
`net_processing.cpp:4486-4494` runs:

```cpp
const CBlockIndex* prev_block = ... LookupBlockIndex(cmpctblock.header.hashPrevBlock);
if (!prev_block) { ... return; }
else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()) {
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

The anti-DoS threshold is `max(MinimumChainWork, 0.5 * tip chainwork)`. Any
cmpctblock below this is dropped before `InitData` runs.

rustoshi at `main.rs:3826-3914` invokes `init_data` unconditionally on
every decoded cmpctblock. `init_data` then walks the entire mempool (BUG-9
shows this is a clone + iterate) and computes a short_id per tx. For a
mempool of 100k txns this is several milliseconds of CPU per attack
message.

**File:** `rustoshi/src/main.rs:3826-3914`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4486-4494`.

**Impact:** Low-work cmpctblock spam at line-rate forces a mempool walk
per message. At 100k mempool txns × 8 byte short_id × 1Gb/s wire =
~12k cmpctblocks/s attack rate → ~1500 mempool walks/s → CPU saturation.

**Carry-forward:** W126 BUG-4.

---

## BUG-14 (P2) — No `LoadingBlocks()` / IBD guard on incoming `cmpctblock`

**Severity:** P2. Core early-returns at `net_processing.cpp:4468-4472` if
`m_blockman.LoadingBlocks()` is true. rustoshi enters `init_data`
unconditionally during IBD, even though the mempool is empty / small and
reconstruction will always fall back to getblocktxn or full-block getdata.

**File:** `rustoshi/src/main.rs:3826`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4468-4472`.

**Impact:** Wasted CPU during IBD on every cmpctblock. Compounds with
BUG-13 (no anti-DoS gate).

**Carry-forward:** W126 BUG-8.

---

## BUG-15 (P0-DEAD) — `CmpctBlock::from_block` is `#[cfg(test)]`-only; rustoshi never SENDS compact blocks

**Severity:** P0-DEAD ("dead-helper-at-call-site" fleet pattern).
`CmpctBlock::from_block` (`compact_blocks.rs:109-137`) and
`CmpctBlock::from_block_with_prefilled` (`compact_blocks.rs:142-186`) are
both `pub` and fully implemented, but every non-test caller is **inside
the `#[cfg(test)] mod tests` of the same file**. A grep across
`rustoshi/src/` + `crates/*/src/` (excluding `tests/`) returns 0
non-test matches.

`announce_block` (`peer_manager.rs:1733-1760`) — the canonical broadcast
path on new-tip — uses `NetworkMessage::Headers` (for BIP-130-aware peers)
or `NetworkMessage::Inv(MsgBlock | MsgWitnessBlock)` (for everyone else).
Never `NetworkMessage::CmpctBlock`.

**File:**
- `crates/network/src/compact_blocks.rs:109-186` (constructors).
- `crates/network/src/peer_manager.rs:1733-1760` (the canonical SEND
  path that should call `CmpctBlock::from_block`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:2103-2152`
(`NewPoWValidBlock`) builds the cmpctblock per-tip and pushes to every HB
peer in `m_connman.ForEachNode` lambda.

**Impact:**
- Network-wide latency degradation. Modern Bitcoin nodes count on
  cmpctblock fast-relay; we never participate in it.
- Asymmetric receiver: we can receive (BUG-2 not withstanding) but never
  send. From the network's view we look like a pre-2016 implementation.

**Carry-forward:** W126 BUG-1; W112 BUG-G23. Open for ~2 months.

---

## BUG-16 (P2) — `MAX_CMPCTBLOCK_DEPTH = 5` constant not defined

**Severity:** P2 (latent — gated behind BUG-15). Even if BUG-15 were
fixed and the SEND-side wired, there's no depth cap on what we'd serve
via `getdata(MSG_CMPCT_BLOCK)`. Core (`net_processing.cpp:138`,
`2466-2471`) only serves compact blocks within 5 of tip; older blocks fall
back to full-block.

**File:** `grep MAX_CMPCTBLOCK_DEPTH` rustoshi/* crates/*/src = 0 matches.

**Core ref:** `bitcoin-core/src/net_processing.cpp:138`.

**Impact:** Latent. Active the moment BUG-11 + BUG-15 are wired.

**Carry-forward:** W126 BUG-7 (in test, not catalogued in audit/).

---

## BUG-17 (P1) — `getblocktxn` reads from disk; no `m_most_recent_block` cache

**Severity:** P1 (DoS amplification). `main.rs:3920-3930` calls
`block_store.get_block(&req.block_hash)` directly — every getblocktxn
hits Pebble. Core (`net_processing.cpp:4254-4264`) first checks
`m_most_recent_block` (the tip cache populated in `NewPoWValidBlock` at
cpp:2127-2128). Only if the requested hash is NOT the tip (or recently
prior) does Core fall back to disk.

**File:** `rustoshi/src/main.rs:3916-3935`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4254-4264`.

**Impact:** An attacker who connects + sends getblocktxn for the tip in
a tight loop forces one disk read per request. Disk IOPS exhaustion;
indirect denial-of-service on chain-tip queries that should be cached.
Combined with BUG-18 (no depth cap) the attack surface is even wider.

**Carry-forward:** W126 BUG-15.

---

## BUG-18 (P2) — `MAX_BLOCKTXN_DEPTH = 10` cap not enforced; rustoshi serves any depth

**Severity:** P2 (DoS amplification). Core's `getblocktxn` handler at
`net_processing.cpp:4276-4302` checks
`pindex->nHeight >= ActiveChain().Height() - MAX_BLOCKTXN_DEPTH` and falls
back to full-block getdata for older blocks (the comment at cpp:4294-4298
explains *"to make attacker pay for disk read"*). rustoshi serves any
depth unconditionally.

**File:** `rustoshi/src/main.rs:3916-3935`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:138, 4276-4302`.

**Impact:** Combined with BUG-17, an attacker requests
`getblocktxn(blockhash_1000_back)` repeatedly and forces deep-disk reads.
Pebble seek + read amplification. Cross-impl divergence: Core would force
the peer to receive a full block over the wire (paying the attacker's
bandwidth budget); rustoshi pays the disk cost for free.

**Carry-forward:** W126 BUG-7.

---

## BUG-19 (P0) — `inflight_partial_blocks` HashMap has no per-peer cap, no global cap, no TTL

**Severity:** P0 (RAM-exhaustion DoS). `main.rs:2282-2285, 3880-3881`:

```rust
let mut inflight_partial_blocks: std::collections::HashMap<
    (u64, rustoshi_primitives::Hash256),
    rustoshi_network::PartiallyDownloadedBlock,
> = std::collections::HashMap::new();
...
// Key: (peer_id, block_hash) — one in-flight block per peer (Core net_processing.cpp:5028).
inflight_partial_blocks
    .insert((peer_id.0, block_hash), partial);
```

The comment claims "one in-flight block per peer" but the map key is
`(peer_id, block_hash)` — N entries per peer (one per distinct block).
Comment-as-confession (5th rustoshi instance tracked across waves).

A `PartiallyDownloadedBlock` (defined at compact_blocks.rs:602-617) holds:
- `header: BlockHeader` (80 bytes),
- `txn_available: Vec<Option<Arc<Transaction>>>` (up to MAX_BLOCK_WEIGHT/60
  = 66_666 entries; each is 8 bytes for the `Option<Arc<_>>` header alone,
  with the underlying `Transaction` cloned and heap-allocated when filled),
- `short_id_map: HashMap<u64, usize>` (up to 66_666 entries × ~32 bytes
  each = ~2 MiB of map overhead alone, plus the underlying allocations).

A single attack-message can stuff up to ~3 MiB into this map. A peer
delivering 1000 distinct cmpctblock-hashes inflates the map to ~3 GiB —
all on one peer.

The map is freed only on peer disconnect (line 4076). If the peer keeps
the connection open and never replies to getblocktxn, the partials sit
forever.

**File:** `rustoshi/src/main.rs:2270-2285, 3870-3886, 4070-4076`.

**Core ref:** `bitcoin-core/src/net_processing.h:47`
(`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` — per-block, not per-peer);
the per-peer cap is implicit in Core's `BlockRequested` /
`mapBlocksInFlight` machinery which limits `MAX_BLOCKS_IN_TRANSIT_PER_PEER
= 16` total in-flight requests per peer.

**Impact:**
- DoS-amplification: one attacker, ~3 GiB RAM consumed per ~1000 messages.
  At line-rate (~12k cmpctblock/s — see BUG-13) the OOM-killer fires in
  seconds.
- Compounds BUG-13: low-work cmpctblock spam → mempool walk per message
  → partial-block insertion per message → OOM.

**Status:** Carry-forward placeholder; W126 caught the *constant absence*
(BUG-9 in W126 = MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK undefined) but did
**not** catch the per-peer cap absence or the no-TTL gap. **NEW W156
extension.**

---

## BUG-20 (P1) — No TTL on `inflight_partial_blocks`; peer-silence holds entries forever

**Severity:** P1 (RAM-exhaustion). Cross-cite to BUG-19. There is no
periodic sweep of stale partial blocks. The only cleanup hooks are:
- `main.rs:3957` — `inflight_partial_blocks.remove(&key)` when a matching
  blocktxn arrives.
- `main.rs:4076` — `inflight_partial_blocks.retain(|(pid, _), _| *pid != peer_id.0)`
  on peer disconnect.

Neither path runs if (a) the peer never replies to getblocktxn and
(b) the peer never disconnects. A well-behaved peer that goes silent
(network partition, slow link, deliberate stall) holds the entry
indefinitely.

**File:** `rustoshi/src/main.rs:3870-3886, 3955-4042, 4070-4076`.

**Core ref:** Core's `mapBlocksInFlight` has timeout handling via
`m_downloading_since` checked in `SendMessages` (block-stalling timeout
default 2s, max 64s) — the partialBlock is cleared with the request.

**Impact:** Slow leak; takes a deliberately-stalling peer to exploit.
Distinct from BUG-19 (BUG-19 is fast OOM; BUG-20 is slow leak).

**NEW W156 finding (W126 did not catch this).**

---

## BUG-21 (P3) — `PeerCompactBlockState` counters (`cmpctblock_count`,
`successful_reconstructions`, `failed_reconstructions`, `last_cmpctblock`)
are written but never read

**Severity:** P3 (dead-data plumbing inventory). On the dead
`PeerCompactBlockState` struct (compact_blocks.rs:918-925), four metrics:

```rust
pub last_cmpctblock: Option<Instant>,
pub cmpctblock_count: u64,
pub successful_reconstructions: u64,
pub failed_reconstructions: u64,
```

are populated by `record_success` / `record_failure` (lines 973-979) and
in `success_rate` (line 983). Their readers are themselves dead (BUG-2 —
`CompactBlockRelay` is never instantiated). Even if the struct were wired,
no RPC, log, or metric surface consumes these fields.

**File:** `crates/network/src/compact_blocks.rs:903-991`.

**Impact:** Wastes nothing at runtime (the struct never lives). Pinned
for the fleet-wide dead-state inventory.

**Carry-forward:** W126 BUG-12.

---

## Fleet cross-refs / patterns

### Dead-data plumbing (fleet pattern)

The pattern of "struct defined with full method surface, zero production
callers" recurs across the fleet — W122 (rustoshi GCS codec stress test
helpers), W138 (assumeUTXO ChainstateManager fleet-wide 9 of 10), W140
(`constantTimeEq` exported-but-not-called in haskoin), W141
(`set_zmq_publisher` attribute-mismatch in ouroboros), W144 (Taproot
dead-data BIP9 plumbing in ouroboros), W145 (`nSubsidyHalvingInterval`
DEAD FIELD set by all 5 networks read by zero in blockbrew W145 BUG-14).

W156 adds three rustoshi instances: `CompactBlockRelay` (BUG-2),
`PeerCompactBlockState` fields (BUG-21), `CmpctBlock::from_block`
(BUG-15). The unifying pattern: code that **looks** wired but isn't.

### Comment-as-confession (5th rustoshi instance)

The comment at `main.rs:3878-3879`:

```
// Key: (peer_id, block_hash) — one in-flight block per peer
// (Core net_processing.cpp:5028).
```

literally documents what Core does, immediately above an impl that does
NOT match it (map keys are `(peer_id, block_hash)`, which is N entries per
peer, not one). Prior rustoshi comment-as-confession instances tracked:
W141 BUG-4 (4th instance), W144 BUG-12 lunarblock (5th fleet instance),
this is the 5th rustoshi-specific.

### Two-pipeline guard (16th distinct fleet extension)

`PartiallyDownloadedBlock` storage exists in TWO places:
- Live: `main.rs:2282 inflight_partial_blocks: HashMap<(u64, Hash256), PartiallyDownloadedBlock>`.
- Dead: `compact_blocks.rs:917 partial_blocks: HashMap<Hash256, PartiallyDownloadedBlock>`
  inside `PeerCompactBlockState`, owned by the dead `CompactBlockRelay`.

Each has its own access patterns (the dead side has `store_partial_block`
/ `get_partial_block` / `remove_partial_block` at 1075-1102; the live side
has direct HashMap mutation). The two-pipeline-guard pattern: same
primitive in two places, only one of them actually used, the unused one
has the eviction hooks the live one lacks. **16th distinct fleet
extension across waves.**

### Three-pipeline drift (3rd rustoshi instance in W142+ tracking)

cmpctblock processing has THREE entry points for the same logical
operation "track an in-flight compact block":
1. The live `inflight_partial_blocks` HashMap (`main.rs:2282`).
2. The dead `CompactBlockRelay.peer_states[..].partial_blocks` (`compact_blocks.rs:917`).
3. The implicit storage in `block_downloader` (`main.rs:3853, 3984` —
   the full-block fast path also tracks blocks in flight).

Three coexisting pipelines that share zero state. Extension of W142
"three-pipeline drift" (rustoshi 3-merkle-copy), W143
(ouroboros 3-consensus-pipeline), W145 (clearbit 3-copy CheckTxInputs).

---

## Severity rollup

| Severity | Count | BUGs |
|----------|-------|------|
| P0-DEAD | 2 | BUG-2, BUG-15 |
| P0 | 2 | BUG-13, BUG-19 |
| P1 | 7 | BUG-3, BUG-4, BUG-7, BUG-11, BUG-17, BUG-20, (+BUG-15 cross-counted) |
| P2-CDIV | 2 | BUG-5, BUG-8 |
| P2 | 6 | BUG-1, BUG-6, BUG-9, BUG-12, BUG-14, BUG-16, BUG-18 |
| P3 | 2 | BUG-10, BUG-21 |
| **Total** | **21** | |

Note: severity counters above count each BUG once at its highest tier.
P0 + P0-DEAD = 4 distinct findings; P0/P1 combined = 11.

---

## Recommended fix-wave priorities

1. **Fix BUG-19 first.** Cap `inflight_partial_blocks` at ≤1 entry per
   peer; on second insert evict the previous entry (matches Core's
   `BlockRequested` semantics). ~10 LOC. Closes the loudest DoS surface.
2. **Fix BUG-20 alongside BUG-19.** Add a TTL sweep (every 30s, drop
   entries older than 5 minutes). ~15 LOC.
3. **Fix BUG-15 + BUG-2 + BUG-11 as a triplet.** Wire `CompactBlockRelay`
   into `peer_state`, add the `m_provides_cmpctblocks` / `wants_hb` flags
   to `PeerInfo`, build the `m_most_recent_block` cache, and wire
   `CmpctBlock::from_block` into `announce_block`. This is the biggest
   structural fix but removes the SEND-side dead-class entirely.
4. **Fix BUG-7 + BUG-13 + BUG-14 together.** Single function:
   `should_accept_cmpctblock(prev_block, header)` returning bool;
   gates BUG-13 (chainwork), BUG-14 (LoadingBlocks). BUG-7 is a 3-line
   change to fire Misbehaving when index OOR.
5. **Fix BUG-5 + BUG-6 together.** Both are wire-codec under-rejections in
   the same function; the fix is `u64`-typed accumulator + explicit
   `BlockTxCount() <= u16::MAX` post-check.
6. **Fix BUG-17 + BUG-18 together** — they share a fix-site (the
   getblocktxn handler). Add the depth gate AND the recent-block cache
   lookup. ~20 LOC.

The remaining BUGs (BUG-1, BUG-3, BUG-4, BUG-8, BUG-9, BUG-10, BUG-12,
BUG-16, BUG-21) are independent and can be batched in a follow-up wave.

---

## Audit verdict

**21 BUGs catalogued / 12 behaviours / 45 sub-gates.**
- **4 P0-class** findings (BUG-2 P0-DEAD, BUG-13 P0 anti-DoS, BUG-15
  P0-DEAD SEND-side, BUG-19 P0 RAM-DoS).
- **7 P1** findings (BUG-3, BUG-4, BUG-7, BUG-11, BUG-17, BUG-20, plus
  BUG-15 cross-counted).
- **9 carry-forwards** from W126 (BUG-1, BUG-2, BUG-4, BUG-7, BUG-10,
  BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18, BUG-21).
- **6 NEW W156 findings** that W126 did not catch (BUG-5 u16 total-count,
  BUG-6 i32 cast wrap, BUG-8 witness asymmetry, BUG-9 mempool order,
  BUG-12 inv MsgCmpctBlock, BUG-19 + BUG-20 inflight-map DoS).

The dominant fleet pattern is the SEND-side dead-class: rustoshi
*receives* compact blocks competently (with caveats) but is structurally
incapable of *sending* them. The receive path has good codec correctness
but lacks anti-DoS gating, the inflight-map is unbounded, and the
`CompactBlockRelay` peer-state machinery is unused production code.

The dominant fix priority is **BUG-19 (RAM DoS)** — exploitable today by
any peer who completes a handshake. Everything else is a degradation of
the protocol; BUG-19 is a degradation of the host.
