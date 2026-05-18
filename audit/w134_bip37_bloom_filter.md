# W134 — BIP-37 Bloom Filter (legacy SPV) audit (rustoshi)

Discovery wave, not a fix wave. Each gate is documented inline and either:
  - **PASS** (regression-pin) for surfaces that are PRESENT and Core-aligned;
  - **`#[ignore]` xfail** for known PARTIAL or MISSING gates, with a `BUG-N`
    reference.

## Scope
- `crates/network/src/message.rs` — `NetworkMessage::FilterLoad/FilterAdd/
  FilterClear/MerkleBlock` variants + `NODE_BLOOM` constant + `InvType::
  MsgFilteredBlock` / `MsgWitnessFilteredBlock`.
- `crates/network/src/peer_manager.rs` — `PeerManagerConfig.peer_bloom_filters`,
  `local_services()` NODE_BLOOM gate, `peer_bloom_filters_enabled()`, eviction
  dead-stub.
- `crates/network/src/peer.rs` — wire deserialization of bloom messages.
- `crates/network/src/eviction.rs` — `EvictionCandidate.bloom_filter` field
  (doubly-dead helper).
- `rustoshi/src/main.rs` — `_ =>` catch-all that forwards unhandled messages
  to `peer_manager.handle_event` (BUG-30); `NetworkMessage::MemPool` gate that
  DOES consult `peer_bloom_filters_enabled()` (PASS for BIP-35); `GetData`
  inv loop dispatch that DROPS `MsgFilteredBlock`.

## Core reference
- `bitcoin-core/src/common/bloom.{h,cpp}` — `CBloomFilter`,
  `MAX_BLOOM_FILTER_SIZE=36000`, `MAX_HASH_FUNCS=50`, `LN2SQUARED`,
  `BLOOM_UPDATE_*`, `Hash()`, `insert`/`contains`/`IsWithinSizeConstraints`/
  `IsRelevantAndUpdate`.
- `bitcoin-core/src/merkleblock.{h,cpp}` — `CMerkleBlock`, `CPartialMerkleTree`.
- `bitcoin-core/src/net_processing.cpp` — `NetMsgType::FILTERLOAD/FILTERADD/
  FILTERCLEAR` handlers (lines 4963-5033), `MSG_FILTERED_BLOCK` getdata
  service (line 2438-2460), `NODE_BLOOM` gate (line 4853-4855).
- `bitcoin-core/src/net_processing.h:44` — `DEFAULT_PEERBLOOMFILTERS = false`.
- `bitcoin-core/src/init.cpp:1104-1105` — `g_local_services |= NODE_BLOOM`
  when `-peerbloomfilters=true`.
- `bitcoin-core/src/protocol.h:317` — `NODE_BLOOM = (1 << 2)`.

BIPs: 37 (Connection Bloom filtering), 111 (NODE_BLOOM service bit and
the `-peerbloomfilters` gate added because the default became OFF in
Core 0.19+).

## Cross-wave context

W110 (`rustoshi/tests/test_w110_bloom_filter.rs`, 32 BUG findings) already
documented the absence of CBloomFilter, MurmurHash3, the constants, the
handlers, and CMerkleBlock. W134 re-audits the same subsystem with the
explicit framing that **Core removed serving in 0.21+ at the default
level** (DEFAULT_PEERBLOOMFILTERS=false since 0.19+; the bit is still
defined in protocol.h:317 because operators can flip the gate via
`-peerbloomfilters=true`, and SPV clients still rely on it for back-compat).

The W134 verdict is therefore "intentionally not served + NODE_BLOOM
correctly NOT advertised by default" — that is the design-correct stance.
The audit concentrates on:

  1. (P0-CDIV) Does `-peerbloomfilters=true` advertise NODE_BLOOM while
     leaving the handlers unwired? **YES — this is the headline P0
     bug-compatibility finding (G2 below).**
  2. (P1) Does `getdata MSG_FILTERED_BLOCK` from a peer get silently
     dropped? **YES — falls through `_ => {}` in main.rs:3383.**
  3. (P1) Is `IsWithinSizeConstraints` enforced before any future
     partial wiring lands? **NO — would be a DoS vector at first wiring.**
  4. (P2) Is the eviction-protection field wired? **NO — doubly dead
     (set false in peer_manager.rs:2500 AND never read in select_node_to_evict).**
  5. (P3) Is `IsRelevantAndUpdate` / CMerkleBlock-from-filter built?
     **NO — entire subsystem missing.**

The W134 gate count is 30 (per audit framework convention).

## Audit verdict counters
PRESENT 6 / PARTIAL 2 / MISSING 22 / **24 distinct BUG findings (30 gates)**.

## Bug index (severity legend: P0-CDIV / P0 / P1 / P2 / P3)

  BUG-1  (P0-CDIV) G2 — `-peerbloomfilters=true` advertises NODE_BLOOM but
                       no FILTERLOAD/FILTERADD/FILTERCLEAR handlers are wired.
                       A bloom-using SPV peer will set our flag, send
                       filterload, expect filtered tx-relay + merkleblock,
                       and receive nothing. We are advertising a capability
                       we do not fulfill (W117 BIP-155 NODE_NETWORK_LIMITED
                       parallel — protocol bug-compat / liveness break).
                       Bonus: filterload, filteradd, filterclear all fall
                       through `_ => { pm.handle_event(...) }` in
                       `rustoshi/src/main.rs:4061-4066` and the peer_manager
                       PeerEvent::Message arm has no match for them
                       (peer_manager.rs:2017-2160) — silent drop.
  BUG-2  (P1)      G3 — `getdata MSG_FILTERED_BLOCK` from a peer is silently
                       dropped. main.rs:3343-3384 only handles MsgBlock /
                       MsgWitnessBlock / MsgTx / MsgWitnessTx; MsgFilteredBlock
                       (=3) hits the `_ => {}` arm. Core sends MerkleBlock +
                       matched-tx TX messages (net_processing.cpp:2438-2460).
  BUG-3  (P1)      G4 — `IsWithinSizeConstraints` (vData.size()<=36000 AND
                       nHashFuncs<=50) is absent. If any partial bloom
                       implementation lands without this guard, a remote
                       peer sending filterload with vData=64KB,
                       nHashFuncs=255 would be accepted unconditionally.
                       Currently moot but P1 because it MUST land before
                       any handler is wired (CVE-class).
  BUG-4  (P2)      G5 — `MAX_BLOOM_FILTER_SIZE = 36000` constant absent.
  BUG-5  (P2)      G6 — `MAX_HASH_FUNCS = 50` constant absent.
  BUG-6  (P3)      G7 — `LN2SQUARED` constant absent (used in sizing formula).
  BUG-7  (P3)      G8 — CBloomFilter constructor / sizing formula absent
                       (vData.size() = min(-1/LN2SQUARED * nElements *
                       log(nFPRate), MAX_BLOOM_FILTER_SIZE*8) / 8).
  BUG-8  (P3)      G9 — nHashFuncs computation absent
                       (min(vData.size()*8/nElements*LN2, MAX_HASH_FUNCS)).
  BUG-9  (P3)      G10 — MurmurHash3 32-bit for bloom-purposes absent.
                       NB: siphasher 1.0 IS in network/Cargo.toml (for
                       compact-block short-id hashing), but it is NOT
                       MurmurHash3 — these are different hash functions.
                       BIP-37 mandates MurmurHash3 specifically.
  BUG-10 (P3)      G11 — Per-bit hash seed schedule
                       (nHashNum * 0xFBA4C795 + nTweak) absent.
  BUG-11 (P3)      G12 — bit_index = MurmurHash3(seed, data) %
                       (vData.size() * 8) absent.
  BUG-12 (P3)      G13 — insert sets bit, contains AND-of-bits absent
                       (vData[nIndex>>3] |= 1<<(7&nIndex);
                       contains short-circuits on first unset bit).
  BUG-13 (P3)      G14 — CVE-2013-5700 empty-vData ⇒ "match-all" short-circuit
                       absent (Core contains/IsRelevantAndUpdate return true
                       if vData.empty(); insert returns to avoid div-by-zero).
  BUG-14 (P3)      G15-G18 — BLOOM_UPDATE_NONE=0 / _ALL=1 / _P2PUBKEY_ONLY=2 /
                       _MASK=3 constants absent. (Tracked as one BUG to keep
                       the count tight; W110 split into BUG-11/12/13/14.)
  BUG-15 (P3)      G19 — `nFlags & BLOOM_UPDATE_MASK` dispatch (NOT raw
                       `nFlags ==`) absent. Reserved upper-6-bits of nFlags
                       must be masked before comparing to ALL or
                       P2PUBKEY_ONLY (Core bloom.cpp:123-132).
  BUG-16 (P3)      G20 — `IsRelevantAndUpdate` txid-match absent
                       (`if (contains(hash.ToUint256())) fFound = true`).
  BUG-17 (P3)      G21 — `IsRelevantAndUpdate` output-script pushdata-match
                       absent (iterate scriptPubKey opcodes, match any
                       data push of size > 0 via contains(data)).
  BUG-18 (P3)      G22 — `IsRelevantAndUpdate` input-outpoint-match absent
                       (`if (contains(txin.prevout)) return true`).
  BUG-19 (P3)      G23 — `IsRelevantAndUpdate` scriptSig pushdata-match absent.
  BUG-20 (P3)      G24 — BLOOM_UPDATE_ALL outpoint auto-insertion absent
                       (after a tx matches, every matched output's outpoint
                       must be inserted so the spending tx is also caught
                       without a client round-trip).
  BUG-21 (P3)      G25 — BLOOM_UPDATE_P2PUBKEY_ONLY outpoint insertion absent
                       (only P2PK and multisig outputs auto-insert; Core uses
                       `Solver(script)` to gate this).
  BUG-22 (P3)      G26 — Outpoint serialization for bloom insert/contains
                       (32-byte LE txid + 4-byte LE index = 36 bytes) absent
                       (Core uses `DataStream stream{}; stream << outpoint;`).
  BUG-23 (P3)      G27 — `CMerkleBlock(block, filter)` constructor absent.
                       Even if filterload were wired, getdata
                       MSG_FILTERED_BLOCK has no way to walk the block,
                       compute IsRelevantAndUpdate per tx, and build a
                       CPartialMerkleTree from the matched set. The RPC-side
                       `build_partial_merkle_tree_bytes` helper in
                       `crates/rpc/src/server.rs:8738` takes a pre-selected
                       match list — it is NOT a complete CMerkleBlock-from-filter
                       constructor. Two-pipeline risk (if a wire-side helper
                       is added it MUST reuse the RPC-side PMT traversal,
                       not re-implement it).
  BUG-24 (P2)      G28 — `EvictionCandidate.bloom_filter` is doubly dead:
                       (a) peer_manager.rs:2500 hard-codes the value to
                       `false` ("bloom_filter - we don't track this currently"),
                       AND (b) `select_node_to_evict` in eviction.rs:80-180
                       never reads the field even when it would be true.
                       Core protects bloom-filter peers from random eviction
                       (eviction.cpp `ProtectEvictionCandidatesByRatio`
                       `m_bloom_filter` check). Pattern: well-engineered
                       helper field never wired AND never consulted —
                       dead-helper-at-both-ends.

## Pass-gates (regression-pin)

  G1   PASS  — `NODE_BLOOM = 1 << 2 = 4` (message.rs:165 matches
              `bitcoin-core/src/protocol.h:317`).
  G29  PASS  — `peer_bloom_filters` default = `false` in
              `PeerManagerConfig::default()` (peer_manager.rs:250) matches
              Core's `DEFAULT_PEERBLOOMFILTERS = false`
              (net_processing.h:44). This is the design-correct stance for
              a non-SPV-serving full node.
  G30  PASS  — BIP-35 `mempool` request honours the NODE_BLOOM gate:
              main.rs:3735-3789 reads `pm.peer_bloom_filters_enabled()`
              and disconnects the peer if NODE_BLOOM is not advertised.
              This matches Core's net_processing.cpp:4853-4855 gate
              (the only BIP-37-dependent feature that IS correctly gated).

PARTIAL pass-gates:

  G9   PARTIAL — wire-level deserialization of `filterload`, `filteradd`,
              `filterclear`, `merkleblock` IS present in `message.rs:1076-1079`
              and command-string round-trip is structurally correct. But
              `FilterLoad`/`FilterAdd` carry raw `Vec<u8>` payloads, NOT
              typed structures — no `nHashFuncs`/`nTweak`/`nFlags` parsing,
              no per-field validation. This blocks G3/G19/G29 etc.
  G2   PARTIAL — `InvType::MsgFilteredBlock = 3` and
              `MsgWitnessFilteredBlock = 0x40000003` are correctly defined
              (message.rs:83+93). The constants are pinned by
              `g1_inv_type_msgfilteredblock_constant_present` below. But
              getdata never serves them — BUG-2.

## New patterns observed (potential META-PATTERNs)

(none beyond the patterns already documented in W110 / W121 / W128;
see "dead-helper-at-call-site" in W110 BUG-31 and "advertise-without-fulfil"
in W117 BIP-155 audit. W134 reconfirms both.)

## Severity rollup for fleet operator

  P0-CDIV: 1   (BUG-1 — NODE_BLOOM advertise-without-fulfil with
                `-peerbloomfilters=true`. Default config does not trip this
                because `peer_bloom_filters` defaults to false.)
  P0:      0
  P1:      2   (BUG-2 getdata-drop on MsgFilteredBlock,
                BUG-3 IsWithinSizeConstraints DoS guard absent)
  P2:      3   (BUG-4 MAX_BLOOM_FILTER_SIZE, BUG-5 MAX_HASH_FUNCS,
                BUG-24 eviction dead-helper)
  P3:      18  (rest of CBloomFilter / IsRelevantAndUpdate / CMerkleBlock)

  **Total: 24 BUGs / 30 gates.**

## Recommended action

Two options for closing the P0-CDIV:

  Option A — **strip the advertise gate** (recommended for full-node-only
  deployments): remove the `peer_bloom_filters` config flag and the
  `s |= NODE_BLOOM` branch in `local_services()`. Drop the CLI flag
  `-peerbloomfilters`. Closes BUG-1 trivially. The BIP-35 `mempool` gate
  in main.rs:3757 then always disconnects (matches a node that does not
  serve mempool — consistent with not serving SPV either).

  Option B — **plumb a `BIP37_P2P_HANDLERS_REGISTERED` gate**: mirror the
  pattern from `BIP157_P2P_HANDLERS_REGISTERED` (peer_manager.rs:76).
  Add `pub const BIP37_P2P_HANDLERS_REGISTERED: bool = false;` and gate
  `s |= NODE_BLOOM` on `peer_bloom_filters && BIP37_P2P_HANDLERS_REGISTERED`.
  This keeps the CLI surface and unblocks a future fix wave to wire the
  handlers. Closes BUG-1 by making the bit unreachable until the handlers
  land. Matches the FIX-71 → FIX-82 plumb-gate-then-flip pattern.

Neither option lands in this discovery wave (no production code changes).
The remaining 23 BUGs are addressed by either Option A (close them as
WONTFIX — deprecated subsystem) or Option B (close them as FUTURE-WORK
behind the gate).
