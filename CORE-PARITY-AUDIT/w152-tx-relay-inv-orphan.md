# W152 — Tx relay + inv batching + orphan handling (rustoshi)

**Wave:** W152 — `RelayTransaction` / `InitiateTxBroadcastToAll`,
`AddTxAnnouncement`, ProcessMessage (msg_tx + msg_inv), `SendMessages`
(inv-batching loop), `m_recently_announced_invs`,
`m_tx_inventory_to_send`, `m_next_inv_send_time`,
`TxRequestTracker`, `TxOrphanage` (`AddTx`, `EraseTx`,
`EraseForBlock`, `EraseForPeer`, `LimitOrphans`),
`OrphanByParent`, BIP-339 MSG_WTX dispatch, BIP-133 feefilter
broadcast, BIP-37 `fRelay` gate, `m_relay_to_set`,
`m_recent_rejects`, `m_recently_confirmed_transactions`,
`MAX_PEER_TX_ANNOUNCEMENTS=5000`,
`MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `GETDATA_TX_INTERVAL=60s`
(BIP-339), `TXID_RELAY_DELAY=2s`, `NONPREF_PEER_TX_DELAY=2s`,
`OVERLOADED_PEER_TX_DELAY=2s`, `INVENTORY_BROADCAST_PER_SECOND=14`,
`DEFAULT_MAX_ORPHAN_TRANSACTIONS=100`, MEMPOOL message + NODE_BLOOM,
`NotFound` emission.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:165-174` — broadcast constants:
  `INBOUND_INVENTORY_BROADCAST_INTERVAL{5s}`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL{2s}`,
  `INVENTORY_BROADCAST_PER_SECOND{14}`,
  `INVENTORY_BROADCAST_TARGET = 14 * 5 = 70`.
- `bitcoin-core/src/protocol.h:126` — `MAX_INV_SZ = 50000`.
- `bitcoin-core/src/net_processing.cpp:128` — `MAX_GETDATA_SZ = 1000`.
- `bitcoin-core/src/net_processing.cpp:4040,4131` —
  `if (vInv.size() > MAX_INV_SZ) Misbehaving(20)` for inv + getdata.
- `bitcoin-core/src/net_processing.cpp::RelayTransaction` —
  walks `m_peer_map`, gated on `m_tx_relay` (BIP-37), schedules into
  per-peer `m_tx_inventory_to_send`.
- `bitcoin-core/src/net_processing.cpp::ProcessGetData` — serves both
  txid-keyed MSG_TX and wtxid-keyed MSG_WTX from mempool + relay set
  + recently-confirmed; emits NOTFOUND for unservable items so the
  requester's `TxRequestTracker` can retry the next-best peer.
- `bitcoin-core/src/net_processing.cpp:5984-5986` — `SendMessages`
  Poisson rebroadcast cadence: `NextInvToInbounds(5s, network_key)` for
  inbound (privacy quantisation), `rand_exp_duration(2s)` for outbound.
- `bitcoin-core/src/net_processing.cpp:3921-3938` —
  WTXIDRELAY message: must be sent in response to VERSION before VERACK,
  only for `version >= 70016`; sets `peer.m_wtxid_relay = true`.
- `bitcoin-core/src/node/txdownloadman.h:24-38` — TxRequestTracker
  constants:
  `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100`,
  `MAX_PEER_TX_ANNOUNCEMENTS    = 5000`,
  `TXID_RELAY_DELAY             = 2s`,
  `NONPREF_PEER_TX_DELAY        = 2s`,
  `OVERLOADED_PEER_TX_DELAY     = 2s`,
  `GETDATA_TX_INTERVAL          = 60s`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:204-217` —
  `AddTxAnnouncement`: rejects when peer already has
  `>= MAX_PEER_TX_ANNOUNCEMENTS` outstanding; adds delay based on
  preference and wtxid/txid mix and overload state.
- `bitcoin-core/src/node/txorphanage.cpp` /
  `bitcoin-core/src/node/txdownloadman_impl.h` —
  `DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100`,
  `OrphanByParent` (txid → wtxid index for cheap block-arrive erase),
  `LimitOrphans` (count + weight-based; historical
  `ORPHAN_TX_EXPIRE_TIME = 20*60`), `EraseForBlock`, `EraseForPeer`.
- `bitcoin-core/src/net_processing.cpp::ProcessOrphanTx` —
  `std::set<uint256> orphan_work_set` drives a BFS through the
  orphanage on every successful ATMP, retrying every child whose
  parent just arrived. Recursive.
- `bitcoin-core/src/net_processing.cpp:4852` — MEMPOOL message handler:
  `NODE_BLOOM` gate + `OutboundTargetReached(false)` bandwidth gate +
  `m_send_mempool=true` scheduling.
- `bitcoin-core/src/net_processing.cpp:UNREQUESTED_TX_MISBEHAVIOR` —
  20-pt misbehavior penalty for txs received without prior INV.
- `bitcoin-core/src/policy/fees.cpp` + `bitcoin-core/src/net_processing.cpp`
  `AVG_FEEFILTER_BROADCAST_INTERVAL = 10min`,
  `MAX_FEEFILTER_CHANGE_DELAY = 5min`, `FeeFilterRounder` privacy buckets.

**Files audited**
- `crates/consensus/src/orphanage.rs` — `TxOrphanage`, `OrphanEntry`,
  `OrphanError`, `MAX_ORPHAN_TX_SIZE=100_000`,
  `MAX_ORPHAN_TRANSACTIONS=100`, `MAX_ORPHANS_PER_PEER=100`,
  `ORPHAN_TX_EXPIRE_TIME=20min`, `add`, `erase`, `erase_for_peer`,
  `erase_for_block`, `find_children`, `evict_oldest`,
  `expire_orphans`, secondary `txid_to_wtxids` index.
- `crates/network/src/relay.rs` — `InventoryTrickle`, `PeerRelayState`,
  `FeeFilterManager`, `FeeFilterState`, `FeeFilterRounder`,
  `build_tx_inv_entry`, `batch_getdata_items`, `poisson_next_send`,
  `pays_for_rbf`, `INBOUND_INVENTORY_BROADCAST_INTERVAL=5s`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`,
  `INVENTORY_BROADCAST_MAX=1000`,
  `INVENTORY_BROADCAST_PER_SECOND=14`,
  `INVENTORY_BROADCAST_TARGET=70`, `MAX_FEEFILTER_CHANGE_DELAY=5min`,
  `AVG_FEEFILTER_BROADCAST_INTERVAL=10min`, `DEFAULT_MIN_RELAY_FEE=1000`,
  `DEFAULT_INCREMENTAL_RELAY_FEE=1000`, `MAX_MONEY=21M*1e8`.
- `crates/network/src/message.rs:22, 33, 75-110, 205` —
  `MAX_INV_SIZE=50_000`, `MAX_GETDATA_SZ=1_000`, `InvType` enum
  (MsgTx=1, MsgWtx=5, MsgBlock=2, MsgWitnessTx=0x40000001,
  MsgWitnessBlock=0x40000002), `NetworkMessage::NotFound(Vec<InvVector>)`,
  `NetworkMessage::WtxidRelay`.
- `crates/network/src/peer_manager.rs` —
  `PeerInfo.supports_wtxid_relay`, `PeerInfo.feefilter`,
  `PeerInfo.relay`, `handle_event` (line 1942-2160) +
  feefilter parser (line 2076-2091),
  `send_initial_feefilter` (line 2223-2227, hardcoded 100k sat/kvB),
  `broadcast` (line 1712-1722, unconditional fan-out),
  `announce_block` (line 1733-1760), `connect_to_with_type`
  outbound init (line 1505-1541, hardcodes `supports_wtxid_relay: false`),
  `connect_to_addrv2` outbound init (line 1620-1656, same),
  `run_inbound_peer` v1 handshake loop (line 3160-3211) +
  PeerInfo construction (line 3237, hardcodes
  `supports_wtxid_relay: false` despite seeing "wtxidrelay" in handshake),
  v2 inbound PeerInfo construction (line 3606-3627, correct
  `app_hs.wants_wtxid_relay`).
- `crates/network/src/peer.rs` — `PeerId`, `PeerStats`.
- `crates/network/src/w103_tx_relay_tests.rs` — 30-gate audit doc with
  20 BUG/MISSING flagged (G1-G30); all annotated `#[ignore]` with
  detailed Core refs. **This file is the W103 prior art for this wave.**
- `crates/network/src/w99_net_processing_tests.rs:348-440` — W99 G11
  (cap PASS), G12 (orphan expiry MISSING; now superseded by W103 G22 FIXED),
  G14 (wtxid-key FIXED), G21 (inbound wtxidrelay hardcoded false).
- `crates/network/tests/test_w136_relay_flags.rs` — W136 sendheaders/
  feefilter/wtxidrelay parity tests that also instantiate the dead
  `InventoryTrickle` / `FeeFilterManager` only inside tests.
- `crates/rpc/src/server.rs:119, 144, 164, 172, 187, 199, 214,
  377-383, 3600-3760, 5383-5398` — `RpcState.mempool` (constructed with
  `MempoolConfig::default()`, `verify_scripts: false`), `recently_rejected:
  HashSet<Hash256>` (plain HashSet, no LRU), `orphanage: TxOrphanage`,
  `send_raw_transaction` broadcast at line 3743-3754 (MsgWitnessTx),
  `submitpackage` broadcast at line 5390-5395 (MsgWitnessTx).
- `crates/consensus/src/mempool.rs:714-790, 3210-3212, 3348-3350` —
  `MempoolConfig` (verify_scripts default false), `production()` helper
  (verify_scripts true), `Mempool.get(&txid)` keyed by txid only
  (NOT wtxid), `Mempool.contains(&txid)` ditto.
- `rustoshi/src/main.rs:2970-3245, 3339-3386, 3735-3811, 4082` —
  the production tx-relay pipeline: block-connect orphan housekeeping
  + `recently_rejected.clear()` (line 3009-3013), `NetworkMessage::Inv`
  handler (line 3061-3096), `NetworkMessage::Tx` handler (line 3098-3246
  — orphan promote at 3145-3187, post-ATMP relay-broadcast at 3190-3211
  using MsgWitnessTx), `NetworkMessage::GetData` handler (line 3339-3386,
  no NotFound), `NetworkMessage::MemPool` handler (line 3735-3811, uses
  MsgWitnessTx), peer-disconnect orphan-erase (line 4082).

---

## Gate matrix (~32 sub-gates)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | INV wire format (BIP-339) | G1: tx broadcast uses MSG_WTX(5) for wtxid-relay peers | **BUG-1 (P0-CDIV)** — every production broadcast (4 sites) emits `MsgWitnessTx (0x40000001)`, a BIP-144 getdata flag, NEVER `MsgWtx (5)`. Core peers silently drop these invs |
| 1 | … | G2: legacy peer broadcast uses MSG_TX(1) keyed by txid | **BUG-1 cross-cite** — broadcast hash is always `wtxid`, regardless of peer's wtxid-relay capability |
| 2 | Per-peer relay state | G3: BIP-37 `fRelay` gates outgoing inv | **BUG-2 (P0-CDIV)** — `peer_manager::broadcast` (line 1713-1722) fans out to every Established peer regardless of `peer.info.relay`; sendrawtransaction/submitpackage/p2p relay all go through it |
| 2 | … | G4: wtxidrelay flag wired from handshake to PeerInfo | **BUG-3 (P0-SEC)** — v1 inbound (line 3237) and v1+v2 outbound init (line 1526, 1642) hardcode `supports_wtxid_relay: false` despite the handshake loop observing "wtxidrelay". Only v2 inbound (line 3624) is correct. Three-pipeline drift — first single-impl 3-handshake-path wtxid hardcoding |
| 3 | InventoryTrickle (Poisson) | G5: trickle queue ever populated in production | **BUG-4 (P0-DEAD)** — `InventoryTrickle::queue_transaction_for_relay` is **never called** outside test code. `relay.rs` defines 800 LOC of fully tested but dead production scheduler |
| 3 | … | G6: per-peer Poisson rebroadcast cadence (5s inbound / 2s outbound) | **BUG-4 cross-cite** |
| 3 | … | G7: INVENTORY_BROADCAST_PER_SECOND=14 / TARGET=70 enforced | PASS in `relay.rs` constants; **DEAD** in production |
| 4 | Wtxid-keyed lookup | G8: `getdata { type=MSG_WTX, hash=wtxid }` resolved against mempool | **BUG-5 (P0-CDIV)** — `mempool.get(&item.hash)` is keyed by TXID only (`mempool.rs:3210`); a wtxid-keyed getdata returns None for every entry, the GetData handler silently swallows it, no NotFound is sent → BIP-339 wtxid-relay request loop pegs at 60s peer timeout per tx |
| 5 | NotFound emission | G9: getdata for unknown items emits NOTFOUND | **BUG-6 (P0-CDIV)** — `main.rs::NetworkMessage::GetData` handler (line 3339-3386) silently skips missing items; no `NetworkMessage::NotFound` is ever emitted. Requesting peers wait `GETDATA_TX_INTERVAL=60s` for a response that never comes |
| 6 | TxRequestTracker | G10: MAX_PEER_TX_REQUEST_IN_FLIGHT=100 cap | **BUG-7 (P1)** — no TxRequestTracker; no in-flight counting. W103 G10 documented; still unfixed |
| 6 | … | G11: MAX_PEER_TX_ANNOUNCEMENTS=5000 cap | **BUG-7 cross-cite** — W103 G9 |
| 6 | … | G12: GETDATA_TX_INTERVAL=60s per-tx expiry + retry | **BUG-7 cross-cite** — W103 G11 |
| 6 | … | G13: NONPREF_PEER_TX_DELAY=2s for inbound announces | **BUG-7 cross-cite** — W103 G12 |
| 6 | … | G14: TXID_RELAY_DELAY=2s when wtxid peers present | **BUG-7 cross-cite** — W103 G13 |
| 6 | … | G15: OVERLOADED_PEER_TX_DELAY=2s @ ≥50 in-flight | **BUG-7 cross-cite** — W103 G14 |
| 7 | Inv-to-getdata propagation | G16: outgoing getdata caps at MAX_GETDATA_SZ=1000 | PASS for the helper (`batch_getdata_items`); **BUG-8 (P1)** — `main.rs:3061-3096` produces a single `GetData(tx_requests)` with up to `MAX_INV_SIZE=50_000` entries (uncapped echo of the inbound inv) instead of chunking via `batch_getdata_items` |
| 8 | Inv-to-getdata wtxid passthrough | G17: getdata reuses the inv-announced type/hash | PARTIAL — line 3080 takes `item.clone()` which keeps the wtxid hash + MsgWitnessTx type; combined with BUG-5 the wtxid-keyed lookup then fails. This is a single bug surface; tracked as part of BUG-5 |
| 9 | Mempool MEMPOOL request | G18: NODE_BLOOM advertised gate before serving | PASS (`main.rs:3741-3765`) |
| 9 | … | G19: peer's `fRelay=false` rejects the request | **BUG-9 (P1)** — MEMPOOL handler does not consult `peer.info.relay`; only the NODE_BLOOM advertised-on-our-side gate runs |
| 9 | … | G20: `OutboundTargetReached(false)` bandwidth gate | **BUG-10 (P1)** — W103 G18 cross-cite; no bandwidth gate at all |
| 9 | … | G21: response uses MSG_WTX(5) for wtxid-relay peers | **BUG-1 cross-cite** (4th broadcast site emits MsgWitnessTx) |
| 10 | TxOrphanage cap + eviction | G22: DEFAULT_MAX_ORPHAN_TRANSACTIONS=100 enforced | PASS (`orphanage.rs:52`, FIFO eviction) |
| 10 | … | G23: per-peer cap MAX_ORPHANS_PER_PEER=100 enforced | PASS (`orphanage.rs:60`) |
| 10 | … | G24: wtxid primary key (BIP-339) | PASS (`orphanage.rs:130`) |
| 10 | … | G25: time-based expiry (ORPHAN_TX_EXPIRE_TIME=20min) is invoked | **BUG-11 (P1)** — `expire_orphans` exists and is well-tested (W103 G22 FIXED) but is **never called** from any production code path. Orphans live until the count cap evicts them, defeating the time-based housekeeping the constant exists for |
| 10 | … | G26: erase_for_block called on every connect | **BUG-12 (P1)** — wired on one path only (`main.rs:3009`, post-`block_store.write_block`); reorg paths and the AssumeUTXO snapshot path do not invoke it. Same shape as W148 carry-forward "one path of N is correct" |
| 10 | … | G27: erase_for_peer called on every disconnect | PARTIAL — `main.rs:4082` covers the standard disconnect path; no equivalent in the peer-manager's `PeerEvent::Disconnected` arm (peer_manager.rs:2001-2016), which fires for handshake-failure disconnects too |
| 11 | Orphan promote pipeline | G28: ProcessOrphanTx called after every ATMP success | PARTIAL — wired in the P2P `NetworkMessage::Tx` arm (main.rs:3145-3187) but NOT in the `sendrawtransaction` RPC path (server.rs:3600+, the success branch at line 3729-3756 broadcasts but never calls `orphanage.find_children`) nor `submitpackage` (server.rs:5380+) |
| 11 | … | G29: BFS-recursive orphan resolution | **BUG-13 (P1)** — W103 G25 cross-cite; `find_children` is single-level. Three-level chain (grandparent → parent → child) requires two manual `find_children` calls but the wired-up promote loop (main.rs:3152-3187) is non-recursive — only direct children of the just-accepted tx are retried |
| 11 | … | G30: orphan promote inherits production script-verify config | **BUG-14 (P0-SEC)** — `verify_scripts: false` (W150 BUG-2 carry-forward) — the orphan retry at main.rs:3155 calls `mempool.add_transaction` with the same MempoolConfig that has `verify_scripts=false`, so promoted orphans bypass signature verification entirely |
| 12 | recently_rejected (m_recent_rejects) | G31: bounded data structure with LRU | **BUG-15 (P1)** — `RpcState.recently_rejected: HashSet<Hash256>` is a plain HashSet hard-capped at 50_000 entries (`main.rs:3242-3244`); once full, no further additions accepted (drop-newest, not evict-oldest). Core uses `CRollingBloomFilter(120_000, 0.000001)` |
| 12 | … | G32: wtxid-keyed (BIP-339) | **BUG-16 (P1)** — `recently_rejected` is keyed by txid only (line 3243 inserts `txid`), but the inv-check at line 3078 (`recently_rejected.contains(&item.hash)`) compares against the inbound inv hash which may be a wtxid → false-negative on every wtxid-relay re-announce of a rejected tx |
| 13 | BIP-133 feefilter cadence | G33: Poisson AVG_FEEFILTER_BROADCAST_INTERVAL=10min rebroadcast | **BUG-17 (P1)** — `send_initial_feefilter` (peer_manager.rs:2223-2227) sends once at handshake; no periodic refresh. `FeeFilterManager::get_pending_feefilters` exists but `FeeFilterManager` is the dead module from BUG-4 |
| 13 | … | G34: FeeFilterRounder privacy quantisation on outgoing value | **BUG-18 (P1)** — outgoing fee filter is the constant `100_000` (peer_manager.rs:2225). No `FeeFilterRounder::round()` call. The 100k value is also wrong as a "during-IBD signal" — Core uses MAX_MONEY |
| 13 | … | G35: IBD signal switches outgoing filter to MAX_MONEY | **BUG-18 cross-cite** — the hardcoded 100k is not IBD-aware |
| 14 | UNREQUESTED tx penalty | G36: peer sending tx without prior INV → Misbehaving(20) | **BUG-19 (P1)** — W103 G28 cross-cite; no per-peer expected-tx set, no penalty |
| 15 | post-handshake WtxidRelay | G37: WtxidRelay received AFTER VERACK → misbehavior | **BUG-20 (P1)** — `NetworkMessage::WtxidRelay` is parsed in the pre-handshake loop only (peer_manager.rs:3186); the post-handshake handler has no arm for it, so a peer that violates BIP-339 by sending it after VERACK is silently ignored instead of penalised |
| 16 | OrphanByParent index | G38: parent-arrival erase is O(degree) not O(N) | **BUG-21 (P1)** — `TxOrphanage::erase_for_block` walks the entire `by_wtxid` map (`orphanage.rs:312-337`), O(N) per call. Core's `OrphanByParent: std::map<COutPoint, ...>` allows O(per-spent-outpoint) erase. With 100 orphans this is fine; with a future weight-based cap (Core trended to ~10k) it would matter |
| 17 | Three-pipeline broadcast drift | G39: a single InitiateTxBroadcastToAll call path | **BUG-22 (P0)** "three-pipeline drift" — four separate sites broadcast (server.rs:3743 sendrawtransaction; server.rs:5390 submitpackage; main.rs:3194 p2p-Tx-accepted; main.rs:3780 mempool-message-reply) with cut-and-paste InvVector construction, none using the relay.rs `build_tx_inv_entry` helper, none using `InventoryTrickle`. Easy to drift further on the next add |

---

## BUG-1 (P0-CDIV) — Tx broadcast wire format: every production site emits `MsgWitnessTx (0x40000001)` instead of `MsgWtx (5)`; rustoshi invisible to BIP-339 peers

**Severity:** P0-CDIV. The W103 audit observed this and the
`relay.rs::build_tx_inv_entry` helper was added (G20a "FIXED") to
produce the correct `MsgWtx (5)` per BIP-339 / Core
`protocol.h:481`. However, **every** production tx-relay broadcast
site in rustoshi continues to use `MsgWitnessTx (0x40000001)` — the
BIP-144 *getdata* witness flag, which is not a valid inv message
type. Modern Core peers silently drop inv entries with that type
(see Core's `InvType::Error` fallback at `protocol.h:486`), making
rustoshi invisible as a relay source on the network.

**Sites (all production):**
1. `crates/rpc/src/server.rs:3741-3747` — `sendrawtransaction` RPC.
2. `crates/rpc/src/server.rs:5390-5395` — `submitpackage` RPC.
3. `rustoshi/src/main.rs:3192-3211` — P2P `NetworkMessage::Tx`
   acceptance path (re-broadcast to all other peers).
4. `rustoshi/src/main.rs:3779-3789` — MEMPOOL message reply
   (inv-dump in response to peer's MEMPOOL request).

The `relay.rs::build_tx_inv_entry` helper exists, is correctly
implemented and tested, but is **never called from production code**
(grep of `crates/`, `rustoshi/`, excluding `tests/` and worktrees,
returns zero matches).

**File:** see four sites above.

**Core ref:** `bitcoin-core/src/protocol.h:481,486` — `MSG_WTX = 5`,
`MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG` (a getdata-only flag);
`bitcoin-core/src/net_processing.cpp::RelayTransaction` —
`hash = peer->m_wtxid_relay ? wtxid : txid`,
`inv_type = peer->m_wtxid_relay ? MSG_WTX : MSG_TX`.

**Excerpt (server.rs::send_raw_transaction, mainnet-active code)**
```rust
// Use WitnessTx type since we support SegWit
let inv = vec![InvVector {
    inv_type: InvType::MsgWitnessTx,  // <-- 0x40000001, getdata flag
    hash: wtxid,                      // <-- wtxid sent regardless of peer
}];
let inv_msg = NetworkMessage::Inv(inv);

// Broadcast to all connected peers
let peer_state = self.peer_state.read().await;
if let Some(ref peer_manager) = peer_state.peer_manager {
    peer_manager.broadcast(inv_msg).await;  // <-- no per-peer wtxid-relay check
    tracing::debug!("Relayed transaction {} to peers", txid.to_hex());
}
```

The inline comment "Use WitnessTx type since we support SegWit" is a
**comment-as-confession**: it admits the author chose the wire value
for "witness support" reasons without checking that Core distinguishes
`MSG_WTX (5)` (inv message, BIP-339) from `MSG_WITNESS_TX (0x40000001)`
(getdata witness flag, BIP-144).

**Impact:**
- BIP-339 wtxid-relay peers (most of the network as of 2024+) silently
  ignore rustoshi's inv announcements; rustoshi's mempool acceptances
  never propagate.
- Pre-BIP-339 peers (rare today) would also fail to decode the value
  as a known inv type.
- rustoshi is effectively a **sink-only** node for tx relay: it
  accepts inbound txs (the inv-to-getdata path at main.rs:3061-3094
  is permissive about inbound types) but cannot forward them.
- Carry-forward of W103 G20 / G20a — the FIXED helper was added but
  never wired to the call sites. Classic "wiring-look-but-no-wire".

---

## BUG-2 (P0-CDIV) — `PeerManagerImpl::broadcast` ignores BIP-37 `fRelay`; relay-disabled peers still receive tx invs

**Severity:** P0-CDIV. Bitcoin Core's tx relay path is gated on
`peer.GetTxRelay()` (the post-BIP-37 `fRelay` field of VERSION). If a
peer set `relay=false` in their VERSION (e.g., a block-only client),
Core never sends them tx-related messages. Sending a tx inv to a
no-relay peer is both a BIP-37 protocol violation AND a privacy leak
(reveals our mempool acceptances to a peer that explicitly opted out).

`crates/network/src/peer_manager.rs:1712-1722`:
```rust
pub async fn broadcast(&self, msg: NetworkMessage) {
    for peer in self.peers.values() {
        if peer.info.state == PeerState::Established {
            let _ = peer.command_tx
                .send(PeerCommand::SendMessage(msg.clone()))
                .await;
        }
    }
}
```

No `peer.info.relay` check. Every tx broadcast (BUG-1 cross-cite, 4
call sites) fans out to every Established peer including those who
sent `relay=false`. The `relay.rs::PeerRelayState::queue_transaction`
helper (line 531-540) DOES check `if !self.relay { return false; }`,
but `PeerRelayState` is part of the dead `InventoryTrickle` (BUG-4).

The main.rs:3192-3211 P2P re-broadcast path additionally filters
`if pid != peer_id` (don't re-announce to the source) but performs
no `info.relay` check either.

**File:** `crates/network/src/peer_manager.rs:1712-1722`;
all four BUG-1 call sites.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`
— iterates `m_peer_map`, `if (auto tx_relay = peer.m_tx_relay)` gate
is the very first check.

**Impact:**
- BIP-37 protocol violation on every tx broadcast.
- Privacy leak to peers that explicitly opted out of tx relay.
- Bandwidth waste sending invs that the peer will drop (or worse,
  penalise us for sending).

---

## BUG-3 (P0-SEC) — v1 inbound + v1/v2 outbound hardcode `supports_wtxid_relay: false`; three of four handshake paths broken

**Severity:** P0-SEC ("three-pipeline drift" — first single-impl
3-out-of-4 handshake-path drift on the same flag). BIP-339
WTXIDRELAY negotiation must be honoured per-peer so the rest of the
relay machinery (inv types, getdata lookups, request scheduler) can
dispatch on the right hash format. rustoshi tracks the flag in
`PeerInfo.supports_wtxid_relay`, but only one of the four handshake
paths actually populates it from the handshake observations.

**Sites (peer_manager.rs):**
1. **v1 outbound** initiator: `connect_to_with_type` (line 1505-1541)
   constructs `PeerInfo` with `supports_wtxid_relay: false` at line
   1526. The wtxidrelay message is later parsed in `run_outbound_peer`
   but the flag never makes it back to the handle's `PeerInfo`.
2. **v1 outbound (addrv2 path)**: `connect_to_addrv2` (line
   1620-1656) repeats the same hardcoded `false` at line 1642.
3. **v1 inbound**: `run_inbound_peer` (line 3160-3211) explicitly
   parses "wtxidrelay" in the pre-handshake loop (line 3186-3191) and
   does NOTHING with it (`continue;`), then constructs PeerInfo with
   `supports_wtxid_relay: false` at line 3237.
4. **v2 inbound**: line 3624 — `supports_wtxid_relay:
   app_hs.wants_wtxid_relay`. CORRECT.

W103 G3 and W99 G21 both flagged this; both still open.

**Excerpt (peer_manager.rs:3186-3211 — v1 inbound)**
```rust
"wtxidrelay" | "sendaddrv2" | "sendtxrcncl" => {
    if cmd == "sendaddrv2" {
        wants_addrv2 = true;
    }
    continue;       // <-- "wtxidrelay" branch falls through, no flag captured
}
...
let peer_info = PeerInfo {
    ...
    supports_wtxid_relay: false,    // <-- HARDCODED line 3237
    supports_addrv2: wants_addrv2,
    ...
};
```

The handler stores `wants_addrv2` correctly but has no symmetric
local `wants_wtxid_relay`. Adding one and propagating to the
PeerInfo construction would be a one-line fix per call site.

**File:** `crates/network/src/peer_manager.rs:1526, 1642, 3186-3191, 3237`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3921-3938`
(`ProcessMessage` WTXIDRELAY arm sets `peer.m_wtxid_relay = true`
only before VERACK and only for `version >= 70016`).

**Impact:**
- Three of four handshake paths produce peers that report `false` for
  wtxid-relay support even when the remote negotiated it.
- Combined with BUG-1 (broadcast always uses MsgWitnessTx with wtxid
  hash regardless of flag) the actual on-wire effect is masked, but
  any code that later branches on `supports_wtxid_relay` (the dead
  `InventoryTrickle` would; future fixes for BUG-5 will) will treat
  these peers as txid-only and disagree with what the peer expects.
- W99 G21 was filed 2025; W103 G3 was re-filed; still open after 6+
  weeks. **Carry-forward to W152 (third re-anchoring).**

---

## BUG-4 (P0-DEAD) — `InventoryTrickle` + `FeeFilterManager` + `PeerRelayState` are fully implemented, fully tested, and entirely unused in production

**Severity:** P0-DEAD ("dead-anti-DoS code" fleet pattern — W148
BUG-8 rustoshi `HeadersPresyncState` precedent). `crates/network/src/relay.rs`
defines ~800 LOC of production-quality scheduling, BIP-133 feefilter,
Poisson timing, BIP-339 dispatch, RBF accounting, and per-peer relay
state. Every test in the file passes. **Production code never
instantiates any of it.**

```
$ grep -rn "InventoryTrickle::\|FeeFilterManager::\|queue_transaction_for_relay" \
       crates/ rustoshi/ --include='*.rs' \
       | grep -v "tests\.rs:\|test_w136\|relay\.rs"
(no matches)
```

The actual production tx-relay path is the cut-and-paste
`peer_manager.broadcast(...)` call from four sites (BUG-1) which
fan out immediately to every peer with no:
- Poisson jitter (privacy fingerprinting; Core uses
  `NextInvToInbounds(5s, network_key)` for inbound),
- inbound vs outbound interval distinction (5s vs 2s),
- per-peer `recently_announced_invs` LRU,
- `INVENTORY_BROADCAST_PER_SECOND=14` global rate limit,
- BIP-37 `fRelay` gate (BUG-2),
- BIP-339 hash/type selection (BUG-1),
- `m_relay_to_set` for `FindTxForGetData` lookback (W103 G27).

Likewise, the BIP-133 feefilter path (BUG-17/BUG-18) is a hardcoded
100k-sat-once-on-handshake `send_initial_feefilter` call rather than
the periodic, rounded, IBD-aware, change-triggered protocol the
`FeeFilterManager` implements.

**File:** entire `crates/network/src/relay.rs` (1585 LOC); referenced
only by the in-file `#[cfg(test)]` block and external test files
`w103_tx_relay_tests.rs`, `test_w136_relay_flags.rs`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::SendMessages`
(line 5980-6100 in current Core) — the per-peer per-tick rebroadcast
loop is the canonical implementation that `InventoryTrickle` mirrors.

**Impact:**
- Fingerprinting: rustoshi peers can be identified on the network by
  the immediate-broadcast pattern (no Poisson jitter).
- Privacy: tx-origin inference is trivial (announcement timestamp
  ≈ acceptance timestamp).
- Bandwidth spikes: bursts of mempool admissions create simultaneous
  inv fan-outs.
- Misbehavior risk: high-volume periods can exceed
  `INVENTORY_BROADCAST_PER_SECOND=14` and trigger penalties from
  Core peers that enforce the rate.
- Fleet pattern: this is exactly the W148 BUG-8 rustoshi
  `HeadersPresyncState` shape — production-quality anti-DoS subsystem
  exists in the tree, compiles, has full unit tests, but no
  production code path wires it in. **Third rustoshi instance of the
  fleet "dead-anti-DoS" pattern** (after W148 HeadersPresyncState
  and W120 PackageManager).

---

## BUG-5 (P0-CDIV) — Mempool `get()` is keyed by txid only; BIP-339 wtxid-keyed getdata returns no match for any entry

**Severity:** P0-CDIV. Bitcoin Core's `FindTxForGetData`
(`net_processing.cpp:2457`) looks up mempool entries by wtxid when the
inv type is `MSG_WTX` and by txid when `MSG_TX`. rustoshi's
`Mempool::get(&self, txid: &Hash256)` (consensus/mempool.rs:3210) takes
ONLY a txid; there is no `get_by_wtxid()` and no parallel index.

`main.rs::NetworkMessage::GetData` handler (line 3368-3382):
```rust
InvType::MsgTx | InvType::MsgWitnessTx => {
    // Serve transaction from mempool
    let rpc = rpc_state.read().await;
    if let Some(entry) = rpc.mempool.get(&item.hash) {
        let tx = entry.tx.clone();
        drop(rpc);
        ...
```

`item.hash` is the wtxid for an inv announcement that came from a
wtxid-relay peer. `mempool.get(&wtxid)` searches the txid-keyed
HashMap and returns `None`. The handler then silently swallows the
miss (no NOTFOUND — see BUG-6). The peer's `TxRequestTracker` waits
`GETDATA_TX_INTERVAL=60s` for a response that never comes, then
tries the next-best peer.

Note that the handler does NOT match on `InvType::MsgWtx`; the only
matched arms are `MsgTx | MsgWitnessTx`. If a Core peer ever sent a
correctly-encoded `MSG_WTX (5)` getdata, the arm wouldn't even fire —
the `_ => {}` fall-through at line 3383 would drop it.

**File:** `crates/consensus/src/mempool.rs:3210`;
`rustoshi/src/main.rs:3368-3382`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::FindTxForGetData`
(consults `m_mempool.info(GenTxid::Wtxid(inv.hash))` when the inv
type is `MSG_WTX`).

**Impact:**
- BIP-339 wtxid-relay peers waste 60s per tx waiting for a getdata
  response that cannot succeed.
- After BUG-1 is fixed (correct MSG_WTX(5) emission), this bug
  becomes the next blocker — fixing only BUG-1 would emit
  correctly-typed invs but still fail to serve them.
- `MsgWtx (5)` arm is missing entirely (only `MsgTx | MsgWitnessTx`
  matched) — even if mempool had a wtxid index, the dispatch logic
  wouldn't reach it.

---

## BUG-6 (P0-CDIV) — GetData handler does not emit `NotFound`; requesting peers stall on every miss

**Severity:** P0-CDIV. `bitcoin-core/src/net_processing.cpp::ProcessGetData`
walks the requested items, serves what it can, and **emits a single
`NotFound` message at the end listing every item that wasn't
served**. Without this, the requesting peer's `TxRequestTracker`
cannot know the item is gone and waits the full `GETDATA_TX_INTERVAL=60s`
per-request before retrying the next-best peer (`txdownloadman_impl.cpp`
ReceivedNotFound path).

rustoshi's GetData handler (`main.rs:3339-3386`) walks the requested
items, serves what it can, and silently drops the rest. There is no
final `NotFound` send. The `NetworkMessage::NotFound(Vec<InvVector>)`
variant exists in `message.rs:205` and has correct
serialize/deserialize coverage (line 762, 1003, tests), but no
production code path emits it.

```
$ grep -rn "NetworkMessage::NotFound" crates/ rustoshi/ \
       --include='*.rs' | grep -v "tests\|message\.rs"
(no matches)
```

Combined with BUG-5: a BIP-339 wtxid-relay peer requesting any tx
gets neither a response nor a notfound; it waits 60s per request,
then re-tries the same fruitless lookup against a different peer.
Aggregate effect across the network: rustoshi is a 60s-latency hole
in the wtxid-relay graph.

**File:** `rustoshi/src/main.rs:3339-3386`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetData`
final `vNotFound` send.

**Impact:**
- Per-tx 60s peer-side stall on every miss.
- For wtxid-relay peers + BUG-5, every tx is a miss → 60s per tx.
- Reduces the network's overall tx-relay throughput in proportion to
  rustoshi's share of peer connections.

---

## BUG-7 (P1) — TxRequestTracker subsystem is entirely absent; six Core constants unenforced

**Severity:** P1 ("entire subsystem missing" / W103 carry-forward).
Core's `TxRequestTracker` (`bitcoin-core/src/node/txrequest.cpp`) is
the scheduler that decides WHEN and FROM WHOM to request each
announced tx. It enforces six numeric constants:

| Core constant | Value | Purpose |
|---------------|-------|---------|
| `MAX_PEER_TX_REQUEST_IN_FLIGHT` | 100 | Cap on concurrent getdata to one peer |
| `MAX_PEER_TX_ANNOUNCEMENTS` | 5000 | Cap on outstanding announcements per peer |
| `TXID_RELAY_DELAY` | 2s | Delay txid announces when wtxid peers available |
| `NONPREF_PEER_TX_DELAY` | 2s | Delay requests to non-preferred (inbound) peers |
| `OVERLOADED_PEER_TX_DELAY` | 2s | Delay requests to peer with ≥100 in-flight |
| `GETDATA_TX_INTERVAL` | 60s | Per-request expiry; retry next-best peer |

rustoshi defines **none** of these in production code. W103 G9-G15
already documented this for the announcement side; the request
side is equally absent. `main.rs:3061-3094` is the entire production
"request scheduler": it sees an inv, builds a `GetData(tx_requests)`
list of items not in mempool/recently_rejected, fires immediately.
No delay, no in-flight count, no fairness, no retry, no expiry.

**Files:** no production file declares `MAX_PEER_TX_REQUEST_IN_FLIGHT`,
`MAX_PEER_TX_ANNOUNCEMENTS`, `TXID_RELAY_DELAY`, `NONPREF_PEER_TX_DELAY`,
`OVERLOADED_PEER_TX_DELAY`, or `GETDATA_TX_INTERVAL` (grep result
empty); `crates/network/src/w103_tx_relay_tests.rs:6-37` documents
the gaps as G9-G15 with `todo!()` placeholders.

**Core ref:** `bitcoin-core/src/node/txrequest.cpp` (the entire file
— ~400 LOC implementing the CANDIDATE → REQUESTED → COMPLETED state
machine); `bitcoin-core/src/node/txdownloadman.h:24-38` for constants.

**Impact:**
- Censorship vector: a single peer that announces a tx first
  monopolises the request slot; no alternating-announcer fallback.
- DoS vector: an attacker can announce 50k tx hashes per inv (BUG-23
  cross-cite) and never get rate-limited at the announcement layer.
- Bandwidth amplification: missing OVERLOADED_PEER_TX_DELAY means
  rustoshi can blast getdata to a single peer with no slow-down.
- W103 G9-G15 first flagged Mar 2026; **W152 third re-anchoring
  carry-forward** with no progress.

---

## BUG-8 (P1) — Outgoing getdata not chunked at `MAX_GETDATA_SZ=1000`; can emit single 50k-item getdata

**Severity:** P1. Bitcoin Core caps each getdata response at
`MAX_GETDATA_SZ = 1000` items per message (`net_processing.cpp:6207`,
break out of the serve loop). The `batch_getdata_items` helper in
`relay.rs:849-857` was added in W103 (G5 FIXED) to split a list into
chunks ≤ 1000 — but it is **never called from production code**.

`main.rs:3061-3096` builds `tx_requests` by iterating an inbound
`Inv` (which can be up to `MAX_INV_SIZE = 50_000` items per Core's
parse cap) and pushes EVERY tx-inv that is not in mempool/recently-rejected
into a single `Vec<InvVector>`, then fires it as one `GetData`
message:

```rust
let mut tx_requests = Vec::new();
for item in &inv_items {
    match item.inv_type {
        InvType::MsgTx | InvType::MsgWitnessTx => {
            let rpc = rpc_state.read().await;
            if !rpc.mempool.contains(&item.hash)
                && !rpc.recently_rejected.contains(&item.hash)
            {
                tx_requests.push(item.clone());     // unbounded
            }
        }
        ...
    }
}
if !tx_requests.is_empty() {
    pm.send_to_peer(peer_id, NetworkMessage::GetData(tx_requests)).await;
    //                                       ^^^^^^^^^^^^^^^^^^^^
    //                       up to 50_000 items in one message
}
```

A malicious peer sending a max-size inv would then get a
50_000-item getdata back from us — which Core (the canonical target)
would reject with `Misbehaving(20)` at `net_processing.cpp:4131`.
Our own peer code's parse-side cap (message.rs:983, also 50_000)
allows the message to be encoded; but if the peer disconnects or
penalises us, the relay flow stalls.

**File:** `rustoshi/src/main.rs:3061-3096`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:128, 6207` —
`MAX_GETDATA_SZ = 1000` + `break` out of serve loop;
`bitcoin-core/src/net_processing.cpp:4131` — `if (vInv.size() >
MAX_INV_SZ) Misbehaving(20)` on receive (note: the cap is shared
with inv, but Core's serving-side break-at-1000 means it would
never EMIT >1000).

**Impact:**
- Outgoing getdata can be up to 50× larger than Core's max → peer
  may penalise / disconnect us.
- Helper exists (`batch_getdata_items`) but is unused — classic
  "wiring-look-but-no-wire".
- Easy fix: chunk via `batch_getdata_items(tx_requests).into_iter().for_each(|chunk| pm.send_to_peer(...))`.

---

## BUG-9 (P1) — MEMPOOL request handler does not check peer's `fRelay`

**Severity:** P1. Core's MEMPOOL handler (`net_processing.cpp:4852`)
checks:
1. `tx_relay = peer.GetTxRelay()` — peer must have negotiated tx relay,
2. `m_connman.OutboundTargetReached(false)` — bandwidth gate,
3. `(peer.m_our_services & NODE_BLOOM)` — service flag gate.

rustoshi's MEMPOOL handler (`main.rs:3735-3811`) implements the
NODE_BLOOM gate (line 3741-3765, with correct disconnect-on-violation)
but skips (1) and (2). A peer that sent `relay=false` in VERSION
(block-only client) can still trigger a full mempool dump just by
sending a MEMPOOL message — which violates BIP-37 and wastes
bandwidth on a peer that won't relay anything back.

**File:** `rustoshi/src/main.rs:3735-3811`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4852`.

**Impact:** BIP-37 violation; pointless mempool dump to block-only
peers. Combined with BUG-2 (broadcast ignores fRelay) the
fRelay-related fleet behaviour is broken end-to-end.

---

## BUG-10 (P1) — MEMPOOL handler has no bandwidth gate

**Severity:** P1 ("W103 G18 cross-cite"). Core gates the MEMPOOL
dump on `OutboundTargetReached(false)` so that an upload-budget-saturated
node refuses further mempool dumps. rustoshi has no upload accounting
at all, hence no gate. A pool of attackers connecting and sending
MEMPOOL repeatedly can extract unbounded bandwidth.

**File:** `rustoshi/src/main.rs:3735-3811`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4852-4900`.

**Impact:** bandwidth DoS vector via mempool dumps.

---

## BUG-11 (P1) — `TxOrphanage::expire_orphans` is never called from production

**Severity:** P1 ("dead-data plumbing" / fleet pattern, ~10th
rustoshi instance). W103 G22 was "FIXED" by adding
`OrphanEntry.inserted_at`, `ORPHAN_TX_EXPIRE_TIME=20min`, and
`TxOrphanage::expire_orphans(now)`. The implementation is complete,
correct, and tested. **No production code path calls it.**

```
$ grep -rn "expire_orphans\|orphan_expire\|orphan_cleanup" crates/ rustoshi/ \
       --include='*.rs' | grep -v "tests\|orphanage\.rs"
(no matches)
```

The orphanage is held in `RpcState.orphanage` and is bounded only by
count (FIFO eviction at 100 entries). Per the W103 G22 docstring:
"Callers should invoke this periodically from the main event loop."
The main event loop in `rustoshi/src/main.rs` does not.

**File:** `rustoshi/src/main.rs` (no caller); `crates/consensus/src/orphanage.rs:394-411`
(method definition, has callers only in tests).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::LimitOrphans`
(time-sweep gate historically `ORPHAN_TX_EXPIRE_TIME = 20*60`,
removed in PR #32941 in favor of weight-based TTL; rustoshi
preserves the historical constant intentionally).

**Impact:**
- Orphans stay in the pool until count-pressure evicts them, which
  may take days on a quiet network (max 100 orphans).
- No memory release for orphans whose parent never arrives.
- Dead-data plumbing pattern: the method exists, is tested, the
  constant exists, the docstring tells callers to invoke periodically
  — and no caller does.

---

## BUG-12 (P1) — `TxOrphanage::erase_for_block` only wired on one block-arrival path

**Severity:** P1 ("one-path-of-N is correct" carry-forward from
W148). The orphanage's block-arrival housekeeping is critical: any
orphan whose inputs were spent by the newly-connected block is
permanently invalid and must be erased. rustoshi calls
`erase_for_block` from exactly one site in `main.rs:3009` — the P2P
block-connect handler post-`block_store.write_block`. The site is
correctly fed `block_txids` and `block_spent`.

Other block-arrival paths in rustoshi do NOT call it:
- Reorg path in `chain_manager.rs` (disconnect + reconnect): no
  per-disconnect or per-reconnect orphan housekeeping.
- AssumeUTXO snapshot load: chainstate jumps to a new tip with no
  orphan sweep.
- RPC `submitblock` success path: no orphan housekeeping (block was
  injected but the orphanage of the same RpcState is not touched).

`erase_for_peer` is only called on `PeerEvent::Disconnected` flowing
through `main.rs:4082`; the peer-manager's own
`PeerEvent::Disconnected` arm in `peer_manager.rs:2001-2016` does not
call it (those disconnects happen for handshake failures and peer
eviction).

**File:** `rustoshi/src/main.rs:3009, 4082`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForBlock`,
`EraseForPeer` (called from
`net_processing.cpp::BlockConnected` and the disconnect handler;
universal coverage).

**Impact:**
- After a reorg, orphans whose parent was spent by the
  disconnected-and-replaced chain stay in the pool indefinitely.
- After an AssumeUTXO snapshot load, the orphanage carries
  pre-snapshot entries that may now be invalid.

---

## BUG-13 (P1) — Orphan promote pipeline is single-level, not recursive (W103 G25 carry-forward)

**Severity:** P1. After a tx is accepted to the mempool,
`main.rs:3152-3187` walks orphans whose inputs reference the
just-accepted txid and re-runs ATMP on each (G19 partially fixed in
W103). The retry is **single-level**: it does not BFS through
descendants. A three-level chain (grandparent → parent → child) is
retried at level 1 only; if `parent` is admitted, `child` is left
in the orphanage. Eventually the FIFO cap or BUG-11 (if it were
called) would evict child, but it never reaches the mempool.

`crates/consensus/src/orphanage.rs::find_children` returns only
direct children of `parent_txid`; there is no
`find_descendants_bfs()` helper. The caller would have to wrap
`find_children` in a BFS loop, queueing newly-admitted children's
txids.

**File:** `rustoshi/src/main.rs:3152-3187`;
`crates/consensus/src/orphanage.rs:352-367` (single-level method).

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessOrphanTx` —
`std::set<uint256> orphan_work_set` drives BFS through descendants.

**Impact:** CPFP / chained txs don't propagate past the first hop.
A child-pays-for-parent transaction where both parent and child are
orphan at first will see only parent admitted; child stays in
orphanage forever (or until evicted by count pressure with BUG-11).

---

## BUG-14 (P0-SEC) — Orphan promotion inherits `verify_scripts: false` (W150 BUG-2 carry-forward)

**Severity:** P0-SEC. W150 BUG-2 documented that `MempoolConfig::default()`
ships with `verify_scripts: false` (`crates/consensus/src/mempool.rs:747`)
and that production `RpcState` constructs the mempool with this
default (`crates/rpc/src/server.rs:172, 199`). All ATMP calls from
production code therefore skip script verification — including the
**orphan promote retry** at `main.rs:3155-3171`:

```rust
let children = rpc.orphanage.find_children(&txid);
for entry in children {
    let child_txid = entry.tx.txid();
    let admit = rpc.mempool.add_transaction(
        (*entry.tx).clone(),
        &|outpoint| { ... }
    );
    ...
}
```

`rpc.mempool` is the same instance that has `config.verify_scripts =
false`. An attacker who can deliver an orphan tx with a bad
signature whose parent later legitimately enters the mempool gets
their orphan **silently admitted to the mempool with no signature
check**. The tx then propagates (well, would propagate if BUG-1 were
fixed) and is only rejected when an honest miner tries to include it
in a block — at which point it gets removed but the bandwidth and
relay-trust damage is done.

**File:** `crates/consensus/src/mempool.rs:714-790`;
`crates/rpc/src/server.rs:172, 199`; `rustoshi/src/main.rs:3155-3171`.

**Core ref:** `bitcoin-core/src/validation.cpp::AcceptToMemoryPool`
always runs `PolicyScriptChecks` + `ConsensusScriptChecks`. There is
no analogous knob for "production with scripts off".

**Impact:**
- DoS vector: attacker floods orphanage with invalid-signature
  orphans whose parent will eventually arrive; on parent arrival
  ALL invalid orphans get admitted in one batch.
- Mempool-policy violation: rustoshi's mempool may contain txs that
  would be rejected by every other implementation.
- Fee-estimator poisoning: invalid txs counted as "accepted" inflate
  the estimator's view of network demand.
- W150 BUG-2 is the root cause; this is a discovery of one more
  consumer of the broken default. **Compounds the W150 problem
  rather than introduces a new one — but adds urgency.**

---

## BUG-15 (P1) — `recently_rejected` is a plain `HashSet` capped at 50_000 with drop-newest, not LRU

**Severity:** P1. Bitcoin Core's `m_recent_rejects` is a
`CRollingBloomFilter(120_000, 0.000001)` (`net_processing.cpp:108`),
i.e., a rolling probabilistic set that evicts oldest entries on
overflow. rustoshi uses `RpcState.recently_rejected: HashSet<Hash256>`
(server.rs:144) with a hardcoded check `if rpc.recently_rejected.len()
< 50_000` (main.rs:3242-3244) that DROPS NEW additions once full
rather than evicting old ones.

```rust
if rpc.recently_rejected.len() < 50_000 {
    rpc.recently_rejected.insert(txid);
}
```

Once the set fills (50_000 distinct rejects since startup or last
block, since the set is `.clear()`ed on block connect at line 3013):
- No further rejects are remembered.
- Future re-announces of those new rejects go through full ATMP
  again (CPU DoS).

The 50_000 cap is also lower than Core's 120_000.

**File:** `crates/rpc/src/server.rs:144`; `rustoshi/src/main.rs:3242-3244`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:108`
(`CRollingBloomFilter(120_000, 0.000001)`).

**Impact:** CPU amplification under sustained spam; first 50k unique
rejects are remembered, all subsequent ones are re-validated on each
announce.

---

## BUG-16 (P1) — `recently_rejected` is keyed by txid; wtxid-keyed re-announces bypass it

**Severity:** P1. The `recently_rejected.insert(txid)` at
`main.rs:3243` stores the **txid** of a rejected tx. The
inv-filter check at `main.rs:3078` does:

```rust
if !rpc.mempool.contains(&item.hash)
    && !rpc.recently_rejected.contains(&item.hash)
{
    tx_requests.push(item.clone());
}
```

`item.hash` is whatever the announcer put in the inv. For wtxid-relay
peers (BIP-339), `item.hash` is the **wtxid**, not the txid. The
`recently_rejected.contains(&wtxid)` check returns false because the
set holds txids. Result: re-announces of a rejected tx from a
wtxid-relay peer pass the filter, get re-requested via getdata, and
re-validated.

Symmetric to BUG-5 (mempool lookup) and BUG-1 (broadcast wire format)
— this is the same "rustoshi maintains txid maps but receives wtxids"
class of bug.

**File:** `rustoshi/src/main.rs:3078, 3243`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`m_recent_rejects` is keyed by wtxid for wtxid-relay items;
`AlreadyHaveTx` consults both txid-keyed and wtxid-keyed sets.

**Impact:** rejected tx can be re-announced indefinitely by a
wtxid-relay peer, bypassing the entire rejection cache.

---

## BUG-17 (P1) — BIP-133 feefilter is sent once at handshake, no Poisson rebroadcast

**Severity:** P1. Bitcoin Core's feefilter cadence is:
- Send once at handshake (typically the IBD signal `MAX_MONEY`).
- Poisson-distributed re-broadcasts at `AVG_FEEFILTER_BROADCAST_INTERVAL = 10min`.
- Early re-broadcast if mempool min-fee crosses a `MAX_FEEFILTER_CHANGE_DELAY = 5min`
  significant-change boundary (Δ > 33% or > 25%).

rustoshi `peer_manager.rs::send_initial_feefilter` (line 2223-2227):

```rust
pub async fn send_initial_feefilter(&mut self, peer_id: PeerId) {
    let fee_rate: u64 = 100_000;
    let _ = self.send_to_peer(peer_id, NetworkMessage::FeeFilter(fee_rate)).await;
}
```

Sends once on `PeerEvent::Connected` (line 1998) and never again.
The fee rate is a hardcoded 100k sat/kvB (~100 sat/vB), which is
neither the IBD signal `MAX_MONEY` nor the post-IBD mempool min-fee.

`FeeFilterManager::get_pending_feefilters` (relay.rs:421-442) does
the right thing per-peer with Poisson scheduling, but
`FeeFilterManager` is part of BUG-4 (entirely dead).

**File:** `crates/network/src/peer_manager.rs:1998, 2223-2227`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::MaybeSendMessage`
(feefilter rebroadcast loop using
`AVG_FEEFILTER_BROADCAST_INTERVAL`).

**Impact:** static feefilter prevents peers from up- or down-rating
us as mempool min-fee changes; bandwidth waste from receiving
sub-feefilter txs.

---

## BUG-18 (P1) — Feefilter value is a hardcoded 100k sat/kvB, not IBD-aware and not privacy-quantised

**Severity:** P1. Core uses:
- During IBD: `feefilter = MAX_MONEY` (signal "don't send me txs").
- Post-IBD: `feefilter = FeeFilterRounder::round(mempool.GetMinFee())`
  — quantised to one of ~150 geometric-spacing buckets at 1.1× ratio
  for privacy (`FEE_FILTER_SPACING = 1.1`).

rustoshi sends a flat 100_000 sat/kvB. This:
- Doesn't signal IBD ("send me everything") even when we're 200k
  blocks behind tip.
- Doesn't shrink toward the actual mempool min-fee (currently
  ~1000 sat/kvB on mainnet) when we're caught up.
- Doesn't quantise — leaks no information today (constant), but if
  a future fix made it dynamic, the unquantised value would
  fingerprint the node.

`FeeFilterRounder::round()` exists in `relay.rs:121-140` with
correct geometric quantisation; unused (BUG-4).

**File:** `crates/network/src/peer_manager.rs:2225`.

**Core ref:** `bitcoin-core/src/policy/fees.cpp::FeeFilterRounder`;
`bitcoin-core/src/net_processing.cpp` IBD-vs-post-IBD branch on
`feefilter = m_ignore_incoming_txs ? MAX_MONEY : rounded_minfee`.

**Impact:** suboptimal bandwidth use (100 sat/vB threshold rejects
most legitimate testnet/signet txs); future-dynamic feefilter
would leak mempool state.

---

## BUG-19 (P1) — No UNREQUESTED tx misbehavior penalty

**Severity:** P1 ("W103 G28 carry-forward"). Core penalises peers
that send a `tx` message without first announcing it via `inv` and
receiving a `getdata`. The penalty is 20 points (a peer at 100 pts
is disconnected and banned).

rustoshi's `NetworkMessage::Tx` arm (main.rs:3098-3246) immediately
runs ATMP on any received tx, with no check that we previously
requested it. The peer-manager records `last_tx_time` (line 2030-2033)
but no expected-tx set is maintained.

An attacker can therefore force unlimited ATMP CPU work by sending
unsolicited txs.

**File:** `rustoshi/src/main.rs:3098-3246`; no production
expected-tx set.

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp::ReceivedTx`
(returns `should_validate=false` + adds to `m_orphan_resolution_tracker`
if unrequested; misbehavior on repeat).

**Impact:** ATMP DoS via unsolicited tx floods.

---

## BUG-20 (P1) — Post-handshake `WtxidRelay` is silently ignored, not misbehavior

**Severity:** P1. BIP-339: WTXIDRELAY must be sent ONLY between
VERSION and VERACK. A peer that sends it after VERACK violates the
BIP and should be penalised (Core: misbehavior penalty + ignored).

rustoshi's pre-handshake loop (peer_manager.rs:3186-3191) handles
"wtxidrelay" by `continue`-ing (and doing nothing with the value —
BUG-3 cross-cite). The post-handshake `handle_event` (line 1942+)
has no arm for `NetworkMessage::WtxidRelay`; the parsed message is
dropped after `last_recv` is updated (line 2020). No misbehavior
applied, no warning logged.

**File:** `crates/network/src/peer_manager.rs:1942-2160, 3186-3191`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3938-3950` —
"wtxidrelay disallowed after verack" misbehavior.

**Impact:** protocol-confusion / fingerprinting vector; sloppy peers
that send wtxidrelay late are not penalised.

---

## BUG-21 (P1) — `erase_for_block` walks the entire orphanage; no `OrphanByParent` index

**Severity:** P1. Bitcoin Core's `TxOrphanage::EraseForBlock` uses
the `OrphanByParent: std::map<COutPoint, ...>` index for O(per-spent-output)
cost. rustoshi's `erase_for_block` (`orphanage.rs:312-337`) does:

```rust
let mut to_remove = Vec::new();
for (wtxid, entry) in &self.by_wtxid {        // O(N) scan
    let txid = entry.tx.txid();
    if included_txids.contains(&txid) { ... }
    if entry.tx.inputs.iter()
        .any(|i| spent_set.contains(&i.previous_output)) { ... }
}
```

O(N) over the orphanage on every block connect. With N = 100 (current
cap) this is fine; with the future weight-based cap (Core trended
toward ~10_000) it would be a noticeable per-block cost.

`txid_to_wtxids` secondary index exists (`orphanage.rs:135`) for
`find_children` parent-arrival lookup; no symmetric outpoint index
for block-arrival sweep.

**File:** `crates/consensus/src/orphanage.rs:135, 312-337`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForBlock`
(uses `OrphanByParent` for O(per-output) lookup).

**Impact:** scaling cliff if orphanage cap is ever increased above
~1000. Cosmetic at N=100.

---

## BUG-22 (P0) — Three-pipeline broadcast drift across four call sites with cut-and-paste InvVector construction

**Severity:** P0 ("three-pipeline drift" — extended to four-pipeline
in rustoshi; first four-pipeline finding tracked). Four distinct
production call sites broadcast a tx inv with hand-rolled
`InvVector { inv_type, hash }` construction, all four with the same
two bugs (wrong wire type per BUG-1, no per-peer wtxid-relay branch
per BUG-3, no fRelay gate per BUG-2), all four bypassing the
`relay.rs::build_tx_inv_entry` helper that was added in W103 to fix
exactly this:

| Site | File:line | Pipeline name |
|------|-----------|---------------|
| 1 | `crates/rpc/src/server.rs:3741-3754` | sendrawtransaction RPC |
| 2 | `crates/rpc/src/server.rs:5383-5398` | submitpackage RPC |
| 3 | `rustoshi/src/main.rs:3192-3211` | P2P Tx → relay |
| 4 | `rustoshi/src/main.rs:3779-3789` | MEMPOOL message reply |

All four hand-write `InvVector { inv_type: InvType::MsgWitnessTx, hash: wtxid }`.
Each fix would require touching all four sites; the existing
`build_tx_inv_entry(peer_supports_wtxid, txid, wtxid)` helper would
collapse them to one call apiece.

**File:** see four sites above; helper at `crates/network/src/relay.rs:829-835`.

**Impact:** every future tx-relay site that gets added has to
re-discover the right pattern; drift on the next change is
near-certain. "Three-pipeline drift" pattern (the W142 rustoshi
three-merkle, W143 ouroboros three-consensus-pipeline, W145 clearbit
three-CheckTxInputs) extended to four pipelines on the same flag
within a single impl.

---

## BUG-23 (P1) — `recently_rejected.clear()` on every block-connect, not Core's bounded retention

**Severity:** P1 (W103 G29 cross-reference / fleet pattern). After
every block-connect (`main.rs:3013`), `recently_rejected` is
completely cleared. Core's `m_recent_rejects` is NOT cleared on
block-connect; it persists across blocks with rolling-bloom-filter
eviction. Only `m_recent_rejects_reconsiderable` is reset per-block
(for orphan-after-reorg reconsideration).

The aggressive clear means a tx rejected in block N (e.g., for
insufficient fee) can be re-announced and re-validated in block N+1,
even though the mempool min-fee has only moved up since the block.
CPU amplification under sustained spam where rejected txs return
every block.

**File:** `rustoshi/src/main.rs:3013`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`m_recent_rejects.reset()` only on rolling-window timeout, not
per-block.

**Impact:** CPU amplification on sustained re-announce attacks;
roughly 1 ATMP-cycle per rejected tx per block where Core has
~0 ATMP cycles for the same tx for the entire bloom-filter window.

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-CDIV:** 5 (BUG-1, BUG-2, BUG-5, BUG-6, BUG-9 [moved to P1
  — see recount])
- **P0-SEC:** 2 (BUG-3, BUG-14)
- **P0-DEAD:** 1 (BUG-4)
- **P0:** 1 (BUG-22)
- **P1:** 14 (BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12, BUG-13,
  BUG-15, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21, BUG-23)

Recount: P0-CDIV 4 (BUG-1, BUG-2, BUG-5, BUG-6) + P0-SEC 2 (BUG-3,
BUG-14) + P0-DEAD 1 (BUG-4) + P0 1 (BUG-22) + P1 15 (BUG-7, BUG-8,
BUG-9, BUG-10, BUG-11, BUG-12, BUG-13, BUG-15, BUG-16, BUG-17,
BUG-18, BUG-19, BUG-20, BUG-21, BUG-23) = 4 + 2 + 1 + 1 + 15 = 23. ✓

**P0-class total: 8 of 23 (35%).**

**Fleet patterns confirmed:**

- **"Dead-anti-DoS / dead-subsystem"** (BUG-4) — `InventoryTrickle` +
  `FeeFilterManager` + `PeerRelayState` are fully implemented and
  tested but have zero production callers. **Third rustoshi
  instance** of the W148 `HeadersPresyncState` pattern (after
  W148-W150 PackageManager). The 800-LOC relay.rs is dwarfed by the
  fact that no caller wires it in.
- **"Three-pipeline drift extended to four"** (BUG-22) — first
  rustoshi four-pipeline drift on the same flag; extends the W142
  three-merkle / W143 three-consensus / W145 three-CheckTxInputs
  series.
- **"Wiring-look-but-no-wire"** (BUG-1, BUG-8, BUG-11, BUG-22) —
  `build_tx_inv_entry`, `batch_getdata_items`, `expire_orphans`, and
  `InventoryTrickle` were all explicitly added by prior fix waves to
  close documented gaps, then **never wired to call sites**. Four
  helpers, zero production consumers.
- **"Comment-as-confession"** (BUG-1: "Use WitnessTx type since we
  support SegWit", server.rs:3742 — admits the wire-value choice
  was made without consulting Core's MSG_WTX vs MSG_WITNESS_TX
  distinction) — **first server.rs instance, ~8th rustoshi
  fleet-wide instance**.
- **"Two-pipeline guard 17th extension"** (BUG-3) — three of four
  handshake paths drift on `supports_wtxid_relay`; first
  3-of-4-paths drift on the same flag inside one impl.
- **"Carry-forward re-anchor"** — BUG-3 (W99 G21 / W103 G3), BUG-7
  (W103 G9-G15), BUG-8 (W103 G5 wired-but-helper-unused),
  BUG-11 (W103 G22 FIXED-but-uncalled), BUG-13 (W103 G25),
  BUG-14 (W150 BUG-2 verify_scripts), BUG-19 (W103 G28),
  BUG-23 (W103 G29) — **8 of 23 bugs are carry-forwards** from
  prior waves with no progress (some 6+ weeks open). Highest
  carry-forward density of any rustoshi wave to date.
- **"Hash-key/wire-key mismatch"** (BUG-5, BUG-16, BUG-1) — three
  distinct sites where rustoshi's data structures are keyed by txid
  while the BIP-339 wire format delivers wtxids: mempool.get
  (BUG-5), recently_rejected (BUG-16), and the broadcast hash
  (BUG-1) all assume txid-keying.
- **"Single-path-of-N is correct"** (BUG-12) — `erase_for_block`
  wired on one block-arrival path of three (P2P, reorg, AssumeUTXO);
  W148 BUG-12 same shape.

**Top three findings:**

1. **BUG-1 + BUG-22 cluster (P0-CDIV + P0) — Tx broadcast wire
   format wrong at every production site.** Four production
   broadcast pipelines all emit `MsgWitnessTx (0x40000001)` — a
   BIP-144 getdata flag — instead of `MsgWtx (5)` (BIP-339 inv
   value). Core peers silently drop these invs, making rustoshi a
   **sink-only** node for tx relay: it can accept inbound txs but
   cannot forward them to BIP-339 peers (most of the network as of
   2024+). The `build_tx_inv_entry` helper exists to do this
   correctly but is unused. Cross-cuts BUG-3 (per-peer wtxid-relay
   branch missing) and BUG-2 (BIP-37 fRelay gate missing).
2. **BUG-4 (P0-DEAD) — Entire `InventoryTrickle` + `FeeFilterManager`
   + `PeerRelayState` subsystem is dead production code.** 800 LOC
   of correct, tested anti-DoS / privacy / scheduling machinery,
   referenced only by tests. Production tx-relay is cut-and-paste
   immediate fan-out via `peer_manager.broadcast()` with zero
   Poisson jitter, zero per-peer cadence, zero rate limiting, zero
   `recently_announced_invs` LRU, zero `m_relay_to_set`. Third
   rustoshi instance of the W148 dead-subsystem pattern;
   compounds BUG-1, BUG-2, BUG-3 by being the would-be home of
   their fixes.
3. **BUG-14 (P0-SEC) — Orphan promotion inherits `verify_scripts: false`.**
   When an orphan's parent arrives, the orphan is retried through
   ATMP using the same `MempoolConfig::default()` that has
   `verify_scripts: false` (W150 BUG-2). Result: an attacker can
   flood the orphanage with invalid-signature orphans whose parent
   will later legitimately arrive, and ALL of them will be silently
   admitted to the mempool when the parent lands. Compounds W150
   BUG-2 rather than introducing a new root cause, but adds a fresh
   attack vector that depends on the orphan promote pipeline being
   wired (which it is — main.rs:3145-3187).
