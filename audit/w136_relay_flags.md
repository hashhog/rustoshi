# W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit (rustoshi)

**Wave:** W136 — three small relay-protocol BIPs bundled
(BIP-130 sendheaders / BIP-133 feefilter / BIP-339 wtxidrelay) (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:**
- `crates/network/src/peer.rs` —
  - `PeerInfo` struct (lines 281-318) — `supports_sendheaders`,
    `supports_wtxid_relay`, `feefilter` fields.
  - `run_outbound_peer` v1 tail (lines 970-1030) — post-handshake
    sendheaders / sendcmpct send.
  - `run_outbound_peer_with_stats` v1 tail (lines 1170-1259) — same.
  - `perform_handshake` / `perform_handshake_tracked` (lines 2127-2229) —
    v1 wtxidrelay-before-verack handshake; receive loop tracks
    `wants_wtxid_relay` / `wants_addrv2` correctly.
  - `perform_v2_handshake_outbound` / `_inbound` (lines 1635-1839) —
    BIP-324 application-layer handshake; tracks both flags.
- `crates/network/src/peer_manager.rs` —
  - `handle_event` PeerEvent::Connected (lines 1985-2000) —
    `send_initial_feefilter` invocation gating on `info.relay`.
  - `handle_event` PeerEvent::Message FeeFilter arm (lines 2076-2091) —
    rejects out-of-range with `Misbehaving`; stores `peer.info.feefilter`.
  - `handle_event` PeerEvent::Message SendHeaders arm
    (lines 2152-2160) — sets `peer.info.supports_sendheaders = true`.
  - `announce_block` (lines 1724-1760) — BIP-130 branch:
    headers-vs-inv per-peer; tests it in-file at line 5039;
    not called from chain-advance path.
  - `send_initial_feefilter` (lines 2220-2227) — hardcoded 100_000
    sat/kvB; no FEEFILTER_VERSION gate; no block-relay-only gate.
  - `run_inbound_peer` v1 handshake loop (lines 3094-3270) —
    sees `wtxidrelay` at line 3186 but only `continue`s without
    tracking; PeerInfo constructed with `supports_wtxid_relay: false`
    at line 3237 regardless.
  - `run_inbound_v2_peer` post-cipher app handshake
    (lines 3601-3627) — uses `perform_v2_handshake_inbound` output;
    `supports_wtxid_relay: app_hs.wants_wtxid_relay` set correctly.
- `crates/network/src/relay.rs` — entire BIP-133 / inventory-trickle
  helper module:
  - `FeeFilterRounder` (lines 87-152) — 1.1x geometric privacy quantizer.
  - `FeeFilterState` (lines 155-267) — per-peer feefilter state,
    `should_relay`, `maybe_send_feefilter`.
  - `FeeFilterManager` (lines 349-484) — multi-peer wrapper.
  - `PeerRelayState` (lines 489-616) — per-peer inv queue,
    wtxid-relay branch at line 589-593 produces `InvType::MsgWtx`.
  - `InventoryTrickle` (lines 618-789) — multi-peer trickle scheduler.
  - **`FeeFilterManager` and `InventoryTrickle` are NEVER WIRED**
    into `PeerManager` — used only by their own unit tests and by
    `w103_tx_relay_tests.rs`. See BUG-1.
- `crates/network/src/message.rs` —
  - `NetworkMessage::FeeFilter(u64)` / `SendHeaders` / `WtxidRelay`
    variants (lines 209-223).
  - Wire encode (lines 786-804) / decode (lines 1045-1065).
  - `SENDHEADERS_VERSION = 70012`, `FEEFILTER_VERSION = 70013`,
    `WTXID_RELAY_VERSION = 70016` (lines 289-293).
  - `InvType::MsgTx = 1`, `MsgWtx = 5`, `MsgWitnessTx = 0x40000001`
    (lines 79-89).
- `rustoshi/src/main.rs` —
  - BIP-35 mempool-response inv-type branch at lines 3779-3789 —
    uses `InvType::MsgWitnessTx` for wtxid-relay peers (wrong;
    should be `MsgWtx`). See BUG-9.
  - Chain-advance path at lines 2900+ — no `announce_block` call
    after `process_block` succeeds for P2P-received blocks.
    See BUG-11.

**Reference:**
- `bitcoin-core/src/net_processing.cpp:3896-3939` — SENDHEADERS /
  WTXIDRELAY / SENDADDRV2 arm handlers; the WTXIDRELAY-after-verack
  disconnect at 3922-3925 (`pfrom.fDisconnect = true`).
- `bitcoin-core/src/net_processing.cpp:5035-5045` — FEEFILTER arm;
  Core silently ignores out-of-range via `MoneyRange(...)` check —
  no misbehavior.
- `bitcoin-core/src/net_processing.cpp:5519-5538` —
  `MaybeSendSendHeaders`; gated on
  `state.pindexBestKnownBlock->nChainWork > MinimumChainWork()`
  (i.e. headers-sync-complete).
- `bitcoin-core/src/net_processing.cpp:5540-5580` —
  `MaybeSendFeefilter`; gates `ignore_incoming_txs`, FEEFILTER_VERSION
  floor, `ForceRelay` permission, `IsBlockOnlyConn`; uses
  `FeeFilterRounder` quantization; 10-min Poisson cadence with
  5-min MAX_FEEFILTER_CHANGE_DELAY snap-forward.
- `bitcoin-core/src/net_processing.cpp:5995-6080` — outbound tx INV
  trickle loop; `peer.m_wtxid_relay ? CInv{MSG_WTX, wtxid}
  : CInv{MSG_TX, txid}`; per-tx `filterrate.GetFee(vsize)` gate.
- `bitcoin-core/src/net_processing.cpp:283-321` — `Peer` struct
  feefilter / wtxid-relay state fields (`m_wtxid_relay`,
  `m_fee_filter_sent`, `m_next_send_feefilter`,
  `m_fee_filter_received`, `m_prefers_headers`, `m_sent_sendheaders`).
- `bitcoin-core/src/policy/feerate.h` — `CFeeRate::GetFee(size)` =
  `ceil(nSatoshisPerK * size / 1000)` (the exact filterrate predicate).
- `bitcoin-core/src/node/protocol_version.h` — version-number floors.
- `bitcoin-core/src/consensus/amount.h:26-27` — `MAX_MONEY = 21M*1e8`,
  `MoneyRange(n) := n >= 0 && n <= MAX_MONEY`.
- BIPs **130** (sendheaders, 2015), **133** (feefilter, 2015),
  **339** (wtxidrelay, 2020).

**Excludes:**
- BIP-152 compact-block-relay sendcmpct / cmpctblock (covered by W126).
- BIP-37 bloom filter / filtering (orthogonal; the FEEFILTER message
  type and FEEFILTER_VERSION proto-floor are in scope, but the bloom
  pipeline that interacts with the trickle loop is W103).
- BIP-155 sendaddrv2 (covered by W117).
- BIP-330 sendtxrcncl / Erlay reconciliation (separate wave;
  rustoshi `erlay.rs` is unwired anyway).
- The OP_CSV / nSequence consensus path (orthogonal to relay).

**Production code changes:** 0 (pure audit).
**Test file:** `crates/network/tests/test_w136_relay_flags.rs`
— 30 gates, 11 PASS regression pins + 19 `#[ignore]`-pinned `BUG-N` stubs.

## Why this matters

BIP-130, BIP-133, BIP-339 are the three pillars of modern Bitcoin
transaction and block **announcement**. They do not change consensus,
but they change every bit a fully-synced node emits to its peers
after the initial-block-download finishes. The cost of getting any
of them wrong is a 24/7 background of:

- **BIP-130 (sendheaders)** — bandwidth waste: every connected block
  costs ~80 B (header) instead of ~36 B (inv-tip-and-getheaders
  round-trip). Worse, a peer that opts in via `sendheaders` and is
  then served `inv(MSG_BLOCK)` cannot directly fetch the header
  via the inv-based getheaders dance and may stall at the tip.
  Most concerning: a node that **sends `sendheaders`** to its peer
  but does not **honor** incoming `sendheaders` will starve those
  peers, accelerating their chance of evicting us.

- **BIP-133 (feefilter)** — bandwidth waste plus reputation damage:
  a node that announces zero feefilter (or never sends one) receives
  every low-fee tx the peer hears about, only to drop it on
  acceptance. Worse, a node that ignores **received** feefilters
  trickles its own low-fee mempool entries to peers that already
  said "don't bother me with this," wasting their bandwidth and
  getting tagged as a misbehaving relay. Worst: an over-strict
  validator that **misbehaves** the peer for an out-of-range value
  bans peers that Core would silently tolerate (cross-impl interop
  bug — BUG-7).

- **BIP-339 (wtxidrelay)** — duplicate-tx-relay storm: pre-BIP-339
  peers gossip txid-keyed inventories, but witness-malleated copies
  of the same tx (same txid, different wtxid) are deduplicated only
  by the receiver. BIP-339 fixes this by gossiping wtxids. A node
  that signals support via `wtxidrelay` but then announces tx-INVs
  with `MSG_TX` (1) or `MSG_WITNESS_TX` (0x40000001) breaks the
  contract — the peer's wtxid-keyed `m_tx_inventory_known_filter`
  never matches, so the peer floods us with duplicate inventories.
  Symmetrically, a node that **receives** `wtxidrelay` but stores
  `supports_wtxid_relay = false` (BUG-3 — inbound v1 path)
  announces its own mempool with `MSG_TX` to a peer that ignores
  `MSG_TX` and waits for `MSG_WTX`, so our outbound tx-relay is
  silent. Both directions are silent failure modes that look
  identical from the operator console.

The wtxidrelay-before-verack ordering is also a known
**handshake-state-machine bug class**: BIP-339 says wtxidrelay
**must** be sent (and received) between VERSION and VERACK, and
peers **must** disconnect on a wtxidrelay arriving after VERACK.
A node that allows wtxidrelay-after-verack accepts mid-session
opt-in (which Core does not — net_processing.cpp:3922-3925
`pfrom.fDisconnect = true`), introducing an interop divergence
that an adversary can detect via active probing.

## Audit gate matrix (30 gates)

### BIP-130 sendheaders (G1-G10)

| #   | Gate                                                       | Verdict | Bug    |
|-----|------------------------------------------------------------|---------|--------|
| G1  | NetworkMessage::SendHeaders variant + wire codec           | PRESENT | —      |
| G2  | SENDHEADERS_VERSION = 70012 constant                       | PRESENT | —      |
| G3  | `supports_sendheaders` field on PeerInfo                   | PRESENT | —      |
| G4  | SendHeaders received from peer flips flag                  | PRESENT | —      |
| G5  | `announce_block` branches headers vs inv per-peer          | PRESENT | —      |
| G6  | `announce_block` called from chain-advance path            | MISSING | BUG-11 |
| G7  | MaybeSendSendHeaders MinimumChainWork gate                 | MISSING | BUG-12 |
| G8  | MaybeSendSendHeaders one-shot (`m_sent_sendheaders` idem)  | PARTIAL | BUG-13 |
| G9  | MAX_BLOCKS_TO_ANNOUNCE = 8 cap                             | MISSING | BUG-14 |
| G10 | Headers-vs-INV revert-to-inv on multi-block / reorg        | MISSING | BUG-15 |

### BIP-133 feefilter (G11-G20)

| #   | Gate                                                       | Verdict | Bug    |
|-----|------------------------------------------------------------|---------|--------|
| G11 | NetworkMessage::FeeFilter(u64) variant + wire codec        | PRESENT | —      |
| G12 | FEEFILTER_VERSION = 70013 constant                         | PRESENT | —      |
| G13 | FeeFilterRounder (1.1x geometric) helper                   | PARTIAL | BUG-1  |
| G14 | FeeFilterManager / FeeFilterState wired into PeerManager   | MISSING | BUG-1  |
| G15 | Periodic feefilter broadcast (10-min Poisson)              | MISSING | BUG-4  |
| G16 | MAX_FEEFILTER_CHANGE_DELAY (5-min) snap-forward            | MISSING | BUG-5  |
| G17 | `MaybeSendFeefilter` FEEFILTER_VERSION + IsBlockOnly gate  | MISSING | BUG-6  |
| G18 | Out-of-range MoneyRange ignored silently (no misbehavior)  | PARTIAL | BUG-7  |
| G19 | Outbound tx-INV filterrate.GetFee(vsize) gate              | MISSING | BUG-8  |
| G20 | feefilter sent during IBD = MAX_MONEY (advertise "no txs") | MISSING | BUG-2  |

### BIP-339 wtxidrelay (G21-G30)

| #   | Gate                                                       | Verdict | Bug    |
|-----|------------------------------------------------------------|---------|--------|
| G21 | NetworkMessage::WtxidRelay variant + wire codec            | PRESENT | —      |
| G22 | WTXID_RELAY_VERSION = 70016 constant                       | PRESENT | —      |
| G23 | `supports_wtxid_relay` on PeerInfo                         | PRESENT | —      |
| G24 | wtxidrelay sent BEFORE verack (BIP-339 ordering)           | PRESENT | —      |
| G25 | wtxidrelay-after-verack triggers disconnect (Core 3922-3925)| MISSING | BUG-16 |
| G26 | v1 INBOUND `wtxidrelay` flips `supports_wtxid_relay`       | MISSING | BUG-3  |
| G27 | Outbound tx-INV uses MsgWtx(5) for wtxid-relay peers       | PARTIAL | BUG-9  |
| G28 | BIP-35 mempool-response uses MsgWtx for wtxid-relay peers  | MISSING | BUG-9  |
| G29 | Duplicate wtxidrelay before verack is tolerated (idempotent)| PARTIAL | BUG-17 |
| G30 | wtxidrelay gated on common_version >= WTXID_RELAY_VERSION  | PRESENT | —      |

**Verdict tallies**: **PRESENT 11 / PARTIAL 5 / MISSING 14**

## Headline findings

**17 bugs catalogued, split by severity:**
**4 P0 / 8 P1 / 4 P2 / 1 P3.** No P0-CDIV (these are relay-layer
bugs, not consensus — they cost bandwidth, interop, and mempool
freshness, not chain integrity).

### P0 — silent-failure-mode bugs that break the BIP contract

- **BUG-1 (P0)** — **The well-engineered `FeeFilterManager` /
  `FeeFilterRounder` / `FeeFilterState` / `InventoryTrickle`
  helpers in `crates/network/src/relay.rs` (lines 87-789) are
  NEVER WIRED into `PeerManager`.** A grep of
  `FeeFilterManager|FeeFilterRounder|FeeFilterState|InventoryTrickle`
  across all non-test rustoshi source returns **zero** matches
  outside `relay.rs` itself. The helpers are referenced only by
  their own in-file unit tests and by
  `crates/network/src/w103_tx_relay_tests.rs` (which tests the
  helpers in isolation, not their integration). `PeerManager`
  uses a single `peer.info.feefilter: u64` field (peer.rs:317)
  stamped from received `FeeFilter` messages (peer_manager.rs:2089)
  — but **nothing reads this field**: no outbound tx-INV path
  consults it (BUG-8), and no periodic broadcast scheduler exists
  (BUG-4). The 700+ lines of helper code in `relay.rs` are dead
  code. **Pattern: well-engineered-helper-never-wired** — this is
  the exact same finding signature as W120 BUG-2 (`validateRbfDiagram`
  unwired in nimrod, fixed by FIX-79) and W121 BUG-3 (ouroboros
  BIP-157 P2P stop-hash). Subsumes BUG-2 through BUG-8 below as
  symptoms.

- **BUG-2 (P0)** — **No feefilter advertised during IBD.** Core
  (net_processing.cpp:5552-5556) sends `MAX_MONEY` as feefilter
  during IBD to tell peers "do not relay any tx to us, we're
  syncing." rustoshi sends a hardcoded `100_000` sat/kvB
  (`send_initial_feefilter` at peer_manager.rs:2225) regardless
  of IBD state, **only once per peer at handshake-complete**.
  During an IBD that lasts ~2 days (testnet4 / mainnet on fresh
  hardware), the node receives tx-INVs at low-fee bands from every
  peer's full mempool — every one of which is discarded because
  the node has no usable mempool yet. Order-of-magnitude bandwidth
  waste at exactly the worst time (network-limited IBD). Pattern:
  comment-as-confession — the comment at peer_manager.rs:2221-2222
  says "Without mempool, we set a high fee rate (100 sat/vbyte =
  100000 sat/kvB) to discourage transaction relay" — but 100 sat/vB
  is **not** prohibitive; mempool min during congestion routinely
  exceeds 200 sat/vB. Core uses MAX_MONEY = 2.1×10^15 specifically
  because the actual ceiling matters.

- **BUG-3 (P0)** — **v1 inbound handshake silently drops
  `wtxidrelay` flag.** In `run_inbound_peer` (peer_manager.rs:3094-3270),
  the pre-verack message loop catches `wtxidrelay`/`sendaddrv2`/
  `sendtxrcncl` at line 3186 with a catch-all `continue`, **without
  setting a `wants_wtxid_relay` flag**. (Note: `wants_addrv2`
  IS set for `sendaddrv2` via the inner `if cmd == "sendaddrv2"`
  branch at line 3187-3189; the wtxidrelay path has no analogous
  set.) When the PeerInfo is constructed at line 3219-3240 after
  verack, `supports_wtxid_relay: false` is hardcoded (line 3237).
  **Every v1 inbound peer that signals BIP-339 is treated as
  non-wtxid-relay.** Our outbound tx-INVs to that peer use
  `InvType::MsgTx` (1) and txid, which the peer's `m_wtxid_relay`
  side ignores. The v2 inbound path (`run_inbound_v2_peer` at
  line 3601-3627) gets this right via
  `app_hs.wants_wtxid_relay`. The v1 outbound path
  (`perform_handshake_tracked` at peer.rs:2186-2222) gets it right
  via the receive loop's `WtxidRelay => wants_wtxid_relay = true`
  arm. **Only v1 inbound is broken.** Since v1 is the dominant
  inbound traffic for any node (v2 BIP-324 deployment is still
  fractional), this hits the majority of inbound peers.

- **BUG-4 (P0)** — **No periodic feefilter broadcast.** Core's
  `MaybeSendFeefilter` (net_processing.cpp:5540-5580) is invoked
  every `SendMessages` tick (the per-peer outbound-message loop)
  and re-broadcasts the rounded current mempool minfee on a
  10-minute Poisson cadence (`AVG_FEEFILTER_BROADCAST_INTERVAL`).
  rustoshi has exactly one `send_initial_feefilter` call
  (peer_manager.rs:1998) per connection, ever. After the
  handshake-time send, no further feefilter messages are emitted.
  A node that joins the network during a low-fee window
  (10 sat/vB) and later sees the mempool minfee rise to
  200 sat/vB during congestion never re-broadcasts — peers continue
  to send us txs at 10 sat/vB indefinitely, which we drop on
  ATMP. Symmetrically, a node that joins during a high-fee window
  never lowers its filter when the mempool clears, so peers
  silently discard low-fee txs they should be relaying to us.

### P1 — interop divergences / efficiency bugs

- **BUG-5 (P1)** — **No `MAX_FEEFILTER_CHANGE_DELAY` (5-min)
  snap-forward.** Core (net_processing.cpp:5574-5579) detects when
  the current filter has changed substantially since the last sent
  value (delta > 33% in either direction) and reschedules the
  pending broadcast to within 5 minutes. Without this, a sudden
  mempool-fee spike during a congestion event takes up to 10
  minutes (the Poisson average) to propagate — long enough for
  peers to waste megabytes of bandwidth on now-stale low-fee
  inventories. The `FeeFilterState::maybe_send_feefilter`
  helper in `relay.rs:255-262` actually implements this logic
  correctly — but it is unwired (BUG-1).

- **BUG-6 (P1)** — **`send_initial_feefilter` skips Core's gates.**
  Core's `MaybeSendFeefilter` (net_processing.cpp:5542-5548)
  short-circuits on: (a) `m_opts.ignore_incoming_txs` (we don't
  want txs at all), (b) `pto.GetCommonVersion() < FEEFILTER_VERSION`
  (peer doesn't understand the message), (c) `ForceRelay`
  permission (we promised this peer we'd relay everything),
  (d) `IsBlockOnlyConn()` (block-relay-only peers don't relay txs).
  rustoshi's `send_initial_feefilter` (peer_manager.rs:2223-2227)
  gates only on `info.relay` (BIP-37 fRelay flag) at the call site
  (line 1997). The block-relay-only check uses `ConnectionType`,
  not `info.relay`. Result: rustoshi sends a `feefilter` message
  to peers with protocol version < 70013 (those peers should
  treat it as an unknown message-type and either log or
  misbehavior-flag us, depending on impl), and to block-relay-only
  outbound peers (we won't relay txs to them anyway, but the
  message is wire-noise).

- **BUG-7 (P1)** — **Out-of-range feefilter triggers `Misbehaving`
  in violation of BIP-133 / Core.** Core net_processing.cpp:5035-5044
  silently ignores values outside `MoneyRange` (no log, no
  misbehavior, no disconnect — just don't store the value). The
  rustoshi handler at peer_manager.rs:2076-2091 sets
  `MisbehaviorReason::ProtocolViolation("feefilter out of range")`
  with the in-source comment "Core marks the peer as misbehaving"
  — **factually wrong**; Core does not. Pattern:
  **comment-as-confession** — the divergence is documented in
  prose and merged anyway, with a confident-but-wrong claim about
  Core's behavior. A rustoshi node will misbehavior-score (and
  eventually ban) a Core peer that sends a malformed feefilter
  due to clock-skew or rollback, in a scenario where Core would
  just ignore it. Cross-impl interop bug.

- **BUG-8 (P1)** — **No outbound tx-INV feefilter gate.** Core
  (net_processing.cpp:6036, 6071) gates **every single outbound
  tx-INV** on `txinfo.fee < filterrate.GetFee(txinfo.vsize)`
  where `filterrate = CFeeRate(tx_relay->m_fee_filter_received)`.
  rustoshi has no outbound tx-INV path that consults
  `peer.info.feefilter`. The BIP-35 mempool-response path
  (`main.rs:3779-3789`) inv'es **every** mempool tx without
  consulting the peer's filter. The `FeeFilterState::should_relay`
  (relay.rs:204-206) implements the predicate correctly but is
  unwired (BUG-1). Result: rustoshi sends low-fee txs to peers
  that explicitly told us not to bother — the canonical "ignore
  the contract" failure mode.

- **BUG-9 (P1)** — **Outbound tx-INV uses wrong inv-type for
  wtxid-relay peers.** Per Core net_processing.cpp:6007-6009,
  `peer.m_wtxid_relay` selects `CInv{MSG_WTX, wtxid.ToUint256()}`
  (MSG_WTX = 5) for wtxid-relay peers, else `CInv{MSG_TX, txid}`
  (MSG_TX = 1) for legacy peers. **MSG_WITNESS_TX (0x40000001) is
  never used in outbound INVs** — it is only valid in a *getdata*
  message to request the witness-bearing tx data. rustoshi's
  BIP-35 mempool-response inv-type branch at main.rs:3779-3789
  uses `InvType::MsgWitnessTx` for wtxid-relay peers — wrong.
  The (unwired) `PeerRelayState::get_pending_inv` in relay.rs:589-593
  does this correctly. **A wtxid-relay peer's
  `m_tx_inventory_known_filter` is keyed by wtxid; an inv with
  MsgWitnessTx hash=txid never deduplicates against it**, so the
  peer may issue duplicate getdata's for the same tx. Worse, the
  peer may treat MsgWitnessTx in an inv as a protocol violation
  (depending on impl) and disconnect/misbehavior us.

- **BUG-10 (P1)** — **Outbound block INV uses wrong logic for
  wtxid-relay-vs-witness distinction in announce_block.**
  `PeerManager::announce_block` (peer_manager.rs:1733-1760)
  selects `MsgWitnessBlock` vs `MsgBlock` based on
  `peer.info.supports_witness` (the NODE_WITNESS service flag).
  This is correct for blocks (BIP-144). But the comment on the
  function and adjacent dead code (e.g., the announce-block test
  at line 5039) tacitly assumes the witness flag governs all
  witness/wtxid behavior — it does not. **`supports_witness`
  (NODE_WITNESS) and `supports_wtxid_relay` (BIP-339) are
  distinct** and reach distinct subsystems (block-relay vs
  tx-relay). A node that defaults `supports_wtxid_relay` from
  the witness flag would still fail BIP-339 — they are not
  semantically substitutable. (rustoshi does **not** make this
  conflation in code, but the file's documentation suggests the
  reviewer should double-check the post-IBD outbound tx path,
  which doesn't exist yet — so the conflation has not been
  introduced. Marking P1 as a forward-warning gate so any fix to
  BUG-9 doesn't accidentally make this confusion.)

- **BUG-11 (P1)** — **`announce_block` is never called from the
  P2P chain-advance path.** A grep for `announce_block` across
  `rustoshi/src/main.rs` returns **zero** hits. The only
  production caller is `crates/rpc/src/server.rs:9624` from the
  `generateblock` RPC. Every block we receive from peers via P2P
  (main.rs:2874 `process_block` success path → undo applied →
  best_block updated at line 2963) is **silently** added to our
  chain without any block-announcement to other connected peers.
  Pattern: **engineered-helper-with-unwired-call-site**. Core's
  PeerManagerImpl::BlockConnected hook fires on every connect-tip
  event; rustoshi has the equivalent helper but no equivalent
  hook. Result: rustoshi is a **black hole** for blocks — it
  accepts but never re-announces, even though all the BIP-130
  branching machinery exists. (`miner` paths and `submitblock`
  RPC path should also wire this — check those before fix.)

- **BUG-12 (P1)** — **No `MaybeSendSendHeaders` minimum-chain-work
  gate.** Core (net_processing.cpp:5519-5538) delays sending
  `sendheaders` to a peer until the peer's
  `state.pindexBestKnownBlock->nChainWork > MinimumChainWork()`
  — i.e., until headers sync has progressed past the
  pre-checkpoint floor. The point is twofold: (a) we don't want
  the peer firing block-announcement headers at us mid-headers-sync
  (it pollutes our state-tracking), and (b) we don't want to
  signal "send me headers" to a peer that hasn't yet shown us
  enough headers to be worth talking to. rustoshi sends
  `sendheaders` **immediately** in `run_outbound_peer` at
  peer.rs:1009-1014, post-handshake-complete, before any header
  sync. Same for `run_inbound_peer` at peer_manager.rs:3256-3262.
  Premature; deviates from Core; may interact badly with
  `presync` (the headers-presync DoS defense) on peer side.

### P2 — efficiency bugs (no interop violation; just bandwidth)

- **BUG-13 (P2)** — **No `m_sent_sendheaders` idempotence.** Core
  uses an atomic `m_sent_sendheaders` flag (net_processing.cpp:406)
  to ensure SENDHEADERS is sent **at most once** per peer per
  session. rustoshi sends `sendheaders` at handshake-complete
  (peer.rs:1009-1014, peer_manager.rs:3256-3262) without tracking
  whether it has been sent before. If the same peer's handshake
  is re-driven (e.g., via the inbound-listen-after-disconnect race
  on the same socket port), the message is re-sent. Low-impact in
  practice because handshake is one-shot, but the idempotence is
  load-bearing for the upgrade path to `MaybeSendSendHeaders` in
  BUG-12.

- **BUG-14 (P2)** — **No `MAX_BLOCKS_TO_ANNOUNCE = 8` cap.**
  Core (net_processing.cpp:5840) caps the per-tick batch size of
  block-announcement headers at 8 (`MAX_BLOCKS_TO_ANNOUNCE`); above
  that, it falls back to inv-style announcement to keep the
  headers message bounded. rustoshi's `announce_block`
  (peer_manager.rs:1733-1760) is called per-block with a single
  header; the multi-block batching equivalent is missing — but
  also irrelevant, because the trigger is missing (BUG-11). The
  P2 grade is because, even when BUG-11 is fixed, the cap should
  be respected.

- **BUG-15 (P2)** — **No `fRevertToInv` logic on reorg or
  multi-block.** Core (net_processing.cpp:5838-5890) revert-to-inv
  scans `m_blocks_for_headers_relay`, checks each block is on
  `m_chainman.ActiveChain()`, bails to inv if any block diverged.
  rustoshi's `announce_block` is single-block, so this trigger
  doesn't arise — but a future caller in the reorg path that wants
  to announce multiple headers in one batch will need to
  implement this gate. P2 forward-warning.

- **BUG-16 (P2)** — **No wtxidrelay-after-verack disconnect.**
  Core (net_processing.cpp:3921-3927) disconnects a peer that
  sends `wtxidrelay` after the handshake is complete:
  `if (pfrom.fSuccessfullyConnected) { pfrom.fDisconnect = true; }`.
  This is BIP-339 §"feature negotiation must happen between
  VERSION and VERACK." rustoshi's post-handshake event loop
  (peer_manager.rs:2017-2160) has arms for SendHeaders / FeeFilter
  / GetAddr / Pong but **no `WtxidRelay` arm at all** — a
  late-arriving WtxidRelay is silently ignored. The peer is not
  disconnected, not misbehavior-flagged, just no-oped. P2 because
  the consequence is "we tolerate a peer that should be banned,"
  not "we ban a peer we shouldn't" — the safer direction.

### P3 — minor

- **BUG-17 (P3)** — **Duplicate wtxidrelay before verack is
  silently tolerated** without being explicitly idempotent.
  Core (net_processing.cpp:3929-3934) tracks
  `if (!peer.m_wtxid_relay) ... else { LogDebug(... duplicate ...); }`
  — i.e., notes the duplicate at debug level. rustoshi's
  pre-verack receive loop in `perform_handshake_tracked`
  (peer.rs:2196-2222) does `NetworkMessage::WtxidRelay =>
  wants_wtxid_relay = true;` unconditionally — silently idempotent,
  no log. Same for v2 paths. P3 because the behavior matches in
  observable terms (`wants_wtxid_relay` ends up `true` either
  way), only the audit-trail visibility differs.

## Cross-cutting patterns observed

- **Well-engineered-helper-never-wired** — BUG-1 (most prominent
  occurrence across W120-W136 audits): the `relay.rs` module has a
  near-complete BIP-133 / inventory-trickle implementation that
  cannot be exercised because `PeerManager` doesn't own it. ~700
  lines of dead code (modulo their unit tests).
- **Comment-as-confession** — BUG-2 ("Without mempool we set a
  high fee rate to discourage tx relay" — but 100 sat/vB is not
  prohibitive) and BUG-7 ("Core marks the peer as misbehaving" —
  Core does not).
- **Half-symmetric BIP gating** — BUG-3: the v1 inbound handshake
  loop catches `wtxidrelay`/`sendaddrv2`/`sendtxrcncl` in the same
  catch-all arm, but only `sendaddrv2` flips its flag; the
  `wtxidrelay` flag-flip is missing. Easy to miss because the
  symmetric arm in the outbound handshake (peer.rs:2207-2214) gets
  this right, so a code-review against the outbound helper as
  reference would not flag the inbound divergence.
- **Engineered-helper-with-unwired-call-site** — BUG-11:
  `announce_block` exists, is tested in-file at line 5039, has
  the correct headers-vs-inv-per-peer branching logic, and is
  even *documented* via the camlcoin reference impl in the
  doc-comment at line 1731. The bug is that no production caller
  invokes it from the P2P chain-advance path.

## Out-of-scope (not in W136 audit)

- `crates/network/src/erlay.rs` — BIP-330 SENDTXRCNCL / Erlay
  reconciliation. Code exists but is unwired (`txreconciliation
  is_peer_registered` returns false unconditionally somewhere).
  Separate wave.
- `crates/network/src/compact_blocks.rs` — BIP-152 sendcmpct /
  cmpctblock / blocktxn. W126 audited this.
- `crates/network/src/headers_presync.rs` — anti-DoS pre-sync.
  Touches the headers-sync side of BIP-130 but not the
  block-announce side.
- Tx-relay outbound queue, NOTFOUND handling, getdata processing —
  covered by W103 tx-relay audit.
- The W103 `BUG-20` finding (`InventoryTrickle::
  queue_transaction_for_relay` never called) is a parent of BUG-1
  here — both are pieces of the same unwired-relay-pipeline class.
  Recommend bundling fixes for W103 BUG-20 + W136 BUG-1 + BUG-4 +
  BUG-8 in one wire-the-relay-pipeline pass.

## Recommendation (for the eventual fix wave)

Sequence the fixes top-down — wiring BUG-1 (FeeFilterManager into
PeerManager) is the single biggest unlock. Once that is done,
BUG-4 / BUG-5 / BUG-6 / BUG-8 collapse to "expose the right hooks
from `peer_manager.handle_event` into the `FeeFilterManager`
method that already does the right thing." BUG-2 is the IBD-aware
filter value, a one-line change to compute `filter_to_send` based
on a chain-state-snapshot input. BUG-3 is a one-line change in
peer_manager.rs:3186-3191. BUG-9 is a one-line change at
main.rs:3779-3782. BUG-11 is one call-site at the connect-tip
hook in main.rs. BUG-12 is a deferred-send guard. BUG-16 is one
match-arm in the post-handshake event loop.

Estimated fix size: ~150-300 LOC across `peer_manager.rs`,
`peer.rs`, `main.rs`, plus retiring the unit-test-only references
to the now-wired helpers in `w103_tx_relay_tests.rs`. No new
helper code required — every needed primitive already exists in
`relay.rs`. **The audit's main finding is that the implementation
already exists; the integration does not.**
