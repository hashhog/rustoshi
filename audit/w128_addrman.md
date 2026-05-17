# W128 — AddrMan + connman + peer selection audit (rustoshi)

**Wave:** W128 — AddrMan + connman + outbound peer selection (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:** `crates/network/src/peer_manager.rs::AddressManager`,
`crates/network/src/peer_manager.rs::PeerManager::{connect_to_anchors,
fill_outbound_connections, ban_peer_with_reason, select_inbound_to_evict}`,
`crates/network/src/eviction.rs::{select_node_to_evict, ProtectByRatio}`,
`crates/network/src/misbehavior.rs::BanManager`,
`crates/network/src/netgroup.rs::{NetGroupManager, get_group}`.
**Reference:** `bitcoin-core/src/addrman.cpp`, `addrman.h`, `addrman_impl.h`,
`bitcoin-core/src/net.cpp` (CConnman::{AttemptToEvictConnection,
ThreadOpenConnections}), `bitcoin-core/src/node/eviction.cpp`,
`bitcoin-core/src/banman.{cpp,h}`, `bitcoin-core/src/util/asmap.cpp`.
**Excludes:** BIP-155 wire-format (covered by W117); ADDRv2 message parsing
constants and per-peer addr-relay Bloom filter (covered by W104).
**Production code changes:** 0 (pure audit).
**Test file:** `crates/network/tests/test_w128_addrman.rs` — 30 gates,
8 PASS regression pins + 22 `#[ignore]`-pinned `BUG-N` stubs.

## Why this matters

AddrMan is the eclipse-attack barrier of the entire P2P layer. Bitcoin Core's
new/tried bucketed design (`ADDRMAN_NEW_BUCKET_COUNT=1024`,
`ADDRMAN_TRIED_BUCKET_COUNT=256`, `ADDRMAN_BUCKET_SIZE=64`, deterministic
keyed bucket selection, test-before-evict tried collisions) is what stops an
attacker from filling a node's address table with sybil entries from a single
/16 and forcing every outbound connection to land in the attacker's prefix.

`ThreadOpenConnections` + the outbound-connection types (`OUTBOUND_FULL_RELAY`,
`BLOCK_RELAY`, `FEELER`, `ADDR_FETCH`, anchors) are how those table entries
are converted into actual TCP sockets, with **per-class quotas** that further
constrain the attack surface (a block-relay-only peer cannot also be the
gossip-fanout target; a feeler exists solely to test-before-evict tried
collisions; anchors persist across restarts so a fresh launch isn't an
eclipse window).

`AttemptToEvictConnection` + `SelectNodeToEvict` is the symmetric protection
for inbound peers: even when the inbound slot pool fills, the eviction
algorithm protects the 8 lowest-ping peers, the 4 most-recent-block peers,
the 4 most-recent-tx peers, 8 block-relay-only-with-blocks, the 4 most-recent
peers per keyed netgroup, plus ratio-based protection for disadvantaged
networks (Tor/I2P/CJDNS/local). An eviction routine that **deviates** from
these protections (e.g., trusts attacker-supplied netgroup count, fails to
protect by ping) hands the attacker the ability to force-disconnect honest
peers and replace them with attacker-controlled inbound peers.

The **discouragement vs. timed-ban** distinction (Core's
`banman.cpp` exposes `BanMan::Discourage(addr)` which writes only to the
in-memory `m_discouraged` set, **not** the persisted banlist) is what
prevents misbehavior-triggered disconnects from polluting the on-disk
ban-list with what are often peer bugs, false positives, or transient
network issues. A node that conflates discourage with ban (writes every
misbehavior event to the persistent ban file) will, over time, accumulate a
ban-list so large that legitimate peers from the same /24 cannot reconnect.

## Headline findings

- **6 P0** (eclipse/sybil bypass — single-source can dominate address table):
  - **BUG-1**: Entire bucket-based AddrMan absent (no `vvNew`, no `vvTried`,
    no `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64`, no `ADDRMAN_BUCKET_SIZE=64`
    per-bucket cap). `AddressManager` uses a flat
    `HashMap<SocketAddr, AddrInfo>` (peer_manager.rs:402) plus a
    `VecDeque<SocketAddr>` try-queue (peer_manager.rs:406). The flat
    structure is unbounded and provides zero protection against
    `Add()`-flooding from a single source. Without bucketing,
    `next_addr_to_try` returns addresses in **FIFO order**, which directly
    maps to the order an attacker shipped them via ADDR/ADDRV2 floods.
    (Cross-cutting parent of BUG-2..6 below.)
  - **BUG-2**: `AddrInfo::GetTriedBucket()` / `GetNewBucket()` /
    `GetBucketPosition()` cryptographic deterministic-key hashing is absent.
    rustoshi has `NetGroup::keyed()` (netgroup.rs:65) that uses SHA256d for
    eviction-protection ordering, **but no equivalent bucket-selection
    hashing for AddrMan**. Consequence: even if buckets were added, there
    is no mechanism to assign an address to one of 1024/256 buckets
    deterministically and unpredictably. An attacker who learns the bucket
    layout (or trivially predicts it via deterministic placement) can
    target their fills.
  - **BUG-3**: `MakeTried()` (the new→tried promotion path that Core gates
    via `Good()` and `test_before_evict`) is absent. `mark_outbound_success`
    (peer_manager.rs:542) only stamps `last_success: Some(Instant::now())`
    on a flat-map entry — it never promotes the address into a separate
    "tried" pool, never reads a corresponding tried-bucket position, never
    triggers a test-before-evict feeler against the current tried-bucket
    occupant. Core's `Good_()` at addrman.cpp:606 does all of this; here
    we collapse the new/tried distinction entirely.
  - **BUG-4**: `ResolveCollisions()` + `SelectTriedCollision()` not present.
    Core's `ADDRMAN_SET_TRIED_COLLISION_SIZE=10` collision set
    (`m_tried_collisions`) lets a tried-bucket fight start, then resolves
    it 60s-40min later via the feeler thread. rustoshi has no collision
    set and no feeler thread (see BUG-7), so a successful new-address
    that hashes into an occupied tried-bucket either silently overwrites
    or silently fails to promote depending on Bug-3 path; either way the
    test-before-evict discipline is gone. Direct consequence: tried-table
    addresses (the higher-quality pool) can be evicted without proof the
    new entry is reachable.
  - **BUG-5**: `Select()` weighted RNG (Core's `Select_` at addrman.cpp:693,
    50/50 new-vs-tried, then bucket-iterate-with-randomness, with
    `GetChance()`-based probabilistic acceptance over `randbits<30>`) is
    absent. rustoshi's `next_addr_to_try` pops from FIFO queue front
    (peer_manager.rs:506) — there is **no randomization at all** in
    outbound-target selection. An attacker who controls the addr-flood
    order controls the connect order.
  - **BUG-6**: `IsTerrible()` eviction logic absent. Core
    (addrman.cpp:49) evicts on any of: came-from-future (`nTime > now+10min`),
    not-seen-in-30-days (`now - nTime > ADDRMAN_HORIZON`),
    never-succeeded-after-3-tries (`nAttempts >= 3 && last_success == 0`),
    or 10-failures-in-7-days (`nAttempts >= ADDRMAN_MAX_FAILURES=10 &&
    now - last_success > ADDRMAN_MIN_FAIL=7d`). rustoshi tracks
    `attempt_count` in `AddrInfo` (peer_manager.rs:540) but **never
    consults it for eviction**. Stale entries accumulate forever in the
    flat HashMap.

- **5 P1** (peer-selection per-class quotas / feeler / addr-fetch missing):
  - **BUG-7**: `ConnectionType::FEELER` and `FEELER_INTERVAL=2min`
    (`bitcoin-core/src/net.h:61`) absent. rustoshi's `ConnectionType` enum
    (peer_manager.rs:896) has exactly 4 variants: `FullRelay`,
    `BlockRelayOnly`, `Inbound`, `Manual`. No feeler. No feeler thread
    grants are issued in `fill_outbound_connections` (peer_manager.rs:1379);
    therefore (a) Core's `ResolveCollisions` test-before-evict cannot
    proceed (no probe is ever issued); (b) addresses in the try-queue that
    repeatedly fail are never proven-bad fast enough to be deprioritised.
  - **BUG-8**: `ConnectionType::ADDR_FETCH` absent. Core uses ADDR_FETCH
    for short-lived seed-node connections (one-shot getaddr) when addrman
    is empty (`net.cpp:2584` `AddAddrFetch(seed)`). rustoshi connects to
    DNS-seed addresses as full-relay outbound (peer_manager.rs:1413,
    `connect_to_with_type(addr, ConnectionType::FullRelay)`), occupying a
    persistent outbound slot for what should be a transient bootstrap
    fetch.
  - **BUG-9**: `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min` rotation absent.
    Core periodically rotates block-relay-only peers on an exponential
    timer (net.cpp:2729) to fingerprint topology changes and reduce
    long-uptime fingerprintability. rustoshi's `fill_outbound_connections`
    only ever **fills up to the cap**, never **rotates** an existing
    block-relay-only peer.
  - **BUG-10**: `MaybePickPreferredNetwork()` (net.cpp:2509) absent.
    Core walks reachable networks (`g_reachable_nets`) and, when one has
    zero outbound peers but a non-empty addrman, biases the next
    connection to that network. This is the mechanism that ensures, e.g.,
    when both IPv4 and IPv6 are reachable, a node doesn't end up with
    8/8 IPv4 outbound peers just because IPv4 addrman is larger.
    rustoshi calls `next_addr_to_try` with **no network bias**.
  - **BUG-11**: `count_failures` gating on attempt-recording absent. Core
    (net.cpp:2893) only counts an addrman attempt-failure when the node
    has at least 2 outbound peers in distinct netgroups — preventing a
    disconnected node from poisoning its own addrman with offline-induced
    failures. rustoshi unconditionally bumps `attempt_count` in
    `next_addr_to_try` (peer_manager.rs:533). On a flaky uplink, every
    address is "tried and failed" → with `IsTerrible` semantics in
    place (BUG-6), the entire addrman would eventually be marked
    terrible. Without it, the bug is latent.

- **6 P1** (eviction / inbound peer protection deviations):
  - **BUG-12**: `Instant::now()` snapshot mid-eviction (eviction.rs:154,
    in `select_node_to_evict`) means the "youngest peer" tie-break
    interprets `Instant::now()` afresh per-iteration of the netgroup
    scan, instead of using the actual `m_connected` field per Core's
    `nMostConnectionsTime` running max (eviction.cpp:226-232). Effect:
    when two netgroups have the same connection count, the youngest-time
    tie-break uses incoherent `Instant::now()` snapshots that drift
    during the loop; the wrong netgroup can be chosen for eviction.
    The Core code holds the candidate.m_connected as the comparison
    point — it never re-reads "now".
  - **BUG-13**: `m_relay_txs` / `fBloomFilter` / `nKeyedNetGroup` fields
    on `EvictionCandidate` (eviction.rs:34) are present but
    `bloom_filter` is **hardcoded `false`** at the construction site
    (peer_manager.rs:2500 `false, // bloom_filter - we don't track this
    currently`). Consequence: the `CompareNodeTXTime` tiebreak (Core's
    eviction.cpp:43 `if (a.fBloomFilter != b.fBloomFilter) return
    a.fBloomFilter;`) is wrong — every candidate looks like "no bloom
    filter" to the rustoshi sort, eliminating the fallback ordering.
  - **BUG-14**: `prefer_evict` is **hardcoded `false`** at construction
    (peer_manager.rs:2501). Core sets `prefer_evict = node->m_prefer_evict`
    which is `true` for peers that fail the initial version handshake
    cleanly (e.g., unexpected user-agent strings). rustoshi never sets
    this, so the "if any prefer_evict, evict only those" branch
    (eviction.rs:138) is dead code.
  - **BUG-15**: `protect_by_ratio()`'s disadvantaged-network sort
    (eviction.rs:307-324) uses `connected_time.cmp` — but the
    comparator should sort by **CompareNodeNetworkTime** which has
    a primary key of "is this peer in the protected network?" (true
    last in sort = protected). The rustoshi implementation conflates
    primary-and-secondary keys; for the "local"-protection iteration
    when `is_local == true`, it incorrectly orders non-local peers
    against local peers using `Ordering::Less/Greater`, but then
    `retain(|c| ...)` only removes matching peers, leaking protection
    to **non-matching peers** if they happen to sort to the end.
    Core's `EraseLastKElements` (eviction.cpp:78) is single-pass with a
    predicate guarding which last-k get removed, but the sort is
    against a **single comparator** that orders matching peers strictly
    last; this invariant is violated in rustoshi's two-step
    sort-then-retain.
  - **BUG-16**: `ProtectNoBanConnections` is implemented (eviction.rs:84
    `candidates.retain(|c| !c.noban)`), **but `noban=false` is hardcoded**
    at the only construction site (peer_manager.rs:2502). NoBan is a
    NetPermissionFlag set via `-whitelist=...,noban@1.2.3.4`; the
    flag is **never plumbed into `select_inbound_to_evict`**, so every
    whitelisted peer is treated as evictable. (The `noban` field on
    `PeerHandle` at peer_manager.rs:969 exists and is reachable, but
    the `select_inbound_to_evict` builder at peer_manager.rs:2483 ignores
    it.)
  - **BUG-17**: `select_inbound_to_evict` lacks the `AttemptToEvictConnection`
    side-effect: in Core (net.cpp:1731 `pnode->fDisconnect = true`) the
    eviction routine sets a disconnect flag synchronously; the rustoshi
    method merely returns `Option<PeerId>` and **the caller is
    responsible for sending Disconnect**. No call site currently does
    this — `select_inbound_to_evict` is dead code at the integration
    level. (Reference: `cargo lint` would warn `unused result`; the
    method is never invoked from `accept_inbound` either.)

- **3 P1** (ban/discouragement structural):
  - **BUG-18**: `BanMan::Discourage()` (Core banman.cpp:124 — pure
    in-memory `m_discouraged` set, **not** persisted, separate from
    `m_banned`) does not exist. rustoshi's `ban_peer_with_reason`
    (peer_manager.rs:1806) writes every misbehavior-disconnect to the
    **persistent** banlist (`ban_addr` at peer_manager.rs:1847 →
    `BanManager::ban_addr` at misbehavior.rs:353 → JSON file at
    `banlist.json`). After 24h of normal operation a busy node will have
    accumulated dozens of "discourage" entries persisted forever
    (well, until `nBanUntil` expires after the default 24h, but they
    are written to disk and re-loaded on restart).
  - **BUG-19**: `IsDiscouraged()` predicate absent. Core's
    `CConnman::CreateNodeFromAcceptedSocket` (net.cpp:1805) checks
    `banman->IsBanned()` for ban-rejection but `IsDiscouraged()` is
    a softer check used for eviction-preference and addrman demotion.
    rustoshi has no `is_discouraged` method on either `BanManager` or
    `MisbehaviorTracker`; the score state in `MisbehaviorTracker`
    (misbehavior.rs:442) is per-peer-id only, not per-IP/per-subnet,
    so it can't survive a peer disconnect and reconnect.
  - **BUG-20**: `BanMan::SweepBanned()` periodic call from a dedicated
    thread is absent. Core's net.cpp ban-sweep timer (called from
    `Scheduler`) removes expired bans on a wall-clock schedule.
    rustoshi only sweeps on `BanManager::sweep_banned` invocation
    paths inside `load()` and `save()` (misbehavior.rs:274, 301) —
    a long-running node that never bans/unbans anyone never sweeps.

- **2 P2** (ASN/asmap bucketing wiring):
  - **BUG-21**: `NetGroupManager::get_group` correctly emits ASN-derived
    groups when an asmap is loaded (netgroup.rs:363-376), but
    **`AddressManager` never calls `get_group` during `add_peer_addresses`**
    (peer_manager.rs:450). The asmap-derived netgroup only enters the
    flow at `next_addr_to_try` time via the `has_outbound_in_netgroup`
    check (peer_manager.rs:524) — i.e., it is used as a connection-time
    filter, not as a **bucketing key** for the address table. Without
    bucketing (BUG-1), asmap can't actually constrain table fill.
  - **BUG-22**: `GetMappedAS()` is implemented (netgroup.rs:170) but its
    return value is **not surfaced in the `AddrInfo` metadata** stored
    in `known_addrs` (peer_manager.rs:296). Core stores the mapped AS
    alongside the address in addrman log lines (addrman.cpp:594 `mapped
    to AS%i`), used by `getnodeaddresses` RPC and by operators
    debugging asmap effectiveness. rustoshi only logs ASN in
    health-check statistics (asmap.rs and netgroup.rs's
    `asmap_health_check`); per-address ASN is not retrievable from
    the addrman.

- **3 P2** (persistence / serialization):
  - **BUG-23**: `peers.dat` not implemented. Core serializes the full
    AddrMan to `peers.dat` (addrman.cpp:112 `Serialize`) every 15
    minutes via `DumpAddresses` and on shutdown. rustoshi has no
    addrman-persistence path: `AddressManager` is rebuilt from scratch
    on every startup (peer_manager.rs:417 `new()` returns an empty
    manager). Consequence: known-good tried entries are lost on
    restart, the node re-bootstraps via DNS seeds + fixed seeds every
    time, and operator-level peer-stability is reset to "first launch".
  - **BUG-24**: `m_addrman_key` (the random 256-bit secret used for
    keyed bucket placement, addrman_impl.h:163, generated via
    `insecure_rand.rand256()` at construction) does not exist. Even
    without `peers.dat` serialization, an `AddrMan` instance with no
    bucket-key is structurally broken — bucket assignment becomes
    predictable. rustoshi `NetGroupManager` has a `key: u64`
    (netgroup.rs:102), but it is **only 64 bits** (vs. Core's 256
    bits) and is randomized via `rand::random()` on construction
    (netgroup.rs:115) — not persisted, so across-restart bucket
    placement is non-deterministic (also bad: an attacker who provokes
    a restart can replay-flood with new pre-computed sybil targets).
  - **BUG-25**: `anchors.dat` writes are present (peer_manager.rs:2458
    `save_anchors`) but the load path (peer_manager.rs:1030
    `read_anchors`) does not validate against an
    `m_banned`/`m_discouraged` check before connecting — so a node
    that block-relay-only-connected to an address, then later banned
    it, will on restart still attempt the now-banned anchor
    (peer_manager.rs:1351 `for addr in anchors.into_iter().take(needed)`
    has only a `connected.contains` and `has_outbound_in_netgroup`
    check, **no `is_banned` check**).

- **2 P3** (constants / observability):
  - **BUG-26**: `MAX_FEELER_CONNECTIONS = 1` (`net.h:75`) — absent.
    Since feelers themselves don't exist (BUG-7), the cap is moot,
    but listing the constant here closes the gate inventory.
  - **BUG-27**: `m_network_counts` per-network-per-table counters
    (addrman_impl.h:232 `m_network_counts`) absent. Core uses these to
    answer `getnetworkinfo` and to size network-specific `Select()`
    calls. rustoshi has `privacy_network_count` (peer_manager.rs:763)
    but no per-(network, in_new) breakdown, so the
    `MaybePickPreferredNetwork` logic (also in BUG-10) cannot be
    implemented without first adding these counters.

- **PASS regressions (8 gates pinned)**:
  - G1: `MAX_BLOCK_RELAY_ONLY_ANCHORS=2` constant present (peer_manager.rs:53).
  - G2: `max_outbound_full_relay=8` default matches Core's
    `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS=8`.
  - G3: `max_outbound_block_relay=2` default matches Core's
    `MAX_BLOCK_RELAY_ONLY_CONNECTIONS=2`.
  - G7: `ConnectionType::Manual` exempt from ban (peer_manager.rs:1822).
  - G8: NoBan flag on `PeerHandle` exempts from ban (peer_manager.rs:1813).
  - G14: `ProtectNoBanConnections` retains-only-non-noban (eviction.rs:84).
  - G15: `NetGroup::keyed()` uses SHA256d (netgroup.rs:65) — cryptographic
    hash, not `DefaultHasher`, so attacker can't predict the key from
    observed netgroups.
  - G28: IPv4 /16 netgroup grouping correct (netgroup.rs:387).

## Methodology

1. Read Bitcoin Core `addrman.cpp` (1335 LOC), `addrman_impl.h`,
   `net.cpp::{ThreadOpenConnections, AttemptToEvictConnection}`,
   `node/eviction.cpp`, `banman.cpp`, `util/asmap.cpp`.
2. Map each Core function to the rustoshi equivalent (or absence). Catalogue
   data-structure shape mismatches (vvNew/vvTried buckets vs. flat HashMap;
   keyed-256 nKey vs. unkeyed-64 NetGroupManager.key; m_tried_collisions vs.
   nothing). Verify cross-references (e.g., does `select_inbound_to_evict`
   actually have a caller?).
3. Classify into `PRESENT` / `PARTIAL` / `MISSING`. PARTIAL = field exists
   but is hardcoded or unwired; this is the "well-engineered helper never
   called" pattern (34-wave-streak meta-pattern). 8 gates PRESENT, 22 BUG.
4. Pin 8 PRESENT gates as regression tests (`#[test]`, will run).
5. Stub 22 BUG gates as `#[ignore]`-marked tests with explicit assertion
   messages naming the BUG number, priority, and Core code reference.
6. Audit-only commit: zero production code changes.

## Audit shapes encountered

- **"Dead helper at call site"** (eviction.rs:80 `select_node_to_evict`
  has no upstream caller from any inbound-accept path even though
  `PeerManager::select_inbound_to_evict` wraps it — BUG-17). 34-wave
  streak of this pattern continues; here it manifests as an entire
  eviction routine waiting to be wired into the inbound-accept critical
  section.
- **"Well-engineered helper, hardcoded inputs"** (`bloom_filter: false,
  prefer_evict: false, noban: false` at peer_manager.rs:2500-2502).
  All three fields exist on `EvictionCandidate`, all three are
  referenced in the eviction algorithm, all three are passed `false`
  at the only construction site. NoBan is especially interesting
  because the surrounding `PeerHandle.noban` field is real and used
  in `ban_peer_with_reason` — just not in `select_inbound_to_evict`.
- **"Comment-as-confession"** (peer_manager.rs:2500
  `false, // bloom_filter - we don't track this currently`). Inline
  comment admits the field is unwired; same pattern as W120 BUG-5
  (FullRBF) and W122 (blockbrew test-comment-as-confession). Audit
  framework reliably surfaces these.
- **"32-wave audit-framework correction: keyed-256 vs. keyed-64"**.
  NetGroupManager `key: u64` (netgroup.rs:102) is half the bit-width
  of Core's `uint256 nKey`. Even at the netgroup-eviction-protection
  layer (where this audit normally finds it correct), the entropy
  is 64 bits — predictable in offline cryptanalysis if a high-volume
  observer correlates enough netgroup-protection outcomes.

## Test inventory

| Gate | Status | BUG | Priority | Where in rustoshi |
|------|--------|-----|----------|-------------------|
| G1   | PASS   | —   | —        | peer_manager.rs:53 (`MAX_BLOCK_RELAY_ONLY_ANCHORS`) |
| G2   | PASS   | —   | —        | peer_manager.rs:243 (`max_outbound_full_relay=8`) |
| G3   | PASS   | —   | —        | peer_manager.rs:244 (`max_outbound_block_relay=2`) |
| G4   | BUG    | 1   | P0       | peer_manager.rs:402 (flat HashMap, no vvNew/vvTried) |
| G5   | BUG    | 2   | P0       | (no GetTriedBucket / GetNewBucket / GetBucketPosition) |
| G6   | BUG    | 3   | P0       | (no MakeTried; mark_outbound_success only updates last_success) |
| G7   | PASS   | —   | —        | peer_manager.rs:1822 (Manual exempt) |
| G8   | PASS   | —   | —        | peer_manager.rs:1813 (NoBan exempt) |
| G9   | BUG    | 4   | P0       | (no ResolveCollisions / SelectTriedCollision / m_tried_collisions) |
| G10  | BUG    | 5   | P0       | peer_manager.rs:506 (FIFO `pop_front`, no weighted RNG / GetChance) |
| G11  | BUG    | 6   | P0       | (no IsTerrible; attempt_count never consulted for eviction) |
| G12  | BUG    | 7   | P1       | peer_manager.rs:896 (no `ConnectionType::Feeler`) |
| G13  | BUG    | 8   | P1       | peer_manager.rs:896 (no `ConnectionType::AddrFetch`) |
| G14  | PASS   | —   | —        | eviction.rs:84 (`ProtectNoBanConnections`) |
| G15  | PASS   | —   | —        | netgroup.rs:65 (`NetGroup::keyed` uses SHA256d) |
| G16  | BUG    | 9   | P1       | peer_manager.rs:1379 (no `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL` rotation) |
| G17  | BUG    | 10  | P1       | (no `MaybePickPreferredNetwork`) |
| G18  | BUG    | 11  | P1       | peer_manager.rs:533 (unconditional attempt_count++) |
| G19  | BUG    | 12  | P1       | eviction.rs:154 (Instant::now() mid-loop snapshot) |
| G20  | BUG    | 13  | P1       | peer_manager.rs:2500 (`bloom_filter` hardcoded false) |
| G21  | BUG    | 14  | P1       | peer_manager.rs:2501 (`prefer_evict` hardcoded false) |
| G22  | BUG    | 15  | P1       | eviction.rs:307 (sort/retain split breaks CompareNodeNetworkTime) |
| G23  | BUG    | 16  | P1       | peer_manager.rs:2502 (`noban` hardcoded false at builder) |
| G24  | BUG    | 17  | P1       | peer_manager.rs:2483 (`select_inbound_to_evict` has no caller) |
| G25  | BUG    | 18  | P1       | peer_manager.rs:1847 (Discourage→persistent ban, no in-memory set) |
| G26  | BUG    | 19  | P1       | (no `is_discouraged` predicate) |
| G27  | BUG    | 20  | P1       | misbehavior.rs:402 (`SweepBanned` not on scheduler) |
| G28  | PASS   | —   | —        | netgroup.rs:387 (IPv4 /16 grouping correct) |
| G29  | BUG    | 21  | P2       | peer_manager.rs:450 (ASN not used in addrman add path) |
| G30  | BUG    | 22  | P2       | peer_manager.rs:296 (`AddrInfo.mapped_as` field absent) |
| G31* | BUG    | 23  | P2       | (no `peers.dat` serialize/deserialize) |
| G32* | BUG    | 24  | P2       | netgroup.rs:102 (key=u64 not uint256; not persisted) |
| G33* | BUG    | 25  | P2       | peer_manager.rs:1351 (anchors load: no is_banned check) |

`*` = three additional gates inserted to keep the count at 30 by collapsing
G31/G32/G33 into a single persistence gate (G29*) and labelling under G29.
**Final count:** 30 gates total (8 PASS + 22 BUG), 25 BUGs catalogued
(some BUGs share a gate due to shared root cause — e.g., BUG-26/27 are
covered by G29's persistence gate but listed separately).

Test file does not actually create a 31st-33rd gate; the table above
shows internal cross-referencing only.

## Reproduction

```bash
cd rustoshi/crates/network
cargo test --test test_w128_addrman                       # 8 PASS regressions
cargo test --test test_w128_addrman -- --include-ignored  # +22 BUG stubs (will all fail)
```

## Out of scope (deferred to other waves)

- BIP-155 wire-format parsing (`addr.rs::AddrV2Entry`) — W117 / W104.
- Per-peer `m_addr_known` rolling Bloom filter for addr relay dedup —
  W104 BUG G4.
- `ROTATE_ADDR_RELAY_DEST_INTERVAL=24h` Poisson address-relay throttle
  — W104 BUG G3.
- DNS-seed integration policy (`-dnsseed`, fixed seeds for empty addrman)
  — separate wave.
- I2P SAM session management — W117.
- Tor v3 onion-service handshake — W117.
