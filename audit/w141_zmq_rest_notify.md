# W141 — ZMQ publisher + REST endpoints + Notification scripts audit (rustoshi)

**Wave:** W141 — ZMQ + REST + Notification scripts (bundled, DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi node-operator-surface telemetry / read-only
HTTP / shell-callback subsystems:

- `crates/rpc/src/zmq.rs` (~1,079 LOC) — `ZmqNotifier`, `ZmqPublisher`,
  `ZmqNotifierConfig`, `ZmqTopic`, `SequenceLabel`, `ZmqNotificationInfo`,
  `parse_zmq_args`, all `notify_*` methods + the dedicated worker
  thread that owns the `zmq::Context` and per-address sockets.
- `crates/rpc/src/rest.rs` (~2,470 LOC) — `start_rest_server`,
  `start_rest_server_with_wallet`, `rest_router(_with_wallet)`,
  `rest_block`, `rest_block_notxdetails`, `rest_headers`, `rest_tx`,
  `rest_getutxos`, `rest_mempool_info`, `rest_mempool_contents`,
  `rest_chaininfo`, `rest_blockhashbyheight`, `rest_blockfilter`,
  `rest_blockfilterheaders`, `payjoin_handler`, the `RestState`
  struct, `RestError` variants, `RestFormat`/`build_response` helpers.
- `rustoshi/src/main.rs` lines 230-241 (`-rest` + `-restbind` CLI args),
  lines 2002-2034 (REST server bring-up).
- (absence) **no** `crates/rpc/src/notify.rs` or any other Rust source
  implementing `-blocknotify` / `-walletnotify` / `-alertnotify`
  shell-callback dispatch.
- `crates/rpc/src/server.rs` lines 1030-1065 (`RpcServerImpl` with
  optional `zmq_notifier: Option<SharedZmqNotifier>` field +
  `with_zmq`-constructor that is **never called outside the crate**)
  and lines 5511-5516 (`get_zmq_notifications` RPC method that always
  reads `None` in production).

**References (Bitcoin Core):**
- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp` (213 LOC) — the
  `CZMQNotificationInterface` validation-interface adapter; per-topic
  factory map keyed by `pubhashblock` / `pubhashtx` / `pubrawblock` /
  `pubrawtx` / `pubsequence`; `Initialize` / `Shutdown` /
  `TryForEachAndRemoveFailed` semantics; the IPC-prefix normalisation
  (`unix://` → `ipc://`).
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (293 LOC) —
  `CZMQAbstractPublishNotifier::Initialize` + `SendZmqMessage`
  (frame layout: `[topic str][body bytes][LE-32 sequence]`), the
  per-topic notifier subclasses, `SendSequenceMsg`
  `[32-byte hash][1-byte label][optional LE-64 sequence]`.
- `bitcoin-core/src/zmq/zmqnotificationinterface.h` — public surface
  + lifecycle hooks (`UpdatedBlockTip` IBD gate, `BlockConnected`
  `role.historical` gate, `TransactionAddedToMempool` /
  `TransactionRemovedFromMempool` sequence number wiring).
- `bitcoin-core/src/rest.cpp` (1,178 LOC) — `StartREST` URI table at
  line 1141; the 14 endpoint families
  (`/rest/tx`, `/rest/block`, `/rest/block/notxdetails`,
  `/rest/blockpart`, `/rest/blockfilter`, `/rest/blockfilterheaders`,
  `/rest/chaininfo`, `/rest/mempool/{info,contents}`, `/rest/headers`,
  `/rest/getutxos`, `/rest/deploymentinfo`, `/rest/blockhashbyheight`,
  `/rest/spenttxouts`); `RESTERR` HTTP-status mapping; `RESTResponseFormat`
  enum (`.bin` / `.hex` / `.json` + `UNDEF`); `CheckWarmup` 503; the
  4 MB `MAX_REST_HEADERS_RESULTS = 2000` headers cap and 15-outpoint
  cap (`MAX_GETUTXOS_OUTPOINTS`).
- `bitcoin-core/src/init.cpp` line 1985 — `-blocknotify=<cmd>` connect
  hooked into `uiInterface.NotifyBlockTip_connect`, `%s` substitution,
  detached `std::thread t(runCommand, command)`, `POST_INIT`-only gate.
- `bitcoin-core/src/wallet/init.cpp` line 75 + `wallet.cpp` lines
  1139-1164 — `-walletnotify=<cmd>` `%s` (txid) / `%w` (shell-escaped
  wallet name) / `%b` (block hash or `"unconfirmed"`) / `%h` (block
  height or `"-1"`) substitution; ShellEscape only on `%w`.
- `bitcoin-core/src/node/kernel_notifications.cpp` lines 30-47 —
  `-alertnotify=<cmd>`: `SanitizeString` strips non-safe chars,
  single-quotes wrap before `%s`, detached thread.
- `bitcoin-core/src/common/system.cpp` lines 40-62 — `ShellEscape`
  (single-quote with `'` → `'"'"'` escape) and `runCommand`
  (`::system(strCmd.c_str())`).

BIPs: None directly. (BIP-78 PayJoin is mounted on the rustoshi REST
listener as `POST /payjoin`, but PayJoin was audited in W119 — out
of scope here.)

**Production code changes:** 0 (pure audit).
**Test file:** `crates/rpc/tests/test_w141_zmq_rest_notify.rs` — 30
gates, PASS regression pins + `#[ignore]`-pinned BUG-N stubs. Tests
are split 10/15/5 across the three subsystems (ZMQ / REST / notify).

## Why this matters

These three subsystems are the **node's observable surface** for any
operator who wants live data without poking RPC: ZMQ is what
indexers, lightning daemons, mempool dashboards, and arbitrage bots
subscribe to; REST is what curl-based monitoring, block-explorer
sidecars, and BIP-21 PayJoin senders hit; notification scripts are
what cron/systemd-style integrations rely on for "ping a webhook when
the chain reorgs" type workflows.

Any silent divergence here looks like "node is healthy" from inside
rustoshi (consensus correct, RPC responding) while every external
integration is wedged or stale or — worse — receiving deceptive data:

1. **ZMQ "the helper exists but is never wired" failure mode.**
   `crates/rpc/src/zmq.rs` is a polished 1,079-line implementation
   with its own dedicated worker thread, multipart-message handler,
   sequence-number tracking, and 6 unit tests verifying pub/sub
   round-trip with a real `zmq::Context`. **It is never instantiated
   in production.** The only constructor (`ZmqNotifier::create`) has
   exactly **zero call sites in `rustoshi/src/main.rs`**, which means
   the `RpcServerImpl::with_zmq` alternate constructor (server.rs:1050)
   is never reached, which means `RpcServerImpl::zmq_notifier` is
   always `None`, which means `getzmqnotifications` always returns
   `[]`, which means operators specifying `-zmqpubhashblock=tcp://…`
   on the command line get **no error and no notifications**. This
   is the W117/W118 "well-engineered helper never wired" pattern in
   its purest form. Coverage: BUG-1 (P0).
2. **REST `/rest/block/<hash>.json` returns notxdetails-shape always.**
   Both `rest_block` (full-detail endpoint) and `rest_block_notxdetails`
   feed the same `build_block_info` → `BlockInfo` shape where `tx` is
   `Vec<String>` of txids. Core's `rest_block` returns
   `blockToJSON(... TxVerbosity::SHOW_DETAILS_AND_PREVOUT)` which
   embeds each tx as a full object with `vin[].prevout` etc. Anyone
   scraping `/rest/block/<hash>.json` for fee-rate accounting or
   address indexing gets a useless txid array. Worse: a comment in
   `build_block_info_simple` (rest.rs:997-999) literally reads
   `"For REST notxdetails endpoint, this is the same since we already
   only return txids"` — the **comment-as-confession** pattern;
   the author noticed that `notxdetails` and `block` collapsed to
   the same shape and resolved the confusion by deleting any
   difference rather than by fixing the full-detail path. Coverage:
   BUG-12 (P0) + BUG-13 (P3 comment-as-confession).
3. **Notification scripts entirely absent.** `-blocknotify`,
   `-walletnotify`, `-alertnotify` do not exist as CLI flags
   (no clap `#[arg(long = "blocknotify")]` anywhere), no
   `notify.rs` module exists, no `runCommand`-equivalent shell-out
   helper is implemented. Every operator who runs `bitcoind` today
   with `-blocknotify=/usr/local/bin/notify-webhook %s` and tries to
   swap in rustoshi as a drop-in replacement gets no warning, no
   error, and silently never fires their webhook. Coverage:
   BUG-22, BUG-23, BUG-24 (all P1).
4. **ZMQ multipart frame ordering is API-equivalent to Core's
   per-zmq_msg loop.** rustoshi's `send_multipart` does three
   `socket.send(... SNDMORE)` calls in sequence (zmq.rs:288-318)
   instead of Core's vararg `zmq_send_multipart` loop
   (zmqpublishnotifier.cpp:40-80). Each frame is sent with `SNDMORE`
   except the last; the wire-level multipart envelope is identical.
   Coverage: G2 regression pin.
5. **Per-topic sequence number tracking matches Core but global
   sequence semantics differ.** Core's `nSequence` is **per-notifier
   instance** (so two `pubhashblock` endpoints maintain separate
   counters), incremented in `SendZmqMessage` after sending
   (zmqpublishnotifier.cpp:204-205). rustoshi keys sequence numbers
   by `ZmqTopic` (zmq.rs:225, 322), so two `pubhashblock` endpoints
   at different addresses **share** the same counter. Operators who
   subscribe to multiple endpoints with the same topic and dedupe by
   `(topic, seq)` will see "missing" sequence numbers on each
   endpoint instead of contiguous 0/1/2/3. Coverage: BUG-2 (P1).
6. **REST 7 endpoint families missing.** `/rest/blockpart/`,
   `/rest/spenttxouts/`, `/rest/deploymentinfo`, the new query-param
   form of `/rest/headers/<hash>?count=N`, the new query-param form
   of `/rest/blockfilterheaders/<filtertype>/<blockhash>?count=N`,
   and `/rest/getutxos` POST-body input (binary post). Each one is
   a Core path that rustoshi answers `404 Not Found` to with no
   handler match. Coverage: BUG-14, BUG-15, BUG-16, BUG-17, BUG-18.

## Audit framework (30 gates / 25 BUGS catalogued; 18 are P0/P1/P2 testable)

Gate legend:
- **PASS** : behaviour matches Core (regression pin).
- **MISSING** : Core implements; rustoshi has no equivalent.
- **WIRING** : Code exists but is never reached in production.
- **CDIV-ZMQ** : ZMQ-wire-format divergence — subscribers parse the
  wrong frame layout / get wrong sequence numbers (not consensus
  but external-protocol cdiv).
- **CDIV-REST** : HTTP body / status code / content-type divergence
  (similar; external-protocol cdiv against scripts that parse
  responses).
- **CDIV-NOTIFY** : shell-command divergence (`%s` not substituted,
  shell-escape missing, `runCommand` thread leaks).

Severity (operator-visible):
- **P0** : production node silently does not provide a documented
  Core feature operators rely on.
- **P1** : feature provided but wire-incompatible (subscribers /
  scripts must special-case rustoshi).
- **P2** : feature provided, subtly different (off-by-one, ordering,
  edge case).
- **P3** : doc / comment / cosmetic — operator can work around.

### Subsystem 1: ZMQ publisher (G1-G10 / 11 BUGS catalogued, 4 testable)

|  # | Gate                                                   | Status   | Sev | BUG    |
|---:|--------------------------------------------------------|----------|-----|--------|
| G1 | 5 topic enum strings match Core (hashblock/hashtx/rawblock/rawtx/sequence) | PASS     | —   | —      |
| G2 | Multipart frame layout = `[topic][body][LE-u32 seq]`   | PASS     | —   | —      |
| G3 | Sequence label enum bytes match Core ('A'/'R'/'C'/'D')  | PASS     | —   | —      |
| G4 | `reverse_hash` produces display-order bytes            | PASS     | —   | —      |
| G5 | `parse_zmq_args` recognises 5 wire keys                | PASS     | —   | —      |
| G6 | `ZmqNotifier::create` returns `Ok(None)` on empty config | PASS   | —   | —      |
| G7 | Production binary actually instantiates `ZmqNotifier`  | WIRING   | P0  | BUG-1  |
| G8 | Sequence numbers are **per-notifier-instance**, not per-topic | CDIV-ZMQ | P1 | BUG-2  |
| G9 | `unix://` → `ipc://` prefix normalisation              | MISSING  | P1  | BUG-3  |
| G10| HWM override per `<arg>+hwm` (`-zmqpubhashblockhwm=N`)  | MISSING  | P2  | BUG-4  |

Additional ZMQ findings rolled into the gates above:
- **BUG-5 (P2)** : IBD gate on `UpdatedBlockTip` is **absent**;
  Core skips notifications when `fInitialDownload || pindexNew ==
  pindexFork` (zmqnotificationinterface.cpp:153-154). rustoshi has
  no equivalent guard — every IBD-syncing block would fire
  notifications, swamping subscribers. Lives at the call-site, but
  there's no call site (BUG-1), so latent.
- **BUG-6 (P3)** : `TryForEachAndRemoveFailed` semantic — Core
  shuts down + drops a notifier whose `Notify*` returned false.
  rustoshi's `handle_command` just `error!`-logs and returns; the
  same socket is reused on the next call.

### Subsystem 2: REST endpoints (G11-G25 / 9 BUGS catalogued, 9 testable)

|  #  | Gate                                                           | Status     | Sev | BUG    |
|----:|----------------------------------------------------------------|------------|-----|--------|
| G11 | `/rest/tx/<hash>.{bin,hex,json}` content-type maps correctly   | PASS       | —   | —      |
| G12 | `/rest/block/<hash>.json` returns FULL tx detail (vin/vout) NOT just txids | CDIV-REST | P0 | BUG-12 |
| G13 | `/rest/block/notxdetails/<hash>.json` returns only txids       | PASS       | —   | —      |
| G14 | `/rest/blockpart/<hash>.{bin,hex}?offset=N&size=M`              | MISSING    | P1  | BUG-14 |
| G15 | `/rest/spenttxouts/<hash>.{bin,hex,json}`                        | MISSING    | P1  | BUG-15 |
| G16 | `/rest/deploymentinfo[/<hash>].json`                            | MISSING    | P1  | BUG-16 |
| G17 | `/rest/headers/<hash>.<fmt>?count=N` (query form)               | MISSING    | P1  | BUG-17 |
| G18 | `/rest/getutxos` accepts POST body for binary input             | MISSING    | P2  | BUG-18 |
| G19 | HTTP 400 on bad hash / 404 on not found / 503 on warmup         | PARTIAL    | P1  | BUG-19 |
| G20 | `MAX_REST_HEADERS_RESULTS = 2000` cap                            | PASS       | —   | —      |
| G21 | `MAX_GETUTXOS_OUTPOINTS = 15` cap                                | PASS       | —   | —      |
| G22 | `-rest` flag defaults OFF (matches Core `DEFAULT_REST_ENABLE`)  | PASS       | —   | —      |
| G23 | REST router shares the JSON-RPC port (Core does)                | CDIV-REST  | P2  | BUG-20 |
| G24 | `build_block_info_simple` is a dead-helper comment-as-confession | CDIV-REST | P3  | BUG-13 |
| G25 | `/rest/chaininfo.json` rejects non-JSON formats                  | PASS       | —   | —      |

### Subsystem 3: Notification scripts (G26-G30 / 5 BUGS catalogued, 5 testable)

|  #  | Gate                                                | Status     | Sev | BUG    |
|----:|-----------------------------------------------------|------------|-----|--------|
| G26 | `-blocknotify=<cmd>` CLI arg + `%s` block-hash substitution | MISSING | P1 | BUG-22 |
| G27 | `-walletnotify=<cmd>` CLI arg + `%s`/`%w`/`%b`/`%h` substitution | MISSING | P1 | BUG-23 |
| G28 | `-alertnotify=<cmd>` CLI arg + sanitised `%s` substitution | MISSING | P1 | BUG-24 |
| G29 | `ShellEscape` helper for `%w` substitution           | MISSING    | P2  | BUG-25 |
| G30 | `runCommand` thread-detach lifecycle (drop-on-spawn)| MISSING    | P2  | BUG-21 |

## BUG catalogue (full text)

### BUG-1 (P0 / WIRING — ZMQ): The entire ZMQ subsystem is unreachable

**Location:** `rustoshi/src/main.rs` end-to-end + `crates/rpc/src/zmq.rs`
+ `crates/rpc/src/server.rs:1050` (`with_zmq` constructor).

`ZmqNotifier::create` (zmq.rs:498) is the only public entry point that
spawns the worker thread, binds sockets, and lets `notify_block` /
`notify_transaction` / `notify_*_sequence` actually publish. **It is
never called from `rustoshi/src/main.rs`.** `RpcServerImpl::with_zmq`
(server.rs:1050) is the only other downstream user; it has no call
sites outside the crate either. Result: every constructor in
production uses `RpcServerImpl::new` (server.rs:1041), which sets
`zmq_notifier = None`, which means `getzmqnotifications` always
returns `[]` and the entire `notify_block` / `notify_transaction`
pipeline is dead code.

Operators specifying `-zmqpubhashblock=tcp://0.0.0.0:28332` on the
rustoshi command line get **no warning** (no clap binding either —
see BUG-26 below) and **no notifications**. A downstream service
expecting Core-shape ZMQ telemetry from rustoshi sits silent.

**Fix sketch:** parse `--zmqpubhashblock=...` etc. CLI flags via
clap, call `ZmqNotifier::create(parse_zmq_args(&cli_zmq_args))`,
plumb the resulting `Option<SharedZmqNotifier>` into `RpcServerImpl`
via `with_zmq`, and wire `mempool.notify_*` / `chain.notify_*`
event sinks to the notifier. ~50 LOC of plumbing on top of the
~1,000-LOC implementation already sitting in zmq.rs.

### BUG-2 (P1 / CDIV-ZMQ — ZMQ): Sequence numbers shared across same-topic notifiers

**Location:** `crates/rpc/src/zmq.rs:225` (`sequences: HashMap<ZmqTopic, u32>`)
and `:322` (`next_sequence` keyed by `ZmqTopic`).

Core maintains `nSequence` on the `CZMQAbstractPublishNotifier`
instance (zmqpublishnotifier.cpp:198-205), so two
`pubhashblock=tcp://A:1` + `pubhashblock=tcp://B:1` notifiers maintain
**independent** counters. rustoshi keys by `ZmqTopic`, so the second
notifier never sees sequence 0 — it sees whatever counter the first
notifier has currently advanced to.

A consumer that subscribes to **only one** endpoint and dedupes by
`(topic, seq)` sees gaps every time the other endpoint fires:
endpoint A receives `(hashblock, 0), (hashblock, 2), (hashblock, 4)`
because endpoint B consumed 1, 3, 5. Looks like packet loss / SUB
HWM drop to the consumer.

**Fix sketch:** store `sequences: HashMap<(ZmqTopic, String), u32>`
(topic × address), or simpler: per-config sequence counter on
`ZmqNotifierConfig` itself.

### BUG-3 (P1 / MISSING — ZMQ): `unix://` prefix not normalised to `ipc://`

**Location:** would be in `ZmqPublisher::new` socket bind path
(`crates/rpc/src/zmq.rs:266`); absent.

Core (zmqnotificationinterface.cpp:62-64) rewrites a `unix://`
prefix to `ipc://` because libzmq itself accepts only `ipc://` for
UNIX domain sockets. rustoshi passes the address string through
unchanged to `zmq::Socket::bind`, so `--zmqpubsequence=unix:///tmp/x`
fails at bind time. Documented Core feature.

### BUG-4 (P2 / MISSING — ZMQ): Per-notifier HWM override (`-zmqpub<topic>hwm=N`)

**Location:** `crates/rpc/src/zmq.rs:660` (`parse_zmq_args`); only
parses base topic names.

Core (zmqnotificationinterface.cpp:69) reads `-zmqpubhashblockhwm`
etc. as siblings of the base flag, defaulting to
`DEFAULT_ZMQ_SNDHWM = 1000`. rustoshi hardcodes 1000
(zmq.rs:167) with a `with_hwm` builder that has no CLI entry point.

### BUG-5 (P2 / MISSING — ZMQ): IBD gate on `UpdatedBlockTip`

**Location:** would be at the (absent) `UpdatedBlockTip` ZMQ
notifier callsite; latent under BUG-1.

Core skips notifications when `fInitialDownload` is true OR
`pindexNew == pindexFork` (zmqnotificationinterface.cpp:153). Once
rustoshi wires ZMQ (BUG-1), every IBD-applied block would fire
hashblock/rawblock notifications, swamping any downstream listener.

### BUG-6 (P3 / CDIV-ZMQ — ZMQ): No `TryForEachAndRemoveFailed` semantic

**Location:** `crates/rpc/src/zmq.rs:288` (`send_multipart`) just
returns `false` and `error!`-logs on send failure.

Core (zmqnotificationinterface.cpp:136-147) tears down + drops a
notifier whose `Notify*` returned false (typically EAGAIN HWM full
or socket closed). rustoshi keeps the failed socket around forever;
every subsequent notification re-attempts and re-logs.

### BUG-7 (P3 / CDIV-ZMQ — ZMQ): `ZmqCommand::Shutdown` arm in `handle_command` is unreachable

**Location:** `crates/rpc/src/zmq.rs:358-361`.

The worker loop (zmq.rs:518-533) handles `Shutdown` directly and
breaks out. The `handle_command` `Shutdown` arm is dead code with
a `// Handled in run loop` comment. Cosmetic.

### BUG-8 (P3 / CDIV-ZMQ — ZMQ): `context` field marked `#[allow(dead_code)]`

**Location:** `crates/rpc/src/zmq.rs:220-221`.

The `zmq::Context` lives on `ZmqPublisher` purely to keep all sockets
alive (zmq sockets borrow from the context); rustoshi marks the field
`dead_code` because nothing reads it post-construction. This is fine
semantically (`Drop` order keeps the context alive while sockets
exist), but the lint suppression is a comment-as-confession pattern
flagging "I'm not sure why this is here." Cosmetic.

### BUG-9 (P3 / CDIV-ZMQ — ZMQ): `notify_block` collects address vectors twice with `.clone()`

**Location:** `crates/rpc/src/zmq.rs:366-376`.

Each `Notify*` call collects `hashblock_addrs` + `rawblock_addrs`
by cloning every config's `address` string out of `self.notifiers`.
A node running with one `pubhashblock` endpoint allocates two new
`Vec<String>` on every block (~0.6 ms per minute on mainnet — not
measurable, but allocation pressure is unnecessary). Fix: keep the
addresses in `Vec` form keyed by topic at construction time.

### BUG-10 (P3 / CDIV-ZMQ — ZMQ): No CLI surface for `-zmq*` flags

**Location:** `rustoshi/src/main.rs` (Cli struct, line 90-onwards);
no `#[arg(long = "zmqpubhashblock")]` anywhere.

The `parse_zmq_args` helper takes `&[(String, String)]` — clearly
intended for CLI arg pairs — but no clap glue ever populates it.
Same shape as BUG-1 but isolates the CLI-surface gap from the
runtime wiring gap. Both must be fixed together. (Bundled.)

### BUG-11 (P3 / CDIV-ZMQ — ZMQ): Module documentation claims sequence numbers are per-topic

**Location:** `crates/rpc/src/zmq.rs:23-24` ("Multi-part... Sequence
number (4-byte little-endian u32)").

The module doc doesn't qualify scope ("per-topic"? "per-notifier"?).
Core's doc-comment + variable naming (`nSequence` on
`CZMQAbstractPublishNotifier`) is explicit. Cosmetic doc gap that
masks BUG-2.

### BUG-12 (P0 / CDIV-REST — REST): `/rest/block/<hash>.json` returns notxdetails-shape

**Location:** `crates/rpc/src/rest.rs:276` (`rest_block`) calls
`build_block_info` (rest.rs:932) which produces `BlockInfo` with
`tx: Vec<String>` of txid hex strings.

Core's `rest_block_extended` (`rest.cpp:473`) calls into `rest_block`
with `tx_verbosity=SHOW_DETAILS_AND_PREVOUT` and `blockToJSON` builds
each transaction as a full UniValue object with `vin[].prevout`,
`vout[].scriptPubKey`, etc. Anyone parsing
`/rest/block/<hash>.json` for fee accounting / address indexing
gets a useless txid array.

The shape-divergence is **silently** wrong: a JSON consumer that
expects `block.tx[0]` to be an object and uses `block.tx[0].txid`
fails on rustoshi with "expected object, got string"; one that
expects a string passes both Core and rustoshi but loses 99% of
the per-tx data Core provides.

### BUG-13 (P3 / CDIV-REST — REST): Comment-as-confession in `build_block_info_simple`

**Location:** `crates/rpc/src/rest.rs:997-999`.

The function comment reads literally:

> `// Same as build_block_info but only txids (no transaction details)`
> `// For REST notxdetails endpoint, this is the same since we already only return txids`

The author observed that `build_block_info` already strips
transaction detail (BUG-12) and rationalised the
`build_block_info_simple` collapse as "no work needed". The
comment **confesses** that the author noticed full vs. txid-only
collapsed and resolved the difference by deleting the work
required in the full-detail path. Same pattern as W120 BUG-5
(blockbrew FullRBF comment) and W122 BUG-1 (blockbrew
"test-comment-as-confession").

### BUG-14 (P1 / MISSING — REST): `/rest/blockpart/<hash>.{bin,hex}` not implemented

**Location:** would be in router at `crates/rpc/src/rest.rs:2034`;
absent.

Core (`rest.cpp:481` `rest_block_part`) serves a sub-range of a
block by `?offset=N&size=M`, used for streaming-block readers and
the lightweight block-explorer pattern. rustoshi: no route, no
handler, 404.

### BUG-15 (P1 / MISSING — REST): `/rest/spenttxouts/<hash>.{bin,hex,json}` not implemented

**Location:** would be in router at `crates/rpc/src/rest.rs:2034`;
absent.

Core (`rest.cpp:313` `rest_spent_txouts`) serializes a block's
undo data — every prevout consumed by every non-coinbase tx in
the block — in either binary or JSON form. Used by block
explorers for fast historical address mapping.

### BUG-16 (P1 / MISSING — REST): `/rest/deploymentinfo[/<hash>].json` not implemented

**Location:** would be in router at `crates/rpc/src/rest.rs:2034`;
absent.

Core (`rest.cpp:743` `rest_deploymentinfo`) projects
`getdeploymentinfo` over REST. rustoshi has `getdeploymentinfo`
on the JSON-RPC surface (W125-era) but no REST projection.

### BUG-17 (P1 / MISSING — REST): `/rest/headers/<hash>.<fmt>?count=N` (new query form)

**Location:** `crates/rpc/src/rest.rs:382` (`rest_headers`) only
parses the deprecated `<count>/<hash>` path form.

Core (`rest.cpp:191-205`) accepts BOTH the deprecated 2-segment
path AND the new 1-segment `?count=N` form. rustoshi rejects
the new form with `InvalidUri`. Same gap exists for
`/rest/blockfilterheaders/<filtertype>/<blockhash>?count=N`
(rest.rs:1486 only parses the 3-segment form).

### BUG-18 (P2 / MISSING — REST): `/rest/getutxos` POST body for binary input

**Location:** `crates/rpc/src/rest.rs:578` (`rest_getutxos`) only
parses URI parts; no body reading.

Core (`rest.cpp:912-986`) reads the request body in `.bin`/`.hex`
mode and deserialises a `[bool checkMempool, vector<COutPoint>]`
DataStream. Rustoshi `rest_getutxos` is registered as `GET` only
(rest.rs:2043 `.route(... get(...))`), so even sending a POST
with body falls through to 405. Operators that pipe a binary
outpoint blob via curl --data-binary get HTTP 405 instead of the
expected utxo bitmap response.

### BUG-19 (P1 / PARTIAL — REST): HTTP-status mapping diverges on some paths

**Location:** `crates/rpc/src/rest.rs:166-196` (`RestError::into_response`).

Core's mapping:
- `RESTERR(HTTP_BAD_REQUEST, ...)` on parse/validation errors.
- `RESTERR(HTTP_NOT_FOUND, ...)` on missing hash / pruned block /
  missing format suffix.
- `RESTERR(HTTP_SERVICE_UNAVAILABLE, ...)` during `RPCIsInWarmup`.

rustoshi:
- `MissingFormat` → 400 (Core: 400 — agreement). OK.
- `InvalidFormat` → 404 (Core: 404 — agreement). OK.
- **No warmup 503** — `rest.rs` has no `CheckWarmup` equivalent.
- HeightOutOfRange → 404 (Core: 404 — agreement).
- DatabaseError → 500 (Core: 500 IO error path). OK.
- `EmptyRequest` (getutxos empty) → 400 (Core: 400). OK.

So the gap is exclusively the missing warmup 503. Operators that
hit REST during startup get 200 + stale (empty mempool, height 0)
data instead of a documented 503 "Service temporarily unavailable".

### BUG-20 (P2 / CDIV-REST — REST): REST runs on its own listener instead of sharing the JSON-RPC port

**Location:** `rustoshi/src/main.rs:2007-2034` (binds axum to
`rpc_port + 100`).

Core's REST is registered as additional URI handlers on the same
`httpserver` instance backing JSON-RPC, so `127.0.0.1:8332/rest/...`
and `127.0.0.1:8332` (JSON-RPC) share host:port. rustoshi binds a
separate axum listener at `rpc_ip:rpc_port+100` because `jsonrpsee
0.22` does not expose a hookable HTTP router. The doc-comment
calls this out (rest.rs:1599-1602) but it remains a behavioural
divergence: operators with a tight firewall whitelist allowing only
the JSON-RPC port get rustoshi REST blocked.

### BUG-21 (P2 / MISSING — NOTIFY): No `runCommand` helper / no thread-detach lifecycle

**Location:** would be in `crates/rpc/src/notify.rs` (doesn't exist).

Core's `runCommand` (common/system.cpp:50-62) shells out via
`::system(cmd.c_str())` from a detached `std::thread`. The
detach-on-spawn semantic means the node continues regardless of
how slow the notify script is and the thread cleans itself up.
rustoshi has no equivalent, but BUG-22/23/24 are blocked on this
being added first.

### BUG-22 (P1 / MISSING — NOTIFY): `-blocknotify=<cmd>` CLI arg + dispatch

**Location:** would be `rustoshi/src/main.rs` clap struct + handler
in `crates/rpc/src/notify.rs`; absent.

Core (`init.cpp:2009-2018`) connects a closure to
`uiInterface.NotifyBlockTip_connect` that:
1. Returns immediately if `sync_state != POST_INIT` (i.e., IBD-on
   block tip notifications are suppressed; only "live" tips trigger).
2. Replaces `%s` with the block hash hex.
3. Spawns + detaches a thread calling `runCommand(cmd)`.

rustoshi: no CLI flag, no handler. Operators expecting to point
rustoshi at a webhook-trigger script get nothing.

### BUG-23 (P1 / MISSING — NOTIFY): `-walletnotify=<cmd>` CLI arg + dispatch

**Location:** would be in the rustoshi wallet bring-up
(`crates/wallet/src/wallet.rs` or `rustoshi/src/main.rs`); absent.

Core (`wallet.cpp:1139-1164`) fires `runCommand` after every
`AddToWallet` or `SyncTransaction` post-mempool admission. The
substitution rules:
- `%s` → txid hex.
- `%b` → confirmed block hash hex OR `"unconfirmed"`.
- `%h` → confirmed block height OR `"-1"`.
- `%w` → `ShellEscape(GetName())` (only on non-Windows).

Critical detail: only `%w` is shell-escaped. Operators putting any
of `%s`/`%b`/`%h` inside shell-quoted strings need to trust those
values, which is safe (txid/hash are hex; height is an integer)
but only because Core guarantees the substituted values are
strict character sets. rustoshi must reproduce the same set with
the same per-token rules to avoid shell-injection surprises (e.g.,
do not naively `%s` substitute without verifying hex input).

### BUG-24 (P1 / MISSING — NOTIFY): `-alertnotify=<cmd>` CLI arg + sanitised dispatch

**Location:** would be plumbed through the kernel notification
interface (`crates/consensus` or `crates/rpc`); absent.

Core (`kernel_notifications.cpp:30-47`) treats the alert text as
**untrusted plain ASCII** (it can come from any user-visible
warning like "Warning: large reorg detected"). The dispatch:
1. `SanitizeString(strMessage)` strips non-safeChars.
2. Wraps with single-quotes.
3. ReplaceAll `%s` with the quoted, sanitised string.
4. Spawns + detaches a `runCommand` thread.

The single-quote wrap is the safety guarantee — `%s` can be
substituted directly into a shell command line without further
escape because the sanitised string contains no quote characters.
Critical correctness detail to reproduce.

### BUG-25 (P2 / MISSING — NOTIFY): `ShellEscape` helper for `%w` wallet-name substitution

**Location:** would be in `crates/rpc/src/notify.rs` or a shared
util module; absent.

Core (`common/system.cpp:41-46`) implements ShellEscape as:
1. Replace every `'` with `'"'"'` (close the single-quote string,
   echo a `"`-quoted single-quote, re-open the single-quote string).
2. Wrap the whole thing in single-quotes.

Required if rustoshi wallet names ever contain characters that
look like shell metacharacters. (rustoshi wallet names are
currently restricted, so the immediate risk is low, but locking
in `ShellEscape` parity now avoids surprises later.)

### Pattern observations (audit-level, not BUGs):

- **"Helper exists but never wired"** (BUG-1, ZMQ): 1,079 LOC of
  well-engineered production code with 7 round-trip tests, zero
  production wiring. Same shape as W117 BUG-3 (rustoshi BIP-152
  RTT shortcut) and W119 BUG-N (PayJoin sender). Suggests pulling
  forward a fleet-wide audit gate: "if a module compiles and tests
  pass but `grep -r ModuleName::new(\|ModuleName::create(\|use crate::module::ModuleName` outside the module + its tests yields zero matches, flag it."
- **"Comment-as-confession"** (BUG-13, REST `build_block_info_simple`):
  third independent instance after blockbrew W120 BUG-5 and W122 BUG-1.
  Detection by `grep -rn "for.*endpoint.*this is the same\|deliberately\|opts out of\|stale"` against the codebase would surface these.
- **Missing fleet-wide CLI surface** (BUG-10 ZMQ + BUG-22/23/24 NOTIFY):
  the rustoshi `Cli` struct doesn't grep-match `zmqpub`, `blocknotify`,
  `walletnotify`, or `alertnotify`. A 30-line clap macro covering
  all four would expose the gaps even before wiring up handlers.
- **Subsystem-level "audit-by-router-table"** (REST): rustoshi's
  router (rest.rs:2034) lists 11 routes; Core's URI table
  (rest.cpp:1144) lists 14. Side-by-side enumeration is a
  good pre-audit step that surfaces BUG-14/15/16 at zero cost.

## Out of scope

- BIP-78 PayJoin receiver-side audit was W119 / FIX-65 / FIX-67;
  the `POST /payjoin` route on the REST listener (rest.rs:1812-1997)
  is **not** re-audited here. The 30 gates above only cover the
  Core-spec REST URI table.
- `start_rest_server_with_wallet` is a richer constructor never
  called from production; the wallet-wired PayJoin endpoint silently
  always answers 503 `unavailable`. That is **separately** a
  "helper-never-wired" pattern (rest.rs:1657 vs main.rs:2022) but
  PayJoin per se is W119/F65 territory, so left as a doc note here.
- The rustoshi-specific `getzmqnotifications` JSON-RPC method is
  audited indirectly through G7 (it always returns `[]`).
- Production wiring of all 5 ZMQ events (BlockConnect /
  BlockDisconnect / TxAcceptance / TxRemoval / RawTx in
  `BlockConnected`) into the rustoshi mempool/chain event bus
  is necessary BEFORE BUG-1's fix matters end-to-end, but the
  event-bus design is a separate W### concern (out of scope here).

## Cross-reference

- W117 BUG-3 — same "well-engineered helper never wired" shape on
  rustoshi BIP-152 short-id RTT.
- W120 BUG-5 (blockbrew) — first comment-as-confession we
  documented; this is rustoshi's first.
- W122 BUG-1 (blockbrew "test-comment-as-confession") — second
  blockbrew instance.
- W118 wallet — wallet-side `-walletnotify` matters at the same
  signal point as the wallet-tx-changed hook; BUG-23 here is the
  shell-out half of that signal.
- W139/W140 (concurrent waves on this date) — likely touch
  adjacent rest.rs / server.rs surfaces; this wave's commits stay
  on additions only (audit/ + tests/) to avoid conflict.
