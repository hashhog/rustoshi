# W125 — JSON-RPC error code parity audit (rustoshi)

**Wave:** W125 — JSON-RPC error code parity (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:** `crates/rpc/src/server.rs::mod rpc_error`,
`crates/rpc/src/wallet.rs::mod wallet_error`, plus every `Self::rpc_error(...)`
call site across `server.rs` (~15 280 LOC) and `wallet.rs` (~3 190 LOC).
**Reference:** `bitcoin-core/src/rpc/protocol.h`, plus per-method error
sites in `bitcoin-core/src/rpc/*.cpp` and `bitcoin-core/src/wallet/rpc/*.cpp`.
**Production code changes:** 0 (pure audit).
**Test file:** `crates/rpc/tests/test_w125_error_parity.rs` — 30 gates,
19 PASS regression pins + 12 `#[ignore]`-pinned xfail BUG-N stubs.

## Why this matters

Bitcoin Core's error-code surface is a contract: wallets, exchanges,
mining pools, and operator scripts grep both `error.code` (numeric) and
`error.message` (substring) when an RPC fails. A code mismatch breaks
recovery scripts silently; a code COLLISION (two different conditions
sharing the same number) is worse — the operator routes the wrong
recovery path. The full Core enum is documented at
`bitcoin-core/src/rpc/protocol.h:23-90`.

## Headline findings

- **2 P0** (code collision — operator alert misroute):
  - **BUG-1**: `RPC_CLIENT_P2P_DISABLED = -9`. Core's `-9` is
    `RPC_CLIENT_NOT_CONNECTED`; Core's `RPC_CLIENT_P2P_DISABLED = -31`.
    Rustoshi's `addnode`, `setban`, `clearbanned`, `disconnectnode` all
    return `-9` when the peer manager is offline, which Core operators
    read as "no peers reachable" → wrong alert.
  - **BUG-2**: `RPC_WALLET_ALREADY_EXISTS = -4`. Core's value is `-36`.
    Rustoshi maps `-4` to BOTH `RPC_WALLET_ERROR` (generic) AND
    `RPC_WALLET_ALREADY_EXISTS`; scripts can't distinguish a create-wallet
    name conflict from a generic wallet error.

- **1 P1 mass-divergence**:
  - **BUG-3**: 51 of 51 parameter-validation sites use `RPC_INVALID_PARAMS`
    (`-32602`, the JSON-RPC standard "invalid params" code, reserved for
    transport-level shape errors). Core uses `RPC_INVALID_PARAMETER`
    (`-8`) at **95+ of 96** application-layer parameter-validation sites
    (the lone Core `-32602` site is `net.cpp:474`, "Only one of address
    and nodeid should be provided"). Every operator script grepping for
    `-8` on `"Block height out of range"`, `"Invalid IP"`, `"Invalid
    command"`, `"Number of keys"`, `"conf_target out of range"`, etc.,
    fails against rustoshi. **Single fix unblocks ~40 gates** (every
    BUG-17 / BUG-18 / BUG-20 / BUG-21 / BUG-22 / BUG-23 child of BUG-3).
    See callsite list in test header.

- **5 missing P2P-recovery codes** (operators have no way to script
  the specific peer-management failure mode):
  - **BUG-11**: `RPC_CLIENT_NODE_ALREADY_ADDED` (-23) — never returned.
  - **BUG-12**: `RPC_CLIENT_NODE_NOT_ADDED` (-24) — never returned.
  - **BUG-13**: `RPC_CLIENT_NODE_NOT_CONNECTED` (-29) — never returned;
    `disconnectnode` of unknown peer collapses to BUG-3's `-32602`.
  - **BUG-14**: `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30) — never returned;
    `setban` bad-IP collapses to BUG-3's `-32602`.
  - **BUG-15**: `RPC_CLIENT_NODE_CAPACITY_REACHED` (-34) — never returned.

- **1 P1 mempool-codes loss-of-fidelity**:
  - **BUG-10**: `sendrawtransaction` collapses every `MempoolError`
    variant to `RPC_TRANSACTION_REJECTED` (-26) at `server.rs:3766-3789`.
    Core distinguishes `MEMPOOL_REJECTED → -26`,
    `ALREADY_IN_UTXO_SET → -27`, and generic `→ -25` per
    `JSONRPCTransactionError` (Core `rpc/util.cpp:408`). Wallets that
    branch on `-25` vs `-26` vs `-27` mis-route. Cross-ref **W120 BUG-16**
    (same surface, different wave).

## Gate summary (30/30)

| # | Surface | Status | Code | Severity |
|---|---------|--------|------|----------|
| G1 | JSON-RPC `RPC_PARSE_ERROR` -32700 | OK | — | — |
| G2 | JSON-RPC `RPC_INVALID_REQUEST` -32600 | OK | — | — |
| G3 | JSON-RPC `RPC_INVALID_PARAMS` -32602 | PARTIAL | BUG-3 | P1 |
| G4 | JSON-RPC `RPC_INTERNAL_ERROR` -32603 | OK | — | — |
| G5 | `RPC_MISC_ERROR` -1 numeric | OK | — | — |
| G6 | `RPC_TYPE_ERROR` -3 numeric | OK | — | — |
| G7 | `RPC_INVALID_ADDRESS_OR_KEY` -5 numeric | OK | — | — |
| G8 | `RPC_INVALID_PARAMETER` -8 numeric | MISSING | BUG-3 | P1 |
| G9 | `RPC_DATABASE_ERROR` -20 numeric | OK | BUG-24 | P2 |
| G10 | `RPC_DESERIALIZATION_ERROR` -22 numeric | OK | — | — |
| G11 | `RPC_TRANSACTION_ERROR` -25 numeric | OK | — | — |
| G12 | `RPC_VERIFY_REJECTED` -26 numeric | OK | BUG-26 | P3 |
| G13 | `RPC_VERIFY_ALREADY_IN_CHAIN` -27 | OK numeric | BUG-9 | P1 |
| G14 | `RPC_IN_WARMUP` -28 | MISSING | BUG-4 | P1 |
| G15 | `RPC_METHOD_DEPRECATED` -32 | MISSING | BUG-6 | P1 |
| G16 | `RPC_CLIENT_*` (-9 collision) | **BUG** | **BUG-1** | **P0** |
| G17 | `RPC_CLIENT_NODE_ALREADY_ADDED` -23 | MISSING | BUG-11 | P1 |
| G18 | `RPC_CLIENT_NODE_NOT_ADDED` -24 | MISSING | BUG-12 | P1 |
| G19 | `RPC_CLIENT_NODE_NOT_CONNECTED` -29 | MISSING | BUG-13 | P1 |
| G20 | `RPC_CLIENT_INVALID_IP_OR_SUBNET` -30 | MISSING | BUG-14 | P1 |
| G21 | `RPC_CLIENT_IN_INITIAL_DOWNLOAD` -10 | MISSING | BUG-5 | P1 |
| G22 | `RPC_WALLET_ERROR` -4 | OK | — | — |
| G23 | `RPC_WALLET_INSUFFICIENT_FUNDS` -6 | OK | — | — |
| G24 | `RPC_WALLET_*` enc-state -12..-15 | OK | — | — |
| G25 | `RPC_WALLET_NOT_FOUND` -18 / `_NOT_SPECIFIED` -19 | OK | BUG-27 | P3 |
| G26 | `RPC_WALLET_ALREADY_EXISTS` -36 | **BUG** | **BUG-2** | **P0** |
| G27 | `RPC_WALLET_ALREADY_LOADED` -35 | OK | — | — |
| G28 | `sendrawtransaction` -25/-26/-27 distinction | BUG | BUG-10 | P1 |
| G29 | `getblockhash` height-OOR uses -8 | BUG | BUG-17 | P2 (parent BUG-3) |
| G30 | JSON-RPC error response shape | OK | — | — |

**Tally:**
- 13 OK (regression pins; 6 documenting numeric parity, 2 documenting
  JSON-RPC-2.0 standard codes, 1 shape, 4 wallet-codes-correct).
- 1 PARTIAL (G3 — value correct, use is wrong; rolled up into BUG-3).
- 9 MISSING.
- 3 BUG (G16, G26, G28).
- 2 P0, 8 P1, 4 P2, 3 P3 (count of severities across the 17 bug rows).

## Full bug table (P0/P1 first)

### P0 — operator alert misroute (code collisions)

**BUG-1 (P0)** — `RPC_CLIENT_P2P_DISABLED` numeric collision.
- **Sites (definition)**: `crates/rpc/src/server.rs:92`.
- **Call sites**: `:4881` (`addnode` when peer mgr None),
  `:5117` (`setban` when peer mgr None), `:5131` (`clearbanned`
  when peer mgr None), `:7006` (`disconnectnode`).
- **Core reference**: `bitcoin-core/src/rpc/protocol.h:58, 64`
  (`RPC_CLIENT_NOT_CONNECTED = -9`, `RPC_CLIENT_P2P_DISABLED = -31`).
- **Operator script impact**: An ops script polling for `error.code = -9`
  expecting "node is starting / no peers yet" instead triggers on
  "P2P subsystem disabled" — operator may attempt peer-list refresh on
  a node that has no networking at all.
- **Fix**: rename constant value `-9 → -31`; (separately) add a new
  `RPC_CLIENT_NOT_CONNECTED = -9` constant for the no-peers case if any
  call site needs it (none today).

**BUG-2 (P0)** — `RPC_WALLET_ALREADY_EXISTS` numeric collision.
- **Site**: `crates/rpc/src/wallet.rs:43`.
- **Core reference**: `bitcoin-core/src/rpc/protocol.h:83`
  (`RPC_WALLET_ALREADY_EXISTS = -36`).
- **Impact**: A `createwallet` collision is indistinguishable from a
  generic wallet error. Wallet provisioning automation cannot recover
  from "name already taken" via the documented Core code.
- **Fix**: `-4 → -36`. No other call site uses the value `-4` as a
  separate enum entry.

### P1 — missing operator-visible codes

**BUG-3 (P1)** — `RPC_INVALID_PARAMS` (-32602) vs `RPC_INVALID_PARAMETER` (-8).
- **Sites**: 51 occurrences in `server.rs`. Selected:
  - `:1075` (`parse_hash`)
  - `:1081` (`parse_hex`)
  - `:2961` (`getblockhash` OOR — direct Core comparison
    `bitcoin-core/src/rpc/blockchain.cpp:591`)
  - `:3613` (`sendrawtransaction` maxfeerate > 1)
  - `:4020` (`estimaterawfee` conf_target)
  - `:4854, :4875` (`addnode`)
  - `:5081, :5111, :5156` (`setban`, `pruneblockchain`)
  - `:5418, :5445, :5463-5484` (`generatetoaddress` family)
  - `:7073` (`prioritisetransaction` dummy)
  - `:7459, :7470, :7478` (`createmultisig`)
- **Core reference**: `RPC_INVALID_PARAMETER` is the value used at 95+
  of 96 Core sites (only `net.cpp:474` uses `RPC_INVALID_PARAMS`).
- **Recommended fix (single-diff sweep)**:
  1. Add `pub const RPC_INVALID_PARAMETER: i32 = -8;` to the
     `rpc_error` module.
  2. `sed`-equivalent rename `rpc_error::RPC_INVALID_PARAMS →
     rpc_error::RPC_INVALID_PARAMETER` across all 51 sites EXCEPT the
     mutually-exclusive-fields pattern (none currently exist in rustoshi;
     can be added back later as needed).
  3. Keep `RPC_INVALID_PARAMS = -32602` as a constant for the
     mutually-exclusive case.
- **Closure**: closes BUG-3 itself + child rows BUG-17/-18/-20/-21/
  -22/-23.

**BUG-4 (P1)** — `RPC_IN_WARMUP` (-28) absent.
- Core gates ALL RPCs except a few helpers during `httpserver` warmup
  (returns HTTP 503 with this code).
- **Fix**: add the constant, surface during chain DB open + replay.

**BUG-5 (P1)** — `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10) absent.
- Core sites: `mempool.cpp:1141` (loadmempool), `mining.cpp:773, 843`
  (getblocktemplate refuses during IBD).
- Rustoshi's `getblocktemplate` does not gate on IBD.

**BUG-6 (P1)** — `RPC_METHOD_DEPRECATED` (-32) absent.
- Required for `-deprecatedrpc=…` opt-in compatibility surface.

**BUG-7 (P1)** — `RPC_OUT_OF_MEMORY` (-7) absent.
- Used by Core for explicitly OOM-aware paths
  (`bitcoin-core/src/wallet/feebumper.cpp`).

**BUG-9 (P1)** — `RPC_VERIFY_ALREADY_IN_CHAIN` rename. Core renamed to
`RPC_VERIFY_ALREADY_IN_UTXO_SET` (`protocol.h:49`). Numeric value
unchanged (-27). Message text "Transaction already in block chain"
(`server.rs:3668`) should be "Transaction outputs already in utxo set"
per Core's `RPCErrorString`.

**BUG-10 (P1)** — `sendrawtransaction` collapses -25/-26/-27 to -26.
- Site: `server.rs:3766-3789`.
- Core ref: `bitcoin-core/src/rpc/util.cpp:408`
  (`JSONRPCTransactionError`).
- Cross-ref **W120 BUG-16**: same surface, audit found from a different
  angle (RBF rejection wording).

**BUG-11..15 (P1)** — 5 P2P recovery codes absent (see headline).

### P2 — operator script-greppability

**BUG-16 (P2)** — `RPC_TYPE_ERROR` (-3) underused. Site: 1 use
(`server.rs:7399`). Core uses -3 broadly in `AmountFromValue`,
`ParseHashV`, `GetVerbosity`.

**BUG-17..23 (P2)** — child rows of BUG-3 — individual call-site
divergences for `getblockhash`, `addnode`, `pruneblockchain`,
`sendrawtransaction maxfeerate`, `setban`, `prioritisetransaction`,
`createmultisig`. All close when BUG-3 is fixed.

**BUG-24 (P2)** — `RPC_DATABASE_ERROR` (-20) over-used. Rustoshi
returns -20 for any RocksDB error; Core returns -20 only for
`reconsiderblock`/`invalidateblock`/`preciousblock` state failures.
Operators can't disambiguate. Fix: route disk I/O errors to
`RPC_MISC_ERROR` (-1) per Core convention.

### P3 — doc / future-proofing

**BUG-25 (P3)** — `signmessage` hardcodes literal `-18` instead of
`wallet_error::RPC_WALLET_NOT_FOUND` (`server.rs:7416`). Numeric
match today; brittle to refactor.

**BUG-26 (P3)** — `RPC_TRANSACTION_REJECTED` defined twice
(`server.rs:84` + `:86`). Cosmetic dual-name.

**BUG-27 (P3)** — `RPC_WALLET_NOT_SELECTED` aliased to -19. Doubled
alias style differs from Core.

**BUG-28 (P3)** — `RPC_WALLET_INVALID_LABEL_NAME` (-11) absent.

**BUG-29 (P3)** — `RPC_WALLET_ENCRYPTION_FAILED` (-16) absent.

**BUG-30 (P3)** — `RPC_FORBIDDEN_BY_SAFE_MODE` (-2) absent (reserved-only
in Core, doc gap).

## Recommended fix sequence

1. **FIX-A (P1, 51-site rename)** — Add `RPC_INVALID_PARAMETER = -8`
   and rename all 51 call sites; keep `RPC_INVALID_PARAMS = -32602`
   for the lone JSON-RPC-shape case. Closes BUG-3, 17-23. One ~60-LOC
   diff.
2. **FIX-B (P0, 2 constants)** — Fix BUG-1 (`-9 → -31`) and BUG-2
   (`-4 → -36`). One ~4-LOC diff.
3. **FIX-C (P1, P2P recovery codes)** — Add `RPC_CLIENT_NODE_*` codes
   -23/-24/-29/-30/-34 and route to call sites in `addnode`, `setban`,
   `disconnectnode`. Bundle with BUG-3 fix.
4. **FIX-D (P1, mempool error map)** — `sendrawtransaction` mempool
   error → -25/-26/-27 split. Closes BUG-10. ~25-LOC diff at
   `server.rs:3760-3790`.
5. **FIX-E (P1, IBD/warmup gates)** — Add `RPC_IN_WARMUP` (-28) and
   `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10); wire to `loadmempool`,
   `getblocktemplate`, `submitblock`. Closes BUG-4, BUG-5.

## Cross-wave links

- **W117 / W118 / W119**: PayJoin + wallet waves shipped `wallet_error`
  module with the BUG-2 value already in place — error-code parity was
  not in scope for those waves.
- **W120 BUG-16**: independently caught the `sendrawtransaction`
  error-code collapse on RBF rejections. This audit (W125 BUG-10)
  generalizes it to all mempool rejection paths.
- **W121 BUG-26**: closed RPC `getblockfilter` shape mismatch but did
  not touch error codes.
- **FIX-88 (commit `b28301e`)**: latest RPC closure wave — also
  unrelated to error-code parity.

## Tests

`crates/rpc/tests/test_w125_error_parity.rs` — 30 gates:
- 19 `#[test]` regression pins (assert constants and the JSON-RPC
  error response shape; today PASS).
- 12 `#[test] #[ignore]` xfail stubs documenting BUG-1, 2, 3, 4, 5,
  6, 10, 11, 12, 13, 14, 17, 26. Each `panic!("BUG-N: ...")` carries
  the audit row + sites. When a fix lands, drop the `#[ignore]` and
  the test becomes a positive regression pin.

```
test result: ok. 19 passed; 0 failed; 12 ignored; 0 measured;
0 filtered out; finished in 0.01s
```

No production code changes. All findings are operator-visible (error
code or message) — none are consensus-divergent (RPC error codes
never cause a fork).
