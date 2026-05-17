# W123 — Mining / GBT / BlockAssembler / BIP-152 parity audit (rustoshi)

**Wave**: W123 (Mining / GBT parity DISCOVERY)
**Impl**: rustoshi (Rust)
**Audit date**: 2026-05-17
**Reference**: `bitcoin-core/src/{node/miner.cpp, rpc/mining.cpp, policy/feefrac.cpp, blockencodings.cpp}`; BIP-22 / BIP-23 / BIP-141 / BIP-152.

## Scope

30 gates across the full mining stack:

- BlockAssembler / `build_block_template` (transaction selection, weight, sigops, witness commitment, coinbase, anti-fee-sniping)
- mining RPCs (`getblocktemplate`, `submitblock`, `getmininginfo`, `prioritisetransaction`, `getnetworkhashps`)
- BIP-141 witness commitment
- BIP-152 compact block (`sendcmpct` / `cmpctblock` / `getblocktxn` / `blocktxn`)
- cluster-mempool `ImprovesFeerateDiagram` for block-builder ordering
- configuration plumbing (`-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`, `-blockversion`)

## Summary

| Status | Count | Gates |
|--------|------:|-------|
| PRESENT | 10 | G1, G2, G7, G9, G10, G12, G15, G17, G19, G24 |
| PARTIAL | 7  | G3, G5, G6, G14, G16, G22, G29 |
| MISSING | 13 | G4, G8, G11, G13, G18, G20, G21, G23, G25, G26, G27, G28, G30 |

**20 bugs** (PARTIAL + MISSING): **0 × P0** / **1 × P1** / **8 × P2** / **9 × P3** / **2 × P4**.

Five gates are carry-forwards of prior W108 / W106 audit findings that the W123 framework re-frames against the mining stack (G3↔W108 G11, G4↔W108 G8, G5↔W106 G8 follow-up, G18↔W108 G27, G20↔W106 G20, G22↔W108 G3, G28↔W108 G4/G5).

## Per-gate findings

### PRESENT (10)

| Gate | Surface | Location |
|------|---------|----------|
| G1   | block weight 4_000_000 enforced as absolute ceiling                | `crates/consensus/src/params.rs:59` + `block_template.rs:393` |
| G2   | block sigops cost 80_000 enforced                                  | `params.rs:77` + `block_template.rs:413` |
| G7   | coinbase locktime = height-1, sequence = MAX_SEQUENCE_NONFINAL     | `block_template.rs:608-619, 627` |
| G9   | block-reward halving every 210_000 blocks (Core schedule)          | `params.rs::block_subsidy:298` |
| G10  | BIP-34 height encoded; OP_0 dummy appended at heights 1-16         | `block_template.rs:579-581` (Core miner.cpp:187-193) |
| G12  | BIP-152 compact block codec (v1 + v2, SipHash-2-4 short IDs)       | `crates/network/src/compact_blocks.rs:30-200` |
| G15  | BIP-152 wire dispatch (sendcmpct/cmpctblock/getblocktxn/blocktxn)  | `crates/network/src/{message.rs, v2_transport.rs}` + `rustoshi/src/main.rs:3826,3874,3950` |
| G17  | nonce reset to 0 in template; extranonce via coinbase_extra_data   | `block_template.rs:518` + `BlockTemplateConfig::coinbase_extra_data` |
| G19  | segwit serialization in template (txid + wtxid distinct emitted)   | `server.rs:4190-4191`; BIP-141 / BIP-144 |
| G24  | block_min_fee_rate (DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/vB) STOPs loop | `block_template.rs:383` (Core miner.cpp:298-300) |

### PARTIAL (7)

| Gate | Severity | Gap | Location |
|------|---------|-----|----------|
| G3   | P2-CDIV | witness commitment omitted when segwit active + no witness txs (Core ALWAYS emits via `GenerateCoinbaseCommitment`). Carry-forward W108 G11. | `block_template.rs:586,598` |
| G5   | P3      | FIX-72 incorporated `get_modified_fee` for single-entry rank, but ancestor-fee aggregation still uses raw `entry.ancestor_fees` (mempool.rs:2349-2351). CPFP fee-bump on an ancestor does not propagate. | `block_template.rs:344-345` |
| G6   | P2      | selection loop pops one tx at a time; no atomic per-chunk (cluster linearization) admission as in Core `addChunks` + `GetBlockBuilderChunk`. | `block_template.rs:372` |
| G14  | P2      | `CmpctBlock::from_block` invoked only in `#[cfg(test)]` paths — no send-side production cmpctblock announce. We RECEIVE compact blocks but never SEND them. | `crates/network/src/compact_blocks.rs:109` + missing send-side wiring in `rustoshi/src/main.rs` |
| G16  | P3      | `sendcmpct` sent ONCE during handshake (peer.rs:1241); no dynamic HB-mode promotion via `sendcmpct(announce=true)` as Core's `SendSendCmpct` does. | `crates/network/src/peer.rs:1241` |
| G22  | P3      | template refreshes on every call (short-poll OK), but no BIP-22/23 long-poll subscription. longpollid emitted but format is wrong (carry-forward W108 G3). | `server.rs:4311` |
| G29  | P2-CDIV (theoretical) | legacy sigops × WITNESS_SCALE_FACTOR approximation only; P2SH + witness sigops not accounted. Validation uses same approximation so block ↔ template are consistent within rustoshi, but a third-party validator running accurate sigops would reject. | `block_template.rs:404-408` |

### MISSING (13)

| Gate | Severity | Surface absence | Location |
|------|---------|-----------------|----------|
| G4   | P2  | `weight_fails` compares against `MAX_BLOCK_WEIGHT` (absolute) not `config.max_weight` (clamped). No `ClampOptions` equivalent. Carry-forward W108 G8. | `block_template.rs:393` |
| G8   | **P1** | **GBT response `transactions[].fee` hardcoded to `0`** (Core mining.cpp:926: `tx_fees.at(index_in_template)`). `BlockTemplate` has no `per_tx_fees` vector. Mining pools that filter by per-tx fee see every tx as zero-fee. | `server.rs:4193` |
| G11  | P2  | GBT response `transactions[].depends` hardcoded to `[]` (Core mining.cpp:917-923 builds `setTxIndex: txid→idx` and pushes deps). BIP-22 requires this when `transactions` is mutable (it is — server.rs:4317). | `server.rs:4192` |
| G13  | P3  | GBT response has no `capabilities` array (Core mining.cpp:946-948 emits `["proposal"]`). Consistent with G28 absence. | `crates/rpc/src/types.rs:585` |
| G18  | P3  | no `m_last_block_weight` / `m_last_block_num_txs` tracking → `getmininginfo.currentblockweight` + `currentblocktx` absent (Core miner.cpp:159-160 + mining.cpp:467-468). Carry-forward W108 G27. | `MiningInfo` struct (types.rs:545-587) |
| G20  | P2  | no `GetBlockBuilderChunk` equivalent. Block builder uses single-tx priority pop; cluster linearizations exist (mempool.rs:481 `DepGraph::linearize`) but the block-builder bypasses them. Carry-forward W106 G20. | `block_template.rs:372` |
| G21  | P3  | no `-blockmaxweight` CLI / config plumb (Core miner.cpp:101). | (search returns zero hits across `crates/`/`rustoshi/src/`) |
| G23  | P3  | no TRUC topology re-check at block builder. Mempool admission catches it; defense-in-depth at the builder is absent. | `block_template.rs:330` |
| G25  | P4  | no `-blockmintxfee` CLI / config plumb (Core miner.cpp:102-104). | (same — no plumb) |
| G26  | P4  | BIP-23 `workid` round-trip absent (no field in template result; submitblock ignores 2nd arg). W108 G25 carry-forward. | `server.rs:4331` |
| G27  | P3  | **`getmininginfo.networkhashps` hardcoded `0.0`** (server.rs:4660 comment: "would need to compute from recent blocks"). The `getnetworkhashps` RPC IS implemented separately (server.rs:7933) — `getmininginfo` just doesn't call it. | `server.rs:4660` |
| G28  | P2  | `getblocktemplate` `_params` is a dead parameter (server.rs:4067) — no `mode='proposal'` dispatch, no rules-array enforcement, no longpollid parse. Carry-forward W108 G4/G5. | `server.rs:4067` |
| G30  | P3  | `BlockTemplate.m_package_feerates` equivalent missing (Core miner.cpp:327 records per-chunk FeePerVSize). Closes off package-mining integrations. | `crates/consensus/src/block_template.rs::BlockTemplate` |

## Universal patterns (W123)

1. **GBT response shape is solid; per-tx fields are stubbed** — G8 (`fee=0`), G11 (`depends=[]`), G13 (no `capabilities`). The struct exists, the wire is correct, the per-tx arrays are placeholders. Pattern: "well-engineered wire, gaps at the per-entry slot" — matches W121 universal finding 7 (codec correct, service layer empty) shifted from network → RPC.

2. **Block-builder selection is per-tx, not per-cluster-chunk** — G6 + G20 are the same finding from two angles. rustoshi has cluster-mempool linearizations (mempool.rs:481) but the block-builder ignores them. This is a `dead-helper-at-builder-call-site` instance — continuation of W120 / W121 dead-helper streak (33+ waves).

3. **CLI / config plumbing absent for mining tunables** — G21 (-blockmaxweight), G25 (-blockmintxfee). The struct fields exist; the CLI parse paths don't. Same shape as several W121 findings ("plumb-gate" missing).

4. **`m_last_block_*` mining counters never tracked** — G18 (carry-forward W108). Cheap to add; observable from monitoring.

5. **Compact block: well-engineered codec, send-side never wired** — G14: `CmpctBlock::from_block` exists with full BIP-152 v1+v2 support but is invoked only in tests. Continues the "well-engineered helper, never wired in prod" pattern (rustoshi W121 BUG-16 BlockFilterIndex ~6500 LOC unreachable; this is a much smaller version but same shape).

6. **Carry-forwards from earlier audits** — 5 gates (G3, G4, G18, G20, G22, G28) re-surface W106/W108 findings. Mining stack has accumulated 5 unfixed gates since W108 (2026-04) that don't materially regress consensus but degrade pool / monitoring interop.

## Top 3 priority findings

1. **G8 (P1) — GBT response `transactions[].fee` hardcoded to 0** at `crates/rpc/src/server.rs:4193`. This is the most impactful new finding — mining pools that filter or shape templates by per-tx fee see every entry as zero-fee. Fix requires adding `per_tx_fees: Vec<u64>` to `BlockTemplate` parallel to `per_tx_sigops`, populated by `build_block_template` from `entry.fee`. ~30 LOC.

2. **G14 (P2) — `cmpctblock` send-side absent**. We receive compact blocks (main.rs:3826) but never send them. After mining a block (or relaying one), HB-mode peers expect a `cmpctblock` from us; they get a `headers` and then have to `getdata` for the full block — defeats the purpose of BIP-152. Fix requires wiring `CmpctBlock::from_block` into the relay pipeline and a `MaybeSendBlockAnnounce` equivalent.

3. **G6 + G20 (P2) — block-builder is per-tx not per-cluster-chunk**. Cluster linearizations are computed and stored but the block-builder bypasses them with a single-tx priority pop. Under adversarial mempool topology (a descendant with higher ancestor feerate than its parent's chunk), the wrong ordering could miss higher-feerate clusters. Same root cause as W106 G20 (cluster-mempool integration partial); converging fix would close both.

## Test layout

`crates/consensus/tests/test_w123_mining_gbt.rs` — 35 `#[test]` functions:
- 15 PRESENT tests pass (real assertions, BIP-22/BIP-141/BIP-152 invariants pinned + supporting tests)
- 20 BUG/MISSING/PARTIAL tests `#[ignore]`d with `panic!` prose + Core line references

```
cargo test --test test_w123_mining_gbt -p rustoshi-consensus
> 15 passed; 0 failed; 20 ignored
```

## References

- `bitcoin-core/src/node/miner.cpp` (BlockAssembler, CreateNewBlock, addChunks, TestChunkBlockLimits)
- `bitcoin-core/src/rpc/mining.cpp` (getblocktemplate, submitblock, getmininginfo, prioritisetransaction, getnetworkhashps)
- `bitcoin-core/src/policy/feefrac.cpp` (cluster-mempool feerate diagram)
- `bitcoin-core/src/blockencodings.cpp` (BIP-152 CmpctBlock)
- BIP-22 (getblocktemplate)
- BIP-23 (getblocktemplate Pooled Mining: workid / longpoll / proposal)
- BIP-141 (witness commitment)
- BIP-152 (compact block relay)
- W106 (mempool) — carry-forwards G8, G20
- W108 (GBT) — carry-forwards G3 (was G11), G4 (was G8), G18 (was G27), G22 (was G3), G28 (was G4/G5)
