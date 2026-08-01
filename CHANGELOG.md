# Changelog

All notable changes to rustoshi are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release of rustoshi, a Bitcoin full node written from scratch in
Rust, validated for Bitcoin Core v31 behavior parity across consensus, policy,
P2P, RPC, and wallet surfaces.

### Highlights

- Full block and transaction validation (BIP-16, BIP-34, BIP-65, BIP-66,
  BIP-68, BIP-141, BIP-143, BIP-146, BIP-147) with an interpreter covering
  P2PKH, P2SH, P2WPKH, P2WSH, and P2TR.
- Headers-first sync with parallel block downloads, stall detection, and a
  P2P liveness watchdog.
- Multi-layer UTXO cache over RocksDB with atomic flush-with-tip semantics;
  flat-file block storage with Core-compatible pruning.
- Cluster mempool with Core v31 limits and v31 relay-fee defaults
  (100 sat/kvB), package relay (1p1c), full-RBF, and ephemeral anchors.
- BIP-152 compact blocks (v2/wtxid), BIP-324 v2 encrypted transport,
  BIP-155/157/158 light-client services.
- HD wallet (BIP-32/44/84/86), Miniscript, PSBT (BIP-174/370), and output
  descriptors (BIP-380-386).
- AssumeUTXO snapshot boot and a faithful Core-ladder assumevalid gate.

### Fixed since v0.1.0-rc1

- consensus: unconditional P2SH|WITNESS|TAPROOT script flags with Core's
  replace-then-OR semantics; deleted the hash-blind `consensus_flags` decoy.
- consensus: opcode-aligned FindAndDelete + pre-segwit unexpected-witness
  gate (Core `IsBlockMutated` / `CheckWitnessMalleation` parity).
- consensus/rpc: submitblock and side-branch store paths enforce
  `ContextualCheckBlockHeader` (bad-diffbits, bad-version, time-too-old/new),
  matching Core `AcceptBlockHeader` reject-before-index.
- shutdown: never regress the durable tip on graceful flush (P1.6).
- wallet: BIP-86 taproot receive + spend; imported private descriptors sign
  with the correct key; refuse SIGHASH_ALL|ANYONECANPAY instead of silently
  signing SIGHASH_ALL.
- p2p: max-inbound cap + eviction on the accept path; BIP-339 wtxid inv
  handling; bounded `getblocktxn` depth; BIP-157 checked arithmetic;
  bounded untrusted decoder allocations (fuzz-found P1s).
- rpc: `logging` and `getmemoryinfo` RPCs (Core node.cpp parity);
  Core-exact BIP-22 reject tokens (`bad-blk-length`, `bad-blk-weight`, …);
  `getdescriptorinfo` checksum over the input as given; `deriveaddresses`
  range inclusive of end.
- net: v2 transport long-form message-type validation — non-printable-ASCII
  command bytes and non-NUL padding after the first NUL are rejected, matching
  Core `V2Transport::GetMessageType`.
- policy: Core v31 relay-fee defaults (1000 → 100 sat/kvB) and cluster
  mempool limits (weight units, >404000, >64).

### Release engineering

- Workspace version bumped to 1.0.0; P2P user-agent and RPC subversion now
  advertise `/Rustoshi:1.0.0/`.
- CI (`.github/workflows/ci.yml`) and release
  (`.github/workflows/release.yml`) workflows re-enabled.
- Test suite brought to green: stale fixtures repaired to post-gate Core
  behavior (compact-block reconstruction, mempool sigops cost, coin-selection
  signing, submitblock/reorg low-difficulty chains), sentinel tests
  re-anchored, and closed audit gaps (G21 `logging`, G30 `getmemoryinfo`)
  converted to positive regression pins.

## [0.1.0-rc1] - 2026-07-22

Initial release candidate (unsigned tag, retained for history).
