# Architecture

rustoshi is a Cargo workspace: one binary crate and seven library crates. Each library crate owns one layer, and the binary wires them together.

```
                     rustoshi (binary: CLI, startup, sync loop, shutdown)
                       |        |          |           |
                    network    rpc ----- wallet        |
                       |        |          |           |
                       +---- consensus ----+           |
                       |        |                      |
                    storage ----+----------------------+
                       |
              primitives, crypto
```

## Crates

| Crate | Path | Contents |
|---|---|---|
| `rustoshi` | `rustoshi/src/` | `main.rs`: CLI definition (clap), config-file merge, datadir setup, logging, the block connect loop, block import, metrics server, shutdown. `ops.rs`: config parser, daemonizing, PID file, log reopening. `swiftsync.rs`: experimental offline range validator. |
| `rustoshi-primitives` | `crates/primitives/` | `Hash256`, transactions, blocks, and the `Encodable` / `Decodable` wire serialization with CompactSize. |
| `rustoshi-crypto` | `crates/crypto/` | SHA-256d, HASH160, secp256k1 ECDSA and Schnorr via `libsecp256k1`, legacy / BIP-143 / BIP-341 sighash, Base58Check, Bech32 and Bech32m addresses. |
| `rustoshi-consensus` | `crates/consensus/` | Script interpreter (`script/`), chain parameters for every network (`params.rs`), proof of work and difficulty (`pow.rs`), block and transaction checks (`validation.rs`), chain state and best-chain selection (`chain_state.rs`, `chain_manager.rs`), BIP-9 versionbits, signature cache, mempool and package relay (`mempool.rs`), orphanage, fee estimation, block templates. |
| `rustoshi-storage` | `crates/storage/` | RocksDB database (`db.rs`, column families in `columns.rs`), block index and block/undo storage (`block_store.rs`, `undo.rs`), the layered UTXO cache (`utxo_cache.rs`), pruning, assumeutxo snapshots (`snapshot.rs`), and the optional indexes (`indexes/`: txindex, BIP-158 block filters, coinstats with MuHash, tx-output spender). |
| `rustoshi-network` | `crates/network/` | P2P messages, peer connections with v1 and BIP-324 v2 transport, the peer manager (address manager, eviction, misbehavior, bans), headers-first sync with headers presync, parallel block download with stall detection, compact blocks (BIP-152), transaction relay with Poisson trickling, SOCKS5/Tor/I2P proxies, ASMap bucketing. |
| `rustoshi-rpc` | `crates/rpc/` | JSON-RPC server on `jsonrpsee` (`server.rs` for node methods, `wallet.rs` for wallet methods, `wallet_route.rs` for `/wallet/<name>`), cookie and password auth, optional TLS, the REST server (`rest.rs`, axum), ZMQ publisher (`zmq.rs`), and the tip notifier used by `waitfor*`. |
| `rustoshi-wallet` | `crates/wallet/` | HD keys (BIP-32/39/44/84/86), output descriptors and miniscript, PSBT version 0 (BIP-174), coin selection, BIP-125 fee bumping, wallet encryption, BIP-21 URIs, BIP-78 payjoin, and SQLite persistence (`db.rs`). |

## Storage

All chain data lives in one RocksDB database at `<netdir>/chainstate/`. Column families separate headers, the block index, the height index, block bodies, undo data, the UTXO set, metadata and each optional index. Block bodies are stored in RocksDB rather than in Core-style `blk*.dat` files; the code that reads `blk*.dat` is used only by `--import-blocks`.

Above RocksDB sits a coins cache sized by `--dbcache`. New and spent coins are tracked in memory with dirty/fresh flags and flushed in a single write batch together with the new tip, so a crash leaves the UTXO set and the tip pointer consistent with each other.

## Validation flow

1. The network crate downloads headers first, checks proof of work and difficulty transitions, and feeds them to the block index.
2. Blocks on the best header chain are requested in parallel from several peers.
3. The connect loop in `rustoshi/src/main.rs` takes the next block in order, runs context-free and contextual checks from `consensus::validation`, and verifies scripts on a thread pool (`--par`). Below the assumevalid block, script checks are skipped as in Core; `--assumevalid=0` turns that off.
4. Coins are applied to the cache and undo data is written so the block can be disconnected during a reorg.
5. The mempool is updated, indexes are advanced, and RPC waiters and ZMQ subscribers are notified.

Reorganizations disconnect blocks back to the fork point using the undo data, then connect the new branch through the same path.

## Mempool and mining

`consensus::mempool` implements Core's standardness and replacement (BIP-125) policy, package acceptance (`submitpackage`), and ancestor/descendant limits. `fee_estimator.rs` tracks confirmation times per fee-rate bucket for `estimatesmartfee`. `block_template.rs` builds `getblocktemplate` responses using ancestor-feerate selection.

## Concurrency

The node runs on a multi-threaded tokio runtime. Peer connections, the RPC and REST servers, and the metrics server are async tasks. Script verification uses a dedicated worker pool. UTXO cache updates happen in one place, the connect loop, so they are never concurrent.
