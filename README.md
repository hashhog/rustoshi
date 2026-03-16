# rustoshi

A Bitcoin full node written from scratch in Rust.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
rustoshi is a from-scratch Bitcoin full node that does exactly that. It's designed
to be educational, well-structured, and idiomatic Rust.

## Current status

- [x] Project structure and Cargo workspace
- [x] Hash types (Hash256, Hash160) with hex encoding
- [x] Binary serialization (Encodable/Decodable traits, CompactSize)
- [x] Transaction types (OutPoint, TxIn, TxOut, Transaction)
- [x] Block types (BlockHeader, Block) with Merkle root computation
- [x] SegWit-aware serialization (txid vs wtxid)
- [x] Cryptographic operations (SHA256d, HASH160, tagged hashes, secp256k1 ECDSA)
- [x] Sighash computation (legacy and BIP-143 SegWit)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (opcodes, stack machine, P2PKH/P2SH/P2WPKH/P2WSH)
- [x] Consensus parameters (chain config, genesis blocks, soft fork heights)
- [x] Difficulty adjustment algorithm
- [x] Persistent storage (RocksDB with column families, UTXO set, undo data)
- [x] Block validation (context-free and contextual checks, BIP-34 height encoding)
- [x] Transaction validation (UTXO lookup, script verification, sigops counting)
- [x] Block connection/disconnection (UTXO updates, undo data, reorg support)
- [x] P2P message serialization (version, headers, inv, block, tx, etc.)
- [x] P2P peer connection (TCP, version/verack handshake, ping/pong keepalive)
- [x] Peer management (connection pool, DNS seed resolution, address manager)
- [x] Header synchronization (block locator, getheaders protocol)
- [x] Block download manager (parallel downloads, sliding window, stall detection)
- [x] UTXO cache (in-memory with database fallback, flush batching)
- [x] Chain state (tip tracking, median-time-past, reorganization support)
- [x] Mempool (transaction storage, fee-rate ordering, ancestor/descendant limits)
- [x] Fee estimation (confirmation time prediction, exponential decay, bucket statistics)
- [x] Block template construction (ancestor-feerate selection, BIP-34 coinbase, witness commitment)
- [x] JSON-RPC server (getblockchaininfo, getblock, sendrawtransaction, estimatesmartfee, etc.)
- [x] HD wallet (BIP-32/44/84 key derivation, address generation, UTXO tracking, transaction building)
- [x] CLI and application entry point (clap-based CLI, event loop, graceful shutdown)
- [x] Testing suite (unit tests, integration tests, property-based tests)
- [x] Performance optimizations (parallel script validation, UTXO compression, DB tuning, benchmarks)
- [x] BIP-146 NULLFAIL enforcement at SegWit activation height
- [x] BIP-141 WITNESS_PUBKEYTYPE enforcement (compressed pubkeys in SegWit v0)
- [x] Witness cleanstack enforcement (implicit cleanstack for witness v0/v1)
- [ ] Full IBD sync (testnet4 sync to tip)

## Quick start

```bash
cargo build --workspace
cargo run -- --network testnet4  # start node on testnet4
cargo run -- --help              # show all CLI options
```

## Project structure

```
rustoshi/
  rustoshi/           # binary crate (CLI entry point)
    benches/          # criterion benchmarks
  crates/
    primitives/       # Hash256, transactions, blocks, serialization
    crypto/           # SHA256d, HASH160, secp256k1 ECDSA, sighash, addresses
    consensus/        # script interpreter, chain params, validation
    network/          # P2P protocol (message types, peer management)
    storage/          # RocksDB persistence
    rpc/              # JSON-RPC server
    wallet/           # HD wallet (BIP-32/44/84, transaction signing)
```

## Running tests

```bash
cargo test --workspace           # run all tests
cargo test -p rustoshi           # run integration + property tests
cargo clippy --workspace         # lint checks
cargo bench --workspace          # run benchmarks
```
