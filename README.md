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
- [ ] Header-first sync and block download
- [ ] Chain management and reorganization
- [ ] JSON-RPC server
- [ ] Wallet functionality

## Quick start

```bash
cargo build --workspace
cargo run -- --help
```

## Project structure

```
rustoshi/
  rustoshi/           # binary crate (CLI entry point)
  crates/
    primitives/       # Hash256, transactions, blocks, serialization
    crypto/           # SHA256d, HASH160, secp256k1 ECDSA, sighash, addresses
    consensus/        # script interpreter, chain params, validation
    network/          # P2P protocol (message types, peer management)
    storage/          # RocksDB persistence
    rpc/              # JSON-RPC server
    wallet/           # key management
```

## Running tests

```bash
cargo test --workspace
```
