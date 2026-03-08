# rustoshi

A Bitcoin full node written from scratch in Rust.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
rustoshi is a from-scratch Bitcoin full node that does exactly that. It's designed
to be educational, well-structured, and idiomatic Rust.

## Current status

- [x] Project structure and Cargo workspace
- [ ] Primitive types (hashes, scripts, addresses)
- [ ] Cryptographic operations (SHA256, RIPEMD160, secp256k1)
- [ ] P2P network protocol
- [ ] Consensus rules and block validation
- [ ] Persistent storage (RocksDB)
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
    primitives/       # foundational types
    crypto/           # hashing and signing
    network/          # P2P protocol
    consensus/        # validation rules
    storage/          # RocksDB persistence
    rpc/              # JSON-RPC server
    wallet/           # key management
```

## Running tests

```bash
cargo test --workspace
```
