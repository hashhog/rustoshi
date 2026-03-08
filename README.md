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
- [ ] P2P network protocol
- [ ] Block validation and chain management
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
    primitives/       # Hash256, transactions, blocks, serialization
    crypto/           # SHA256d, HASH160, secp256k1 ECDSA, sighash, addresses
    consensus/        # script interpreter, chain params, difficulty adjustment
    network/          # P2P protocol
    storage/          # RocksDB persistence
    rpc/              # JSON-RPC server
    wallet/           # key management
```

## Running tests

```bash
cargo test --workspace
```
