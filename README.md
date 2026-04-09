# rustoshi

A Bitcoin full node written from scratch in Rust. Part of the [Hashhog](https://github.com/hashhog/hashhog) project.

## Quick Start

### Docker

```bash
docker-compose up -d
```

This starts rustoshi on mainnet with data persisted to a Docker volume. Ports 8333 (P2P) and 8332 (RPC) are exposed.

### Build from Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y build-essential librocksdb-dev

# Build
cargo build --release

# Run on testnet4
./target/release/rustoshi --network testnet4

# Run on mainnet
./target/release/rustoshi --network mainnet --datadir ~/.rustoshi
```

## Features

- Full block and transaction validation (BIP-16, BIP-34, BIP-65, BIP-66, BIP-68, BIP-141, BIP-143, BIP-146, BIP-147)
- Script interpreter supporting P2PKH, P2SH, P2WPKH, P2WSH, and P2TR
- SegWit-aware serialization (txid vs wtxid, witness discount)
- Headers-first sync with parallel block downloads and stall detection
- Multi-layer UTXO cache (CoinsView hierarchy with DIRTY/FRESH flags, batch flushing)
- RocksDB storage with column families for blocks, UTXOs, and chain state
- Flat file block storage (blk?????.dat, 128 MiB limit, pre-allocation)
- Transaction mempool with fee-rate ordering and 25/25/101kvB package limits
- Fee estimation with confirmation time prediction and exponential decay
- Block template construction (ancestor-feerate selection, BIP-34 coinbase, witness commitment)
- HD wallet (BIP-32/44/84 key derivation, address generation, UTXO tracking, transaction building)
- Miniscript (type system, parsing, compilation, satisfaction, analysis)
- PSBT support (BIP-174/BIP-370: create, decode, combine, finalize)
- Output descriptors (BIP-380-386: derive addresses, import)
- BIP-9 versionbits state machine for soft fork activation tracking
- BIP-133 feefilter with privacy-preserving Poisson delays
- Checkpoint verification and fork rejection
- Transaction index (txindex) for historical lookups
- Block pruning to configurable size
- Block import from blk*.dat files or stdin
- Regtest mode with generatetoaddress, generatetodescriptor, and generateblock RPCs
- Parallel script validation for IBD performance
- Inventory trickling with Poisson-timed tx relay
- Misbehavior scoring and peer banning
- Stale peer eviction and self-connection detection

## Configuration

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--network <NETWORK>` | Network: mainnet, testnet3, testnet4, signet, regtest | `testnet4` |
| `--datadir <DATADIR>` | Data directory for blockchain data and configuration | `~/.rustoshi` |
| `--rpcbind <RPCBIND>` | RPC bind address | `127.0.0.1:8332` |
| `--rpcuser <RPCUSER>` | RPC authentication user | |
| `--rpcpassword <RPCPASSWORD>` | RPC authentication password | |
| `--listen` | Listen for incoming P2P connections | disabled |
| `--port <PORT>` | P2P listen port (overrides network default) | |
| `--maxconnections <N>` | Maximum number of outbound connections | `8` |
| `--connect <CONNECT>` | Connect only to this peer (for testing) | |
| `--txindex` | Enable transaction indexing | disabled |
| `--loglevel <LEVEL>` | Log level: trace, debug, info, warn, error | `info` |
| `--prune <MiB>` | Prune blockchain data to this many MiB | disabled |
| `--import-blocks <PATH>` | Import blocks from blk*.dat directory or stdin (`-`) | |

### Subcommands

| Command | Description |
|---------|-------------|
| `reindex` | Reindex the blockchain from stored block data |
| `resync` | Wipe and resync the blockchain |

## RPC API

### Blockchain

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Returns blockchain processing state info |
| `getblockcount` | Returns height of the most-work fully-validated chain |
| `getbestblockhash` | Returns hash of the best (tip) block |
| `getblockhash` | Returns hash of block at given height |
| `getblock` | Returns block data for a given hash |
| `getblockheader` | Returns block header data |
| `getdifficulty` | Returns proof-of-work difficulty |
| `getchaintips` | Returns information about all known tips in the block tree |
| `gettxout` | Returns details about an unspent transaction output |
| `invalidateblock` | Marks a block as invalid |
| `reconsiderblock` | Removes invalidity status from a block |
| `preciousblock` | Treats a block as if it were received before others at the same height |

### Transactions

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Returns raw transaction data (mempool, txindex, or by blockhash) |
| `sendrawtransaction` | Submits a raw transaction to the network |
| `decoderawtransaction` | Decodes a hex-encoded raw transaction |
| `createrawtransaction` | Creates an unsigned raw transaction |
| `decodescript` | Decodes a hex-encoded script |
| `testmempoolaccept` | Tests whether a raw transaction would be accepted by the mempool |

### Mempool

| Method | Description |
|--------|-------------|
| `getmempoolinfo` | Returns mempool state details |
| `getrawmempool` | Returns all transaction IDs in the mempool |
| `getmempoolentry` | Returns mempool data for a given transaction |
| `getmempoolancestors` | Returns all in-mempool ancestors for a transaction |

### Network

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Returns P2P networking state info |
| `getpeerinfo` | Returns data about each connected peer |
| `getconnectioncount` | Returns the number of connections |
| `addnode` | Adds or removes a peer |
| `disconnectnode` | Disconnects a peer |
| `listbanned` | Lists all banned IPs/subnets |
| `setban` | Adds or removes an IP/subnet from the ban list |
| `clearbanned` | Clears all banned IPs |

### Mining

| Method | Description |
|--------|-------------|
| `getblocktemplate` | Returns a block template for mining |
| `submitblock` | Submits a new block to the network |
| `getmininginfo` | Returns mining-related information |
| `estimatesmartfee` | Estimates fee rate for confirmation within N blocks |
| `generatetoaddress` | Mines blocks to an address (regtest only) |
| `generatetodescriptor` | Mines blocks to a descriptor (regtest only) |
| `generateblock` | Mines a block with specific transactions (regtest only) |

### Wallet

| Method | Description |
|--------|-------------|
| `createwallet` | Creates a new wallet |
| `loadwallet` | Loads a wallet from disk |
| `unloadwallet` | Unloads a wallet |
| `listwallets` | Lists loaded wallets |
| `getnewaddress` | Generates a new receiving address |
| `getbalance` | Returns wallet balance |
| `listunspent` | Lists unspent outputs |
| `listtransactions` | Lists wallet transactions |
| `getwalletinfo` | Returns wallet state info |
| `importdescriptors` | Imports output descriptors into the wallet |
| `walletpassphrase` | Unlocks an encrypted wallet |
| `walletlock` | Locks the wallet |
| `setlabel` | Sets an address label |

### Descriptors and PSBT

| Method | Description |
|--------|-------------|
| `getdescriptorinfo` | Analyzes and checksums an output descriptor |
| `deriveaddresses` | Derives addresses from a descriptor |
| `createpsbt` | Creates a PSBT |
| `decodepsbt` | Decodes a base64 PSBT |
| `combinepsbt` | Combines multiple PSBTs |
| `finalizepsbt` | Finalizes a PSBT |

### Utility

| Method | Description |
|--------|-------------|
| `validateaddress` | Validates a Bitcoin address |
| `verifymessage` | Verifies a signed message |
| `uptime` | Returns server uptime in seconds |
| `stop` | Stops the node |
| `help` | Lists available RPC commands |

## Architecture

rustoshi is structured as a Cargo workspace with seven crates, each responsible for a distinct layer of the system. The `primitives` crate defines core Bitcoin types -- Hash256, transactions, blocks, and binary serialization using Encodable/Decodable traits with CompactSize encoding. The `crypto` crate builds on these with SHA256d, HASH160, secp256k1 ECDSA/Schnorr verification, sighash computation (legacy, BIP-143, and BIP-341), and address encoding (Base58Check, Bech32, Bech32m). The `consensus` crate contains the script interpreter implementing all opcodes across P2PKH, P2SH, P2WPKH, P2WSH, and P2TR, plus chain parameters, difficulty adjustment, and block/transaction validation with full BIP rule enforcement.

The `storage` crate provides persistence through RocksDB with separate column families for block headers, block data, UTXO entries, and chain state. A multi-layer CoinsView cache hierarchy sits above RocksDB, using DIRTY and FRESH flags to track modifications and batch-flush them efficiently. Block data is stored in flat blk?????.dat files (128 MiB each, pre-allocated) with a RocksDB index mapping block hashes to file positions. Undo data for reorgs is maintained in separate rev*.dat files.

The `network` crate handles P2P communication: TCP connections with version/verack handshakes, DNS seed resolution, and a peer manager that maintains the connection pool with misbehavior scoring and ban lists. Header synchronization uses block locators and the getheaders protocol. The block download manager implements a parallel sliding-window download strategy with stall detection and adaptive timeouts. Inventory trickling uses Poisson-distributed delays for transaction relay privacy.

The `rpc` crate exposes a Bitcoin Core-compatible JSON-RPC server built on jsonrpsee, supporting blockchain queries, raw transaction operations, mempool inspection, mining (block templates and regtest block generation), and wallet operations. The `wallet` crate implements BIP-32/44/84 HD key derivation, address generation, UTXO tracking, transaction building, miniscript, and PSBT workflows.

Concurrency during IBD relies on parallel script validation: blocks are split into batches of transactions whose scripts are verified across multiple threads using Rayon, while UTXO cache updates remain single-threaded to preserve consistency. The mempool enforces per-package ancestor/descendant limits (25/25/101kvB) and supports fee estimation via confirmation time tracking with exponential decay across fee-rate buckets.

## Project Structure

```
rustoshi/
  rustoshi/           # binary crate (CLI entry point)
    benches/          # criterion benchmarks
  crates/
    primitives/       # Hash256, transactions, blocks, serialization
    crypto/           # SHA256d, HASH160, secp256k1 ECDSA, sighash, addresses
    consensus/        # script interpreter, chain params, validation, difficulty adjustment
    network/          # P2P protocol (message types, peer management)
    storage/          # RocksDB persistence, UTXO cache layer
    rpc/              # JSON-RPC server
    wallet/           # HD wallet (BIP-32/44/84), miniscript, PSBT, descriptors
```

## Running Tests

```bash
cargo test --workspace           # run all tests
cargo test -p rustoshi           # run integration + property tests
cargo clippy --workspace         # lint checks
cargo bench --workspace          # run benchmarks
```

## License

MIT
