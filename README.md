# rustoshi

A Bitcoin full node written from scratch in Rust. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Block validation | Full consensus rules (BIP-16/34/65/66/68/112/113/141/143/147/341/342). Script interpreter checked against Core's `script_tests.json` and `sighash.json` vectors (`crates/consensus/tests/script_vectors.rs`, `sighash_vectors.rs`). |
| UTXO set vs Core | `gettxoutsetinfo` `hash_serialized_3` matches Bitcoin Core on the same chain; [docs/status.md](docs/status.md) shows a 5-minute regtest check and how to run it on mainnet. |
| RPC | 140 JSON-RPC methods with Core's names and result shapes; error codes for bad or missing parameters often differ. See [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, BIP-152 compact blocks, BIP-324 v2 transport, addrv2, BIP-157/158 filters (opt-in). Tests in `crates/network`. |
| Test suite | `cargo test --workspace`: 4,374 passed, 1 failed (a test that races a shared counter; passes serially), 550 ignored. See [docs/status.md](docs/status.md#test-suite). |
| Wallet | Descriptor wallet, PSBT and coin selection work on regtest and are unit-tested. Not reviewed for custody: see [SECURITY.md](SECURITY.md). |

Last updated: 2026-10-16.

## Quick start

Tested on Debian 13 with stable Rust 1.99.0 (install Rust from <https://rustup.rs>):

```bash
sudo apt-get install -y build-essential clang libclang-dev cmake pkg-config curl git
git clone https://github.com/hashhog/rustoshi.git && cd rustoshi
cargo build --release          # a few minutes; RocksDB and ZeroMQ are built from source
DATADIR=$(mktemp -d)
./target/release/rustoshi --network regtest --datadir "$DATADIR" &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" \
  -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

The first `curl` prints the regtest genesis state (`"chain":"regtest","blocks":0`). More regtest walkthroughs (wallet, mining, comparing with Core) are in [docs/running.md](docs/running.md) and [docs/status.md](docs/status.md).

## Running

Choose a network with `--network` (`mainnet`, `testnet4`, `testnet3`, `signet` or `regtest`). The default is testnet4, not mainnet, so pass `--network mainnet` explicitly. Data goes under `--datadir` (default `~/.rustoshi`):

| Network | P2P port | RPC port | Data subdirectory |
|---|---|---|---|
| mainnet | 8333 | 8332 | `<datadir>/` |
| testnet4 | 48333 | 48332 | `<datadir>/testnet4/` |
| testnet3 | 18333 | 18332 | `<datadir>/testnet3/` |
| signet | 38333 | 38332 | `<datadir>/signet/` |
| regtest | 18444 | 18443 | `<datadir>/regtest/` |

A Prometheus endpoint listens on `0.0.0.0:9332` unless you pass `--metrics-port 0`.

For mainnet, plan for the same disk as an unpruned Bitcoin Core node (several hundred GB), or pass `--prune <MiB>` to keep only recent blocks. Memory use is driven mostly by the UTXO cache, `--dbcache <MiB>` (default 2560); a larger cache makes the initial sync faster.

Every flag, the config file format, environment variables and the datadir layout are in [docs/running.md](docs/running.md).

## RPC

rustoshi serves Bitcoin Core's JSON-RPC interface on the RPC port above. It writes a Core-style cookie to `<datadir>/.cookie` on startup (the base datadir, not the network subdirectory), or you can set `--rpcuser` / `--rpcpassword`. Any JSON-RPC client that works with `bitcoind` should work. With the quick-start node running (before the final `stop`):

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getwalletinfo","params":[]}' http://127.0.0.1:18443/wallet/demo
```

As in Core, wallet calls can be sent to a named wallet with the `/wallet/<name>` URL path. The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md). An optional Core-compatible REST interface is enabled with `--rest`.

## Development

```bash
cargo test --workspace           # unit and integration tests for all crates
```

```
rustoshi/            binary crate: CLI, startup, sync loop (src/main.rs)
crates/primitives/   hashes, transactions, blocks, serialization
crates/crypto/       SHA-256, HASH160, secp256k1, sighash, address encodings
crates/consensus/    script interpreter, chain params, validation, mempool, fee estimation
crates/storage/      RocksDB chainstate, UTXO cache, block index, optional indexes
crates/network/      P2P messages, peer manager, header sync, block download
crates/rpc/          JSON-RPC, REST and ZMQ servers
crates/wallet/       HD/descriptor wallet, PSBT, miniscript, coin selection
fuzz/                cargo-fuzz targets for the decoders and script interpreter
```

[docs/architecture.md](docs/architecture.md) describes how the parts fit together, [docs/building.md](docs/building.md) covers toolchains and build options, and [CONTRIBUTING.md](CONTRIBUTING.md) explains how to send changes.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
