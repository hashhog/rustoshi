# Running rustoshi

Everything here applies to `target/release/rustoshi` built as in [building.md](building.md). `rustoshi --help` prints the same flag list.

## Networks and ports

| `--network` | P2P port | RPC port | REST port (with `--rest`) | Data subdirectory |
|---|---|---|---|---|
| `mainnet` (alias `main`) | 8333 | 8332 | 8432 | `<datadir>/` |
| `testnet4` (default) | 48333 | 48332 | 48432 | `<datadir>/testnet4/` |
| `testnet3` (alias `testnet`) | 18333 | 18332 | 18432 | `<datadir>/testnet3/` |
| `signet` | 38333 | 38332 | 38432 | `<datadir>/signet/` |
| `regtest` | 18444 | 18443 | 18543 | `<datadir>/regtest/` |

`--network` defaults to `testnet4`. The RPC port follows the network only while `--rpcbind` is left at its default; an explicit `--rpcbind` is used as given. The P2P port can be changed with `--port`.

## Command-line flags

Flags use the `--name value` or `--name=value` form. Boolean flags are switched on by giving the flag (`--txindex`). Most names match Bitcoin Core's options.

### General

| Flag | Default | Meaning |
|---|---|---|
| `--network <name>` | `testnet4` | Chain to use (table above). |
| `--datadir <path>` | `~/.rustoshi` | Base data directory. |
| `--conf <path>` | see below | Config file. |
| `--daemon` | off | Fork into the background and detach. |
| `--pidfile <path>` | `<netdir>/rustoshi.pid` | PID file, removed on clean shutdown. |
| `--ready-fd <fd>` | none | Write `READY=1\n` to this file descriptor once startup is complete. |

### Chainstate and validation

| Flag | Default | Meaning |
|---|---|---|
| `--dbcache <MiB>` | 2560 | UTXO cache budget: 80% in-memory coins cache, 20% RocksDB block cache. Clamped to 4–65536. |
| `--par <n>` | 0 | Script-verification threads. `0` = one per core (up to 16), `1` = serial, negative = leave that many cores free. |
| `--assumevalid <hash\|0>` | built-in | Skip script checks below this block, as in Core. `0` verifies every script from genesis. |
| `--prune <MiB>` | off | Keep about this many MiB of block data. `1`, or any value below 550, enables manual pruning only (`pruneblockchain`). |
| `--txindex` | off | Transaction index for `getrawtransaction` on confirmed transactions. |
| `--coinstatsindex` | off | Per-height UTXO statistics, so `gettxoutsetinfo` can answer for past heights. |
| `--txospenderindex` | off | Spent-outpoint index for `gettxspendingprevout` on confirmed spends. |
| `--blockfilterindex <0\|1\|basic>` | off | BIP-158 basic block filter index (`getblockfilter`). |
| `--load-snapshot <path>` | none | Load a Core-format UTXO snapshot (`dumptxoutset` output) at startup. It must match an assumeutxo entry built into the chain parameters. |
| `--no-historical-backfill` | off | After `--load-snapshot`, do not download the blocks below the snapshot. |
| `--import-blocks <path\|->` | none | Import blocks from a directory of Core `blk*.dat` files, or from stdin (`-`) framed as `[height u32 LE][size u32 LE][block]`. |

### Mempool and fees

| Flag | Default | Meaning |
|---|---|---|
| `--maxmempool <MB>` | 300 | Mempool size limit. |
| `--minrelaytxfee <BTC/kvB>` | 0.00000100 | Minimum relay fee rate. |
| `--fallbackfee <BTC/kvB>` | 0 | Wallet fee rate when estimation has no data. `0` disables the fallback. |
| `--acceptnonstdtxn` | off | Relay and mine non-standard transactions. Refused on mainnet. |

### P2P

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | on | Accept inbound connections on `0.0.0.0:<port>`. It cannot be switched off on the command line; use `listen=0` in the config file. |
| `--port <port>` | per network | P2P listen port. |
| `--maxconnections <n>` | 125 | Maximum automatic connections (inbound + outbound), as in Core. Outbound targets are min(8, n) full-relay plus min(2, n − full-relay) block-relay-only; `0` runs offline. |
| `--connect <ip:port>` | none | Connect only to these peers (repeatable). Disables DNS seeds and automatic outbound connections. |
| `--nodnsseed` | off | Do not query DNS seeds. |
| `--nofixedseeds` | off | Do not fall back to the built-in seed list. |
| `--externalip <ip[:port]>` | none | Address to advertise (repeatable or comma-separated). Turns `--discover` off unless it is given. |
| `--discover[=<bool>]` | on | Learn our own address from peers. |
| `--proxy <host:port>` | none | SOCKS5 proxy for outbound IPv4/IPv6. |
| `--onion <host:port>` | `--proxy` | SOCKS5 proxy for Tor v3 peers. |
| `--i2psam <host:port>` | none | I2P SAM 3.1 bridge. |
| `--cjdnsreachable` | off | Treat `fc00::/8` addresses as reachable. |
| `--asmap <path>` | none | ASMap file for AS-based peer bucketing. Relative paths are resolved against the datadir. |
| `--peerbloomfilters` | off | Serve BIP-37 bloom filters and BIP-35 `mempool`. |
| `--peerblockfilters` | off | Serve BIP-157 filters. Requires `--blockfilterindex`. |
| `--p2p-watchdog-secs <s>` | 900 | Exit with status 1 if no P2P message arrives for this long while peers are connected, so a supervisor can restart the node. `0` disables. |

### RPC, REST and metrics

| Flag | Default | Meaning |
|---|---|---|
| `--rpcbind <ip:port>` | `127.0.0.1:<rpc port>` | JSON-RPC listen address. |
| `--rpcuser`, `--rpcpassword` | none | Password authentication. The cookie file works either way. |
| `--rpc-tls-cert <pem>`, `--rpc-tls-key <pem>` | none | Serve RPC over HTTPS. Both must be set. |
| `--rest` | off | Enable Core's `/rest/` interface (no authentication). |
| `--restbind <ip:port>` | RPC IP, RPC port + 100 | REST listen address. rustoshi serves REST on its own port, not the RPC port as Core does. |
| `--metrics-port <port>` | 9332 | Prometheus `/metrics` and JSON `/health` on `0.0.0.0:<port>`. `0` disables. |

### Logging

| Flag | Default | Meaning |
|---|---|---|
| `--loglevel <level>` | `info` | `trace`, `debug`, `info`, `warn` or `error`. |
| `--debug <categories>` | none | Core-style categories, comma-separated (`net`, `mempool`, `validation`, `rpc`, `wallet`, `prune`, ...). `all` enables every category. |
| `--printtoconsole=<bool>` | `true` | Also log to stdout. Write it with `=`: `--printtoconsole=false`. Off under `--daemon`. |
| `--debuglogfile <path>` | `<netdir>/debug.log` | Log file. `SIGHUP` reopens it, for logrotate. |

### Subcommands

| Command | State |
|---|---|
| `reindex` | Not implemented: logs a warning and exits. |
| `resync` | Not implemented: logs a warning and exits. |
| `swiftsync-pass` | Experimental offline range validator that reads Core's block and undo files. Its input packs are produced by tooling that is not part of this repository. |

## Config file

rustoshi reads one config file, from the first of these that exists: `--conf <path>`, `<datadir>/rustoshi.conf`, `~/.rustoshi/rustoshi.conf`. The format is `key=value` per line, as in `bitcoin.conf`. `#` starts a comment, `[section]` headers are ignored, and values may be quoted, so the TOML-style `config.example.toml` in this repo also parses. Command-line flags override the file.

Keys read from the file: `network`, `datadir`, `rpcbind`, `rpcuser`, `rpcpassword`, `rpc-tls-cert`, `rpc-tls-key`, `listen`, `peerbloomfilters`, `blockfilterindex`, `peerblockfilters`, `port`, `externalip`, `discover`, `maxconnections`, `connect` (comma-separated), `nodnsseed`, `nofixedseeds`, `txindex`, `coinstatsindex`, `loglevel`, `metrics_port`, `p2p_watchdog_secs`, `prune`, `daemon`, `no-historical-backfill`, `pidfile`, `debug`, `printtoconsole`, `debuglogfile`, `rest`, `restbind`, `asmap`, `proxy`, `onion`, `i2psam`, `cjdnsreachable`, `par`. Booleans accept `1`, `true`, `yes` or `on`. Other flags (for example `dbcache`, `maxmempool`, `txospenderindex`, `assumevalid`) are command-line only, and unknown keys are ignored.

Example, on regtest:

```bash
DATADIR=$(mktemp -d)
cat > "$DATADIR/rustoshi.conf" <<'EOF'
network=regtest
rpcuser=alice
rpcpassword=change-me
rest=1
metrics_port=19332
txindex=1
EOF
./target/release/rustoshi --datadir "$DATADIR" &
sleep 5
curl -s --user alice:change-me -d '{"method":"getindexinfo","params":[]}' http://127.0.0.1:18443/
curl -s http://127.0.0.1:18543/rest/chaininfo.json
curl -s http://127.0.0.1:19332/health
curl -s --user alice:change-me -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

The first line of output is `rustoshi: loaded config from <path>`, and `getindexinfo` reports `txindex`.

## Environment variables

| Variable | Effect |
|---|---|
| `RUST_LOG` | Standard `tracing` filter; overrides `--loglevel` and `--debug`. |
| `RUSTOSHI_BIP324_V2_OUTBOUND`, `RUSTOSHI_BIP324_V2_INBOUND` | BIP-324 v2 transport is on by default in both directions. Set to `0` to fall back to v1. |
| `HASHHOG_BLOCKS_IN_FLIGHT_PER_PEER` | Blocks requested at once from one peer (1–128). The default is 16, or 128 with a single `--connect` peer. |
| `HASHHOG_DISABLE_HISTORICAL_BACKFILL=1` | Same as `--no-historical-backfill`. |
| `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT`, `HASHHOG_CAMPAIGN_ASSUMEUTXO` | Testing only: accept UTXO snapshots that are not in the built-in assumeutxo table. The node logs a loud warning. Never set these on a node you rely on. |

## Data directory

```
<datadir>/.cookie           RPC cookie (__cookie__:<hex>), mode 0600, deleted on shutdown
<datadir>/<net>/chainstate/ RocksDB: headers, block index, block and undo data, UTXO set, indexes
<datadir>/<net>/wallets/    one directory per wallet
<datadir>/<net>/debug.log   log file
<datadir>/<net>/mempool.dat mempool saved on shutdown and loaded on start
<datadir>/<net>/fee_estimates.json
<datadir>/<net>/peers.dat   address manager
<datadir>/<net>/rustoshi.pid
```

`<net>` is empty for mainnet. Unlike Core, block data is stored inside RocksDB rather than in `blocks/blk*.dat`, and the cookie is written to the base datadir rather than the network subdirectory.

## Resources

On mainnet, disk use is in the same range as an unpruned Bitcoin Core node (several hundred GB), less with `--prune`. Memory is dominated by `--dbcache` plus the mempool (`--maxmempool`). The initial sync is mostly limited by the UTXO cache size and by script verification; raising `--dbcache` and leaving `--par` at its default helps most.

## Stopping

Call the `stop` RPC or send `SIGTERM` or `SIGINT`. Both flush the UTXO cache and save the mempool before exiting.

## Monitoring

With the default `--metrics-port 9332`:

- `GET /metrics` returns Prometheus text: block height, peer count, mempool size and script-check counters.
- `GET /health` (also `/healthz`, `/livez`) returns `{"status":"ok","height":N,"peers":N}`.

The metrics server binds all interfaces. Firewall the port or pass `--metrics-port 0` if you do not want it reachable.

## A regtest walkthrough

Create a wallet, mine 101 blocks so the first coinbase matures, and check the balance and UTXO set:

```bash
DATADIR=$(mktemp -d)
./target/release/rustoshi --network regtest --datadir "$DATADIR" --metrics-port 0 &
sleep 5
rpc() { curl -s --user "$(cat "$DATADIR/.cookie")" -d "{\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:18443/; echo; }
rpc createwallet '["demo"]'
ADDR=$(rpc getnewaddress | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
rpc generatetoaddress "[101,\"$ADDR\"]" > /dev/null
rpc getbalance
rpc gettxoutsetinfo
rpc stop
```

`getbalance` returns `50.0` and `gettxoutsetinfo` reports `"height":101`.
