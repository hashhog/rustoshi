# Status and how to check it

Each row of the status table in the [README](../README.md) can be checked with the commands on this page. Last updated 2026-10-16, against the `master` commit of that date.

## Test suite

```bash
cargo test --workspace --no-fail-fast
```

On 2026-10-16 this ran 82 test binaries: 4,374 tests passed, 1 failed and 550 were ignored. The failure, `script_verification_counter_increments_by_verified_inputs` in `crates/consensus/tests/w105_checkqueue.rs`, reads a process-wide counter that other tests in the same binary also increment, so it fails only when tests run in parallel. Run serially it passes:

```bash
cargo test -p rustoshi-consensus --test w105_checkqueue -- --test-threads=1
```

## Script interpreter against Core's vectors

Bitcoin Core's `script_tests.json` and `sighash.json` are copied into `crates/consensus/testdata/`, and these tests run every vector:

```bash
cargo test -p rustoshi-consensus --test script_vectors --test sighash_vectors
```

## UTXO set against Core, on regtest

This builds a chain on Bitcoin Core, lets rustoshi sync it over P2P, and compares the two UTXO-set hashes. `hash_serialized_3` covers every coin, so one wrong coin, amount or script changes it. You need Bitcoin Core's `bitcoind` and `bitcoin-cli` on your `PATH`; this was run with Core v31.

```bash
CORE=$(mktemp -d); NODE=$(mktemp -d)
bitcoind -regtest -datadir="$CORE" -port=18544 -rpcport=18543 -listen=1 -daemon
sleep 3
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 generatetoaddress 200 bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89
./target/release/rustoshi --network regtest --datadir "$NODE" --metrics-port 0 --connect 127.0.0.1:18544 &
sleep 15
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 gettxoutsetinfo
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"gettxoutsetinfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 stop
```

Both report `"height": 200`, the same `bestblock`, and `"hash_serialized_3": "55a904f0ebf65d38b61e674ea2c411e0241cd7d311ad8c5f35c24c9eafbfe44f"`. The block hashes change from run to run because block times differ, but this UTXO hash does not: the chain holds only coinbase outputs to a fixed address, and their txids do not depend on the time.

## UTXO set against Core, on mainnet

The same comparison works on mainnet; it needs a full sync of both nodes. Run rustoshi with `--network mainnet --assumevalid=0` so every script is verified, wait until both nodes report the same `bestblock` in `gettxoutsetinfo`, and compare `hash_serialized_3`.

Bitcoin Core can also produce the hash for a past height, so you do not have to catch both nodes at the same tip: `bitcoin-cli -named dumptxoutset path=<file> rollback=<height>` returns it as `txoutset_hash` (the regtest form of that command is shown below). For height 958,794 Core's value is `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over 166,180,925 coins; a rustoshi node whose tip is at that height reports the same `hash_serialized_3`.

The regtest form, against the Core node of the previous section before you stop it:

```bash
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 -named dumptxoutset path="$CORE/utxo-100.dat" rollback=100
```

## RPC coverage

Start a regtest node as in the README's quick start, then:

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"help","params":[]}' http://127.0.0.1:18443/
```

`help` lists 117 methods. [rpc.md](rpc.md) lists all 140 that the dispatch table registers, and the differences from Core that are known.

## Known limitations

- `reindex` and `resync` are accepted as subcommands but only log a warning and exit.
- `--listen` cannot be switched off on the command line; set `listen=0` in the config file.
- `--help` mentions `--no-printtoconsole`, which does not exist; use `--printtoconsole=false`.
- ZMQ notifications cannot be enabled: there are no `-zmqpub*` options.
- PSBT version 2 (BIP-370) is not implemented.
- Some named RPC parameters have different names from Core's (see [rpc.md](rpc.md)), and missing or mistyped parameters return `-32602` instead of Core's codes.
- `listdescriptors` returns no descriptors for a wallet made by plain `createwallet`.
- `Cargo.lock` is not committed, so builds are not reproducible bit for bit ([building.md](building.md)).
- One test fails when the suite runs in parallel (see above).
