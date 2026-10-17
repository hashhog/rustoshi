# RPC reference

rustoshi serves Bitcoin Core's JSON-RPC interface: the same method names, positional parameters and result field names. Clients written for `bitcoind`, including `bitcoin-cli` pointed at rustoshi's port and cookie, work for the methods below.

## Calling it

Authenticate with the cookie in `<datadir>/.cookie` or with `--rpcuser` / `--rpcpassword`, and POST a JSON body to the RPC port (see [running.md](running.md#networks-and-ports)). On regtest:

```bash
DATADIR=$(mktemp -d)
./target/release/rustoshi --network regtest --datadir "$DATADIR" --metrics-port 0 &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockhash","params":[0]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockhash","params":{"height":0}}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '[{"method":"getblockcount","params":[]},{"method":"getbestblockhash","params":[]}]' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"help","params":[]}' http://127.0.0.1:18443/
bitcoin-cli -regtest -rpccookiefile="$DATADIR/.cookie" -rpcport=18443 getblockchaininfo
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

The `bitcoin-cli` line needs Bitcoin Core's client installed; everything else needs only `curl`.

Named parameters (a JSON object) and batches (a JSON array of requests) are accepted. Wallet methods use the only loaded wallet, or the one named in the URL path `/wallet/<name>` when several are loaded, as in Core.

## Known differences from Core

- Responses use the JSON-RPC 2.0 envelope (`{"jsonrpc":"2.0","result":...,"id":...}` with no `"error":null` field), whatever version the request asks for.
- A call with missing parameters, too many parameters, or a parameter of the wrong JSON type is rejected by the RPC framework with `-32602 Invalid params` before the handler runs. Core answers these with its own codes (usually `-1` with the method's help text, or `-3` for a type error). For example `{"method":"getblockhash","params":[]}` returns `{"code":-32602,"message":"Invalid params","data":"No more params"}`.
- Some named parameters have different names from Core's. For example `getblock` and `getblockheader` take `hash` where Core uses `blockhash`, so `{"blockhash": ...}` fails with `-32602`. Positional parameters match Core.
- `help` lists 117 of the 140 methods. The ones marked "no" below are callable but not listed. `help <method>` prints a one-line usage summary, not Core's full help text.
- REST (`--rest`) listens on its own port (RPC port + 100) instead of sharing the RPC port.
- There is no `-zmqpub*` option, so ZMQ notifications cannot be enabled at startup.

For invalid *values* (bad hashes, out-of-range heights, malformed addresses) many methods return Core's error codes; the tests in `crates/rpc/tests/test_w125_error_parity.rs` and `crates/rpc/src/r5_errcode_tests.rs` pin the cases that have been checked.

## Methods

Grouped like Core's `help`. "In `help`" says whether rustoshi's own `help` lists it.

### Blockchain

| Method | In `help` | Notes |
|---|---|---|
| `dumptxoutset` | no |  |
| `getbestblockhash` | yes |  |
| `getblock` | yes |  |
| `getblockchaininfo` | yes |  |
| `getblockcount` | yes |  |
| `getblockfilter` | yes |  |
| `getblockfrompeer` | yes |  |
| `getblockhash` | yes |  |
| `getblockheader` | yes |  |
| `getblockstats` | yes |  |
| `getchainstates` | yes |  |
| `getchaintips` | yes |  |
| `getchaintxstats` | yes |  |
| `getdeploymentinfo` | yes |  |
| `getdifficulty` | yes |  |
| `getsyncstate` | no | Not in Core. Sync progress summary. |
| `gettxout` | yes |  |
| `gettxoutproof` | yes |  |
| `gettxoutsetinfo` | yes |  |
| `gettxspendingprevout` | yes |  |
| `invalidateblock` | yes |  |
| `loadtxoutset` | no | Only snapshots matching a built-in assumeutxo entry are accepted. |
| `preciousblock` | yes |  |
| `pruneblockchain` | yes |  |
| `reconsiderblock` | yes |  |
| `scanblocks` | yes |  |
| `scantxoutset` | yes |  |
| `verifychain` | yes |  |
| `verifytxoutproof` | yes |  |
| `waitforblock` | yes |  |
| `waitforblockheight` | yes |  |
| `waitfornewblock` | yes |  |

### Mempool

| Method | In `help` | Notes |
|---|---|---|
| `dumpmempool` | yes |  |
| `getmempoolancestors` | yes |  |
| `getmempooldescendants` | yes |  |
| `getmempoolentry` | yes |  |
| `getmempoolinfo` | yes |  |
| `getorphantxs` | yes |  |
| `getrawmempool` | yes |  |
| `importmempool` | yes |  |
| `loadmempool` | yes |  |
| `savemempool` | yes |  |
| `submitpackage` | yes |  |
| `testmempoolaccept` | yes |  |

### Mining

| Method | In `help` | Notes |
|---|---|---|
| `getblocktemplate` | yes |  |
| `getmininginfo` | yes |  |
| `getnetworkhashps` | yes |  |
| `getprioritisedtransactions` | yes |  |
| `prioritisetransaction` | yes |  |
| `submitblock` | yes |  |
| `submitheader` | yes |  |

### Generating (regtest)

| Method | In `help` | Notes |
|---|---|---|
| `generateblock` | no | Hidden in Core's `help` too. |
| `generatetoaddress` | no | Hidden in Core's `help` too. |
| `generatetodescriptor` | no | Hidden in Core's `help` too. |

### Network

| Method | In `help` | Notes |
|---|---|---|
| `addnode` | yes |  |
| `addpeeraddress` | yes |  |
| `clearbanned` | yes |  |
| `disconnectnode` | yes |  |
| `getaddednodeinfo` | yes |  |
| `getaddrmaninfo` | yes |  |
| `getconnectioncount` | yes |  |
| `getnettotals` | yes |  |
| `getnetworkinfo` | yes |  |
| `getnodeaddresses` | yes |  |
| `getpeerinfo` | yes |  |
| `listbanned` | yes |  |
| `ping` | yes |  |
| `setban` | yes |  |
| `setnetworkactive` | yes |  |

### Control

| Method | In `help` | Notes |
|---|---|---|
| `getmemoryinfo` | yes |  |
| `getrpcinfo` | yes |  |
| `help` | yes |  |
| `logging` | yes |  |
| `setmocktime` | no | Hidden in Core's `help` too. |
| `stop` | yes |  |
| `uptime` | yes |  |

### Raw transactions

| Method | In `help` | Notes |
|---|---|---|
| `combinerawtransaction` | yes |  |
| `createrawtransaction` | yes |  |
| `decoderawtransaction` | yes |  |
| `decodescript` | yes |  |
| `fundrawtransaction` | no |  |
| `getrawtransaction` | yes |  |
| `sendrawtransaction` | yes |  |
| `signrawtransactionwithkey` | yes |  |

### PSBT

| Method | In `help` | Notes |
|---|---|---|
| `analyzepsbt` | yes |  |
| `combinepsbt` | yes |  |
| `converttopsbt` | yes |  |
| `createpsbt` | yes |  |
| `decodepsbt` | yes |  |
| `descriptorprocesspsbt` | yes |  |
| `finalizepsbt` | yes |  |
| `joinpsbts` | yes |  |
| `utxoupdatepsbt` | yes |  |

### Util

| Method | In `help` | Notes |
|---|---|---|
| `createmultisig` | yes |  |
| `deriveaddresses` | yes |  |
| `estimaterawfee` | yes |  |
| `estimatesmartfee` | yes |  |
| `getdescriptorinfo` | yes |  |
| `getindexinfo` | yes |  |
| `signmessagewithprivkey` | yes |  |
| `validateaddress` | yes |  |
| `verifymessage` | yes |  |

### Wallet

| Method | In `help` | Notes |
|---|---|---|
| `backupwallet` | yes |  |
| `bumpfee` | no |  |
| `createwallet` | yes |  |
| `encryptwallet` | no |  |
| `getaddressinfo` | yes |  |
| `getbalance` | yes |  |
| `getbalances` | yes |  |
| `getnewaddress` | yes |  |
| `gettransaction` | no |  |
| `getwalletinfo` | yes |  |
| `importdescriptors` | no |  |
| `importprivkey` | no | Core no longer has this method (it was legacy-wallet only). |
| `listdescriptors` | no | Wallets made by plain `createwallet` currently list no descriptors; see SECURITY.md. |
| `listlockunspent` | yes |  |
| `listtransactions` | yes |  |
| `listunspent` | yes |  |
| `listwalletdir` | no |  |
| `listwallets` | yes |  |
| `loadwallet` | yes |  |
| `lockunspent` | yes |  |
| `psbtbumpfee` | no |  |
| `rescanblockchain` | no |  |
| `restorewallet` | yes |  |
| `send` | yes |  |
| `sendtoaddress` | yes |  |
| `sethdseed` | no |  |
| `setlabel` | yes |  |
| `signmessage` | yes |  |
| `signrawtransactionwithwallet` | no |  |
| `unloadwallet` | yes |  |
| `walletcreatefundedpsbt` | yes |  |
| `walletlock` | yes |  |
| `walletpassphrase` | yes |  |
| `walletpassphrasechange` | no |  |
| `walletprocesspsbt` | yes |  |

### Payjoin (BIP-78, not in Core)

| Method | In `help` | Notes |
|---|---|---|
| `getpayjoinrequest` | no | Not in Core. |
| `sendpayjoinrequest` | no | Not in Core. |

### ZMQ

| Method | In `help` | Notes |
|---|---|---|
| `getzmqnotifications` | no | Always `[]`: there are no `-zmqpub*` startup options yet. |
