# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (rustoshi)

**Wave:** W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:**
- `crates/rpc/src/server.rs::start_rpc_server` (lines ~10836-10905) — jsonrpsee `ServerBuilder` wiring + plaintext bind path.
- `crates/rpc/src/tls.rs::serve_https` (lines 149-267) — HTTPS bind path.
- `crates/rpc/src/auth.rs` (entire file, 375 LOC) — `AuthLayer` / `AuthMiddleware` / `AuthCredentials` / `check_auth`.
- `crates/rpc/src/types.rs::RpcConfig` (lines 100-170) — server configuration struct.
- `rustoshi/src/main.rs::write_cookie_file` (lines 566-589) — `.cookie` file generation.
- `rustoshi/src/main.rs::delete_cookie_file` (lines 591-600) — cookie cleanup.
- `rustoshi/src/main.rs::Cli` (lines 51-289) — every `--rpc*` CLI flag.
- `rustoshi/src/main.rs::async_main` (lines 1620-2034) — RPC bind/auth wiring (cookie write + `RpcConfig` build).
- jsonrpsee 0.22.5 `ServerBuilder` defaults (`/home/work/.cargo/registry/.../jsonrpsee-server-0.22.5/src/server.rs:344-347`).

**Reference (Bitcoin Core):**
- `bitcoin-core/src/httpserver.cpp` — `HTTPServer` + `HTTPRequest` + libevent threadpool + `HTTPBindAddresses` + `InitHTTPAllowList` + `ClientAllowed`.
- `bitcoin-core/src/httpserver.h` — `DEFAULT_HTTP_THREADS=16`, `DEFAULT_HTTP_WORKQUEUE=64`, `DEFAULT_HTTP_SERVER_TIMEOUT=30`, `MAX_HEADERS_SIZE=8192`, `MAX_SIZE` body cap.
- `bitcoin-core/src/httprpc.cpp` — `HTTPReq_JSONRPC` + `RPCAuthorized` + `CheckUserAuthorized` (HMAC-SHA256 + `TimingResistantEqual`) + `InitRPCAuthentication` + `WWW_AUTH_HEADER_DATA` + 250 ms brute-force sleep + `g_rpc_whitelist` per-user method ACL.
- `bitcoin-core/src/rpc/request.cpp` — `GenerateAuthCookie` (32-byte CSPRNG, umask 0077, `-rpccookieperms`), `COOKIEAUTH_USER = "__cookie__"`, `COOKIEAUTH_FILE = ".cookie"`, `DeleteAuthCookie`.
- `bitcoin-core/src/rpc/protocol.h` — `HTTPStatusCode` enum (200, 204, 400, 401, 403, 404, 405, 500, 503) + `RPCErrorCode` (see W125).
- `bitcoin-core/share/rpcauth/rpcauth.py` — reference HMAC-SHA256 format `<user>:<salt>$<hash>`.
- `bitcoin-core/src/init.cpp` — `-rpcauth` / `-rpcuser` / `-rpcpassword` / `-rpccookiefile` / `-rpcallowip` / `-rpcbind` / `-rpcthreads` / `-rpcworkqueue` / `-rpcservertimeout` / `-rpcwhitelist` ArgsManager registration.

**Production code changes:** 0 (pure audit).
**Test file:** `crates/rpc/tests/test_w140_http_rpcauth.rs` — 30 gates, all `#[ignore]`-pinned xfail sentinels.

## Why this matters

The RPC interface is **the only authenticated, network-reachable control
plane** of a Bitcoin full node. A misconfigured node with weak auth or no
IP allowlist can be remote-controlled by anyone who can reach the port —
sweep the wallet, replace bantable peers, generate templates that drain
miner economics, or simply DoS the daemon by exhausting its workqueue.

Core's HTTP/RPC surface is consequently one of its most paranoid
modules:
- HMAC-SHA256 password hashing (`rpcauth` lines) so the plaintext password
  is never in the config file or process memory beyond startup.
- Constant-time (`TimingResistantEqual`) hash comparison to prevent
  remote timing oracle attacks against the salt+hash.
- 250 ms wall-clock sleep on every failed authentication to deter
  online brute-force.
- A default-deny IP ACL: refuse to bind to anything except localhost
  unless **both** `-rpcallowip` and `-rpcbind` are explicitly specified,
  with a clear warning logged at startup if the operator binds to
  `0.0.0.0`/`::` or to a non-loopback subnet.
- A bounded workqueue (`-rpcworkqueue=64`) + bounded thread pool
  (`-rpcthreads=16`) so a slow `getblock` doesn't starve `getpeerinfo`.
- HTTP 401 with `WWW-Authenticate: Basic realm="jsonrpc"` for missing /
  wrong credentials, HTTP 403 for IP not in ACL or method not in
  per-user whitelist, HTTP 503 for workqueue overflow.

rustoshi gets a handful of these right (cookie file with `0o600`,
`__cookie__` username convention, base64 + colon-split decode, batch
limit, `WWW-Authenticate` header) but **misses the security-critical
defenses**:

1. **No IP allowlist anywhere.** Anyone who can reach the RPC port
   only needs to know the cookie OR the rpcuser/rpcpassword. There is
   no `--rpcallowip` flag, no subnet CIDR parser, no `ClientAllowed`
   middleware. Binding to `0.0.0.0:8332` is silently accepted without
   any safety net.
2. **No HMAC-SHA256 / `rpcauth` flag.** Cleartext rpcuser/rpcpassword
   is the only non-cookie auth path. There is no way to deploy
   rustoshi with the hashed credentials format every Bitcoin Core
   ops guide recommends.
3. **String `==` password compare** (`auth.rs:67`, `auth.rs:62`) —
   non-constant-time. Variable-time UTF-8 byte comparison leaks the
   first differing byte position via timing on a network round trip.
4. **No 250 ms brute-force sleep** on failed auth — an attacker can
   probe ~thousands of guesses per second per TCP connection.

The first two are **P0-SEC** with direct deployment impact: any operator
who follows the standard `-rpcuser`/`-rpcpassword`/`-rpcallowip` pattern
from the Core docs will be silently running a wide-open node.

## Headline findings

- **3 P0-SEC** (security-critical, immediate deployment risk):
  - **BUG-1**: No `--rpcallowip` CLI flag, no subnet/CIDR ACL middleware.
    The HTTP server has zero source-address filtering. Operator binds
    to `--rpcbind=0.0.0.0:8332` thinking Core's "deny by default unless
    rpcallowip is set" semantics apply; rustoshi happily serves
    authenticated requests from anywhere on the network.
  - **BUG-2**: No `--rpcauth` flag, no HMAC-SHA256 password verification.
    Only cleartext `--rpcuser`/`--rpcpassword` (plain string compare) +
    cookie file. Operators following Core's standard "use rpcauth for
    multi-user setups, never plaintext" guidance have nowhere to put
    their `<user>:<salt>$<hash>` lines.
  - **BUG-3**: Password compare is `==` (`auth.rs:67`, `:62`). Core uses
    `TimingResistantEqual` (constant-time XOR-loop) at `httprpc.cpp:66,77`.
    Network-observable timing oracle.

- **1 P0-OPS** (operator pain, parity with W124 BUG-13):
  - **BUG-4**: Cookie file is written to `base_datadir` (`main.rs:1983`),
    not the network-specific subdir. Core writes to
    `<datadir>/<network>/.cookie` (mainnet: `<datadir>/.cookie`;
    testnet4: `<datadir>/testnet4/.cookie`; etc.).
    `bitcoin-cli -conf=… -datadir=… -testnet4` looks for the cookie in
    the testnet4 subdir and silently fails over to "no cookie", forcing
    a manual `-rpccookiefile=` path override.

- **3 P1** (defense-in-depth + spec compliance):
  - **BUG-5**: No brute-force 250 ms sleep on failed auth. Core's
    `httprpc.cpp:128` `UninterruptibleSleep(250ms)` after a failed
    `RPCAuthorized` is one of the cheapest, highest-leverage anti-
    bruteforce primitives in the codebase. Absent here.
  - **BUG-6**: No `--rpcbind` multi-bind support. The flag accepts a
    single `host:port` and the server binds exactly once. Core accepts
    `-rpcbind=` repeatedly and binds every endpoint (IPv4 loopback +
    IPv6 loopback + LAN address, typically). One TCP listener means no
    way to bind both `127.0.0.1:8332` and `[::1]:8332` simultaneously
    without an external proxy.
  - **BUG-7**: No `--rpcwhitelist` / per-user method ACL. Core's
    `g_rpc_whitelist` (`httprpc.cpp:38,146,154,184`) returns 403 if a
    whitelisted user calls a non-whitelisted method. Rustoshi: every
    authenticated user can call every method, including `stop`,
    `setban`, `disconnectnode`, `getbalance`.

- **2 P1-OPS** (operational parity):
  - **BUG-8**: No `--rpcthreads` or `--rpcworkqueue` knobs. The jsonrpsee
    tokio-based server uses runtime worker threads (`#[tokio::main]`),
    so the Core threadpool/queue concept doesn't map directly — but the
    operator-visible knobs (`-rpcthreads=N`, `-rpcworkqueue=M`) are
    completely missing. Capacity tuning requires recompilation.
  - **BUG-9**: No `--rpcservertimeout` knob. Core's `-rpcservertimeout=30`
    sets `evhttp_set_timeout(http, 30)` — request-level idle timeout.
    The jsonrpsee server has no equivalent operator-visible knob.

- **2 P2** (HTTP/protocol spec compliance):
  - **BUG-10**: 503 on workqueue overflow not surfaced. Core writes
    HTTP 503 + body `"Work queue depth exceeded"` when the threadpool
    queue is full. rustoshi has no equivalent surface (because there is
    no work queue concept on the jsonrpsee path) — but also no fallback
    surface for any kind of "server temporarily overloaded" signal.
  - **BUG-11**: 405 `BAD_METHOD` not emitted for non-POST requests.
    Core's `HTTPReq_JSONRPC` rejects GET/PUT/HEAD with HTTP 405. jsonrpsee
    accepts only POST but emits 200 + JSON-RPC parse error, not 405.

- **3 P3** (defaults / cosmetic):
  - **BUG-12**: `max_request_body_size` is jsonrpsee default 10 MB, Core's
    `MAX_SIZE` is ~32 MB — 1 (effectively unbounded). Submitting a
    `submitblock` for a 4 MB witness-heavy block works today; a future
    large-weight block might 413.
  - **BUG-13**: `max_connections` is jsonrpsee default 100 (per
    `jsonrpsee-server-0.22.5/src/server.rs:68`). Core has no analogous
    per-RPC-connection cap (it relies on threadpool back-pressure +
    workqueue). Not operator-visible.
  - **BUG-14**: `RPC_IN_WARMUP` (-28) not returned with HTTP 503 during
    chain warmup. Cross-ref W125 BUG-4. Core's `httprpc.cpp` returns
    "loading block index…" with HTTP 503 + RPC -28 until validation is
    ready; rustoshi has no warmup gate.

## Gate summary (30 / 30)

| #   | Surface                                                          | Status   | Code   | Severity |
|-----|------------------------------------------------------------------|----------|--------|----------|
| G1  | `.cookie` file written at `<datadir>/.cookie`                    | PARTIAL  | BUG-4  | P0-OPS   |
| G2  | Cookie file permissions `0o600`                                  | OK       | —      | —        |
| G3  | Cookie username literal `__cookie__`                             | OK       | —      | —        |
| G4  | Cookie file deleted on shutdown                                  | OK       | —      | —        |
| G5  | Cookie file in network-specific subdir (testnet/regtest)         | MISSING  | BUG-4  | P0-OPS   |
| G6  | `--rpcauth` flag + HMAC-SHA256 password verification             | MISSING  | BUG-2  | P0-SEC   |
| G7  | `<user>:<salt>$<hash>` rpcauth format parser                     | MISSING  | BUG-2  | P0-SEC   |
| G8  | rpcuser/rpcpassword cleartext fallback (legacy)                  | OK       | —      | —        |
| G9  | Constant-time password / HMAC comparison                         | MISSING  | BUG-3  | P0-SEC   |
| G10 | `--rpcallowip` flag                                              | MISSING  | BUG-1  | P0-SEC   |
| G11 | Subnet / CIDR (IPv4 + IPv6) parser                               | MISSING  | BUG-1  | P0-SEC   |
| G12 | `ClientAllowed`-style source-IP middleware                       | MISSING  | BUG-1  | P0-SEC   |
| G13 | Default-deny: refuse non-loopback bind without explicit ACL      | MISSING  | BUG-1  | P0-SEC   |
| G14 | HTTP 401 + `WWW-Authenticate: Basic realm="jsonrpc"`             | OK       | —      | —        |
| G15 | HTTP 403 on rpcallowip ACL miss                                  | MISSING  | BUG-1  | P0-SEC   |
| G16 | HTTP 405 `BAD_METHOD` for non-POST                               | MISSING  | BUG-11 | P2       |
| G17 | HTTP 503 on workqueue overflow                                   | MISSING  | BUG-10 | P2       |
| G18 | HTTP 503 on `RPC_IN_WARMUP` startup gate                         | MISSING  | BUG-14 | P3       |
| G19 | 250 ms brute-force sleep on failed auth                          | MISSING  | BUG-5  | P1       |
| G20 | JSON-RPC 1.0 + 2.0 version coexistence                           | PARTIAL  | —      | P3       |
| G21 | JSON-RPC batch requests bounded (≤1000 in Core, ≤1000 here)      | OK       | —      | —        |
| G22 | `--rpcbind` multi-bind support                                   | MISSING  | BUG-6  | P1       |
| G23 | `--rpcwhitelist` per-user method ACL                             | MISSING  | BUG-7  | P1       |
| G24 | `-rpcwhitelistdefault` deny-list default                         | MISSING  | BUG-7  | P1       |
| G25 | `--rpcthreads` operator-visible thread-count knob                | MISSING  | BUG-8  | P1-OPS   |
| G26 | `--rpcworkqueue` operator-visible queue-depth knob               | MISSING  | BUG-8  | P1-OPS   |
| G27 | `--rpcservertimeout` per-request timeout knob                    | MISSING  | BUG-9  | P1-OPS   |
| G28 | `max_request_body_size` ≥ Core's MAX_SIZE (~32 MB)               | PARTIAL  | BUG-12 | P3       |
| G29 | TLS / HTTPS opt-in (cert+key required together)                  | OK       | —      | —        |
| G30 | `/wallet/<name>/` path prefix dispatcher                         | MISSING  | —      | P3       |

**Tally**:
- 5 OK (regression pins).
- 3 PARTIAL.
- 22 MISSING.
- 3 P0-SEC, 1 P0-OPS, 5 P1, 1 P2, 4 P3 (gate-row count of severities).
- BUG count: 14 unique BUGs (BUG-1..BUG-14).

## Full bug table (P0-SEC first)

### P0-SEC — Security-critical (immediate deployment risk)

**BUG-1 (P0-SEC)** — Missing IP-allowlist + ACL middleware.
- **Sites (absence)**: `rustoshi/src/main.rs` (no `--rpcallowip` flag in
  CLI between lines 51-289), `crates/rpc/src/server.rs::start_rpc_server`
  (no `ClientAllowed`-equivalent in the middleware stack at lines
  10840-10905), `crates/rpc/src/auth.rs` (no source-IP check in
  `AuthMiddleware::call`).
- **Core surface**: `httpserver.cpp:137-145` `ClientAllowed(const CNetAddr&)`;
  `:148-168` `InitHTTPAllowList()` (default-allow `127.0.0.0/8` + `::1`,
  add each `-rpcallowip` subnet); `:217-222` early-reject 403 in
  `http_request_cb`; `:319-326` refuse non-loopback bind if `-rpcallowip`
  is empty AND `-rpcbind` is empty.
- **Operator impact**: rustoshi accepts authenticated RPC from any
  source IP that can reach the bound port. An operator who sets
  `--rpcbind=0.0.0.0:8332 --rpcuser=alice --rpcpassword=pw` (because
  they want LAN access) gets a node any LAN attacker can drive once
  they brute-force or guess `pw`. With BUG-5 (no sleep deterrent),
  that's hours not weeks on a weak password.
- **Severity**: P0-SEC. Direct exposure.

**BUG-2 (P0-SEC)** — Missing `--rpcauth` (HMAC-SHA256) authentication.
- **Sites (absence)**: `rustoshi/src/main.rs::Cli` lines 51-289 have no
  `--rpcauth` flag; `crates/rpc/src/types.rs::RpcConfig` lines 100-170
  has no `rpc_auth_entries` field; `crates/rpc/src/auth.rs::AuthCredentials`
  lines 47-73 only supports `cookie_secret` + cleartext `user_pass`.
  No `hmac` / `sha2::HMAC` import anywhere in `crates/rpc/src/`.
- **Core surface**: `httprpc.cpp:63-82` `CheckUserAuthorized` walks
  `g_rpcauth: Vec<[user, salt, hash]>`, runs `CHMAC_SHA256(salt).Write(pass).Finalize()`,
  compares `HexStr(out) ==_TimingResistant hash`; `:240-329`
  `InitRPCAuthentication` parses `-rpcauth=user:salt$hash` lines from
  `<datadir>/bitcoin.conf` and from CLI; `:288` hashes any plaintext
  `-rpcpassword` with a fresh random salt on startup so it isn't
  retained as plaintext beyond init.
- **Operator impact**: rustoshi only supports cleartext passwords or
  the cookie. Every published Core ops guide (run-as-systemd-unit,
  multi-user installs, `bitcoin-cli` shared deployments) recommends
  `rpcauth`. Operators copying their `bitcoin.conf` get a "unknown
  option `rpcauth`" warning (BUG-12 W124) and end up either falling
  back to cleartext (worse) or disabling auth.
- **Severity**: P0-SEC. Deployment parity gap.

**BUG-3 (P0-SEC)** — Non-constant-time password compare.
- **Site**: `crates/rpc/src/auth.rs:62` `return pass == secret;` (cookie
  path); `:67` `if user == u && pass == p { return true; }` (rpcuser
  path).
- **Core surface**: `httprpc.cpp:66-77` `TimingResistantEqual(user_view, fields[0])`
  + `TimingResistantEqual(hash_from_pass, hash)` (both used inside
  `CheckUserAuthorized` — constant-time XOR loop in `util/strencodings.cpp`).
- **Operator impact**: Rust `==` on `&str` is the libcore `slice::eq`
  which short-circuits at the first byte mismatch. The wall-clock
  delta between "first byte wrong" and "byte 30 wrong" is small (~ns
  on a hot cache), but observable across a TCP RTT over enough samples
  (~10⁴ for a 1-byte oracle on a 1 Gbps LAN). Combined with cleartext
  passwords (no hash to oracle, just the password itself), this is
  the simplest possible timing attack surface.
- **Severity**: P0-SEC. Network-observable.

### P0-OPS — Operator-pain parity

**BUG-4 (P0-OPS)** — Cookie file in wrong directory.
- **Site**: `rustoshi/src/main.rs:1983` `let cookie_secret = write_cookie_file(&base_datadir)?;`
  uses `base_datadir` (the network-naked path, e.g. `~/.rustoshi/`),
  not the network-specific `datadir` (`~/.rustoshi/testnet4/`).
- **Core surface**: `rpc/request.cpp:86-96` `GetAuthCookieFile` resolves
  via `AbsPathForConfigVal(gArgs, arg)` which uses the network-specific
  datadir per `bitcoin-cli`'s standard `-testnet4` flag.
- **Operator impact**: Cross-references W124 BUG-13. `bitcoin-cli
  -testnet4 -datadir=~/.rustoshi getblockcount` looks for the cookie at
  `~/.rustoshi/testnet4/.cookie` (Core's convention) and fails. The
  operator either passes `-rpccookiefile=~/.rustoshi/.cookie` or falls
  back to cleartext `-rpcuser`/`-rpcpassword`.
- **Severity**: P0-OPS. Operator-visible parity break with every
  Core/Knots/btcd guide.

### P1 — Defense-in-depth + spec compliance

**BUG-5 (P1)** — Missing 250 ms brute-force sleep on failed auth.
- **Site (absence)**: `crates/rpc/src/auth.rs::check_auth` returns the
  401 response synchronously. No `tokio::time::sleep`.
- **Core surface**: `httprpc.cpp:128` `UninterruptibleSleep(std::chrono::milliseconds{250});`
  fires after every failed `RPCAuthorized`.
- **Severity**: P1 (defense-in-depth).

**BUG-6 (P1)** — `--rpcbind` is single-value.
- **Site**: `rustoshi/src/main.rs:64` `#[arg(long, default_value = "127.0.0.1:8332")] rpcbind: String,`
  — single `String`, not `Vec<String>`.
- **Core surface**: `httpserver.cpp:329-338` iterates `gArgs.GetArgs("-rpcbind")`
  and binds every entry.
- **Severity**: P1.

**BUG-7 (P1)** — Missing per-user method whitelist.
- **Site (absence)**: No `--rpcwhitelist` / `--rpcwhitelistdefault` flag
  in `main.rs::Cli`; no per-user `HashMap<String, HashSet<String>>` in
  `crates/rpc/src/auth.rs` or `server.rs`.
- **Core surface**: `httprpc.cpp:36-39` `g_rpc_whitelist` +
  `g_rpc_whitelist_default`; `:146-149` 403 for whitelisted user not
  allowed any method; `:154-158` per-method check.
- **Severity**: P1.

**BUG-8 (P1-OPS)** — Missing `--rpcthreads` / `--rpcworkqueue` knobs.
- **Site (absence)**: No flags in `main.rs::Cli`. Server uses tokio
  runtime's worker count (defaults to CPU count via `#[tokio::main]`).
  jsonrpsee 0.22 `ServerBuilder` does expose
  `max_connections(u32)` and a tower `concurrency_limit` middleware
  could approximate a workqueue, but neither is exposed.
- **Core surface**: `httpserver.h:20` `DEFAULT_HTTP_THREADS=16`;
  `:26` `DEFAULT_HTTP_WORKQUEUE=64`; `httpserver.cpp:419-420` reads
  `-rpcworkqueue`; `:440-444` reads `-rpcthreads`.
- **Severity**: P1-OPS.

**BUG-9 (P1-OPS)** — Missing `--rpcservertimeout`.
- **Site (absence)**: No `--rpcservertimeout` in `main.rs::Cli`. jsonrpsee
  0.22 has no per-request idle timeout via its builder; would need a
  tower `Timeout` middleware.
- **Core surface**: `httpserver.cpp:408` `evhttp_set_timeout(http,
  gArgs.GetIntArg("-rpcservertimeout", 30));`.
- **Severity**: P1-OPS.

### P2 — Spec compliance

**BUG-10 (P2)** — Missing 503 + workqueue-overflow surface.
- **Site (absence)**: No `WorkQueueSize`-based 503 path. Tokio task
  spawn never bounds, so concurrent RPC requests fan out without
  back-pressure; system runs out of FDs first.
- **Core surface**: `httpserver.cpp:255-259` `if (g_threadpool_http.WorkQueueSize() >= g_max_queue_depth)`
  → `WriteReply(HTTP_SERVICE_UNAVAILABLE, "Work queue depth exceeded")`.
- **Severity**: P2.

**BUG-11 (P2)** — Missing HTTP 405 for non-POST.
- **Site (absence)**: jsonrpsee returns 200 + JSON-RPC parse error for
  GET/PUT/HEAD instead of 405. No early method-check middleware.
- **Core surface**: `httprpc.cpp:107-110`
  `if (req->GetRequestMethod() != HTTPRequest::POST) WriteReply(HTTP_BAD_METHOD,
  "JSONRPC server handles only POST requests");`.
- **Severity**: P2.

### P3 — Defaults / cosmetic / future-proofing

**BUG-12 (P3)** — `max_request_body_size` 10 MB vs Core's ~32 MB.
- **Site**: `crates/rpc/src/server.rs:10890-10898` builds `ServerBuilder`
  without calling `.max_request_body_size(...)`; jsonrpsee default
  (`jsonrpsee-server-0.22.5/src/server.rs:344` =
  `TEN_MB_SIZE_BYTES`) applies.
- **Core surface**: `httpserver.cpp:410` `evhttp_set_max_body_size(http,
  MAX_SIZE)` where `MAX_SIZE = 0x02000000 - 1 = 33,554,431` bytes.
- **Operator impact**: `submitblock` of a large block (close to 4 MB
  serialized; a future increase to weight units could push to 8 MB+
  serialized) silently 413s. Not user-visible today but quietly time-
  bombed.
- **Severity**: P3.

**BUG-13 (P3)** — `max_connections=100` jsonrpsee default vs Core's
"unbounded but back-pressured by threadpool".
- **Site**: `crates/rpc/src/server.rs:10890-10898` doesn't call
  `.max_connections(...)`; jsonrpsee default of 100 applies. Not
  obviously a parity break (Core has its own back-pressure), but
  100 is low enough that a slow client + 100 hung connections =
  service denial.
- **Severity**: P3.

**BUG-14 (P3)** — Missing `RPC_IN_WARMUP` / 503 startup gate.
- **Site (absence)**: RPC server starts handling requests immediately
  after `start_rpc_server.await?` returns; chain state may still be in
  `loadblockindex`/`replayblocks`. No equivalent of Core's
  `RPCSetTimerInterface` / `SetRPCWarmupFinished`.
- **Core surface**: `httprpc.cpp` returns 503 with
  `{"code": -28, "message": "Loading block index…"}` for any method
  before `SetRPCWarmupFinished()` is called.
- **Cross-ref**: W125 BUG-4.
- **Severity**: P3.

## Suggested FIX waves (priority order)

| Wave   | Scope                                                    | Bugs                |
|--------|----------------------------------------------------------|---------------------|
| FIX-W1 | Wire `--rpcallowip` flag + CIDR parser + IP ACL middleware | BUG-1               |
| FIX-W2 | Wire `--rpcauth` flag + HMAC-SHA256 + constant-time HMAC compare | BUG-2, BUG-3        |
| FIX-W3 | Move cookie write to network-specific datadir            | BUG-4               |
| FIX-W4 | 250 ms `tokio::time::sleep` on `check_auth` failure path | BUG-5               |
| FIX-W5 | `--rpcbind` → `Vec<String>`; bind every entry            | BUG-6               |
| FIX-W6 | `--rpcwhitelist` per-user method ACL middleware          | BUG-7               |
| FIX-W7 | `--rpcthreads` (tokio worker count) + `--rpcworkqueue`
          (tower `ConcurrencyLimit`)                                | BUG-8               |
| FIX-W8 | `--rpcservertimeout` via tower `Timeout` layer           | BUG-9               |
| FIX-W9 | 405 for non-POST + 503 for workqueue overflow            | BUG-10, BUG-11      |
| FIX-W10| `max_request_body_size = 32 MB`; document `max_connections` knob | BUG-12, BUG-13      |
| FIX-W11| `RPC_IN_WARMUP` 503 + warmup-finished gate               | BUG-14              |

FIX-W1, FIX-W2, FIX-W3, FIX-W4 are the P0 cluster. Closing them
restores Core-grade security defaults for any rustoshi deployment that
isn't strictly loopback-only with cookie auth.

## Cross-cutting findings

- **8 of 30 gates (G6-G13, G19) are gated on auth/ACL primitives that
  don't exist in the codebase.** The fix is single-crate (`rustoshi-rpc`)
  + CLI wiring (`rustoshi/src/main.rs`), no consensus or storage
  touch — high-leverage closure.
- **The Tower middleware shape is good** (the `AuthLayer` is a clean
  insertion point for an `AllowIpLayer` + a `RpcAuthLayer` + a
  `WhitelistLayer`). The audit's verdict isn't "rewrite the auth
  stack" — it's "wire the missing primitives into the existing
  middleware chain".
- **Cookie + HTTPS path is correctly built**. Cookie permissions are
  `0o600`, the username convention matches Core, cookie deletion fires
  on shutdown, and the HTTPS opt-in cert+key validation rejects an
  asymmetric config. **6 of 30 gates pass cleanly** (G2, G3, G4, G8,
  G14, G21, G29 — 7 actually).
- **W124 BUG-13 (cookie lifecycle PARTIAL) is the same surface as our
  BUG-4 here**. W124 found cookie regeneration races / late-delete
  warnings; W140 finds the cookie *location* is wrong. They are
  complementary but not duplicates.
- **W125 BUG-4 (`RPC_IN_WARMUP` absence) overlaps with our BUG-14**.
  Same missing surface, different lens — W125 from the JSON-RPC error
  code side, W140 from the HTTP status side. Both need fixing in the
  same FIX wave.
- **No production code touched in this commit.** All 30 gate tests
  are `#[ignore]`-pinned compile-time sentinels that document the
  presence/absence of specific symbols, flags, and middleware. When a
  fix wave lands, the corresponding gate flips from `#[ignore]` to
  active assertion in the same commit, matching the pattern
  established by W120/W121/W124/W125.

## References

### Core source citations

- `bitcoin-core/src/httpserver.cpp:51` — `MAX_HEADERS_SIZE = 8192`.
- `bitcoin-core/src/httpserver.cpp:71-74` — `rpc_allow_subnets` global.
- `bitcoin-core/src/httpserver.cpp:78-79` — `g_threadpool_http` + `g_max_queue_depth`.
- `bitcoin-core/src/httpserver.cpp:137-145` — `ClientAllowed`.
- `bitcoin-core/src/httpserver.cpp:148-168` — `InitHTTPAllowList`.
- `bitcoin-core/src/httpserver.cpp:217-222` — 403 reject in
  `http_request_cb` before dispatch.
- `bitcoin-core/src/httpserver.cpp:225-229` — 405 for non-POST.
- `bitcoin-core/src/httpserver.cpp:255-259` — 503 workqueue overflow.
- `bitcoin-core/src/httpserver.cpp:309-360` — `HTTPBindAddresses` +
  default-deny non-loopback bind.
- `bitcoin-core/src/httpserver.cpp:408-410` — `evhttp_set_timeout`,
  `evhttp_set_max_headers_size`, `evhttp_set_max_body_size`.
- `bitcoin-core/src/httpserver.cpp:419-420` — `g_max_queue_depth`.
- `bitcoin-core/src/httpserver.cpp:440-444` — thread pool start.
- `bitcoin-core/src/httpserver.h:20,26,28` — `DEFAULT_HTTP_THREADS=16`,
  `DEFAULT_HTTP_WORKQUEUE=64`, `DEFAULT_HTTP_SERVER_TIMEOUT=30`.
- `bitcoin-core/src/httprpc.cpp:33` — `WWW_AUTH_HEADER_DATA`.
- `bitcoin-core/src/httprpc.cpp:36-39` — `g_rpcauth`, `g_rpc_whitelist`.
- `bitcoin-core/src/httprpc.cpp:63-82` — `CheckUserAuthorized` HMAC-SHA256
  + `TimingResistantEqual`.
- `bitcoin-core/src/httprpc.cpp:84-102` — `RPCAuthorized` Basic decode.
- `bitcoin-core/src/httprpc.cpp:107-110` — 405 for non-POST.
- `bitcoin-core/src/httprpc.cpp:113-117` — 401 + `WWW-Authenticate`.
- `bitcoin-core/src/httprpc.cpp:122-132` — 250 ms sleep + 401 on auth fail.
- `bitcoin-core/src/httprpc.cpp:146-158` — per-user whitelist 403.
- `bitcoin-core/src/httprpc.cpp:240-329` — `InitRPCAuthentication`
  (`-rpcauth`, `-rpcuser`, `-rpcpassword`, `-rpcwhitelist`).
- `bitcoin-core/src/rpc/request.cpp:81-83` — `COOKIEAUTH_USER`,
  `COOKIEAUTH_FILE`.
- `bitcoin-core/src/rpc/request.cpp:100-146` — `GenerateAuthCookie`.
- `bitcoin-core/src/rpc/request.cpp:148-165` — `GetAuthCookie`.
- `bitcoin-core/src/rpc/request.cpp:167-177` — `DeleteAuthCookie`.
- `bitcoin-core/src/rpc/protocol.h:10-21` — HTTP status enum.

### Rustoshi-side citations

- `rustoshi/src/main.rs:51-289` — `Cli` (search for `rpcauth` /
  `rpcallowip` / `rpcbind` Vec / `rpcwhitelist` / `rpcthreads` /
  `rpcworkqueue` / `rpcservertimeout` — all absent).
- `rustoshi/src/main.rs:63-64` — single-bind `--rpcbind`.
- `rustoshi/src/main.rs:66-72` — `--rpcuser` / `--rpcpassword`.
- `rustoshi/src/main.rs:551-560` — `default_rpc_port`.
- `rustoshi/src/main.rs:566-589` — `write_cookie_file` (writes to
  `base_datadir`, not network-specific datadir).
- `rustoshi/src/main.rs:591-600` — `delete_cookie_file`.
- `rustoshi/src/main.rs:1620-1626` — `rpc_bind` selection.
- `rustoshi/src/main.rs:1983` — cookie write at `base_datadir` (BUG-4).
- `rustoshi/src/main.rs:1986-1995` — `RpcConfig` build.
- `crates/rpc/src/types.rs:104-170` — `RpcConfig` struct.
- `crates/rpc/src/auth.rs:42-73` — `AuthCredentials` + `verify`
  (BUG-2 absent rpcauth, BUG-3 non-constant-time).
- `crates/rpc/src/auth.rs:81-101` — `AuthLayer`.
- `crates/rpc/src/auth.rs:104-218` — `AuthMiddleware` (BUG-1 no IP ACL,
  BUG-5 no sleep, BUG-7 no whitelist).
- `crates/rpc/src/auth.rs:229-277` — `check_auth` helper.
- `crates/rpc/src/server.rs:10815` — `MAX_BATCH_SIZE = 1000` (G21 OK).
- `crates/rpc/src/server.rs:10836-10905` — `start_rpc_server` (single bind,
  no body-size override, no concurrency-limit middleware).
- `crates/rpc/src/server.rs:10890-10898` — `ServerBuilder` default
  request body 10 MB (BUG-12).
- `crates/rpc/src/tls.rs:56-131` — `load_tls_config` (G29 OK).
- `crates/rpc/src/tls.rs:149-267` — `serve_https` (single bind, single
  TLS config).
- `/home/work/.cargo/registry/.../jsonrpsee-server-0.22.5/src/server.rs:68`
  — `MAX_CONNECTIONS = 100` (BUG-13 framework default).
- `/home/work/.cargo/registry/.../jsonrpsee-server-0.22.5/src/server.rs:344`
  — `max_request_body_size: TEN_MB_SIZE_BYTES` (BUG-12 framework default).

### Cross-wave references

- **W124** — operator experience. BUG-13 there (cookie file lifecycle
  PARTIAL) overlaps with our BUG-4 (cookie file in wrong directory).
- **W125** — JSON-RPC error parity. BUG-4 (`RPC_IN_WARMUP` -28
  absence) overlaps with our BUG-14 (HTTP 503 + RPC -28 startup gate).
- **W141** — RPC content-type / batch behavior (concurrent wave): may
  collide on JSON-RPC version normalization in `auth.rs:160-212`.
- **W138 / W139** — concurrent waves; no expected overlap with HTTP/auth
  surface.
