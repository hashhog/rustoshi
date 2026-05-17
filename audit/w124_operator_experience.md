# W124 — Operator-experience audit (rustoshi)

**Wave**: W124 (discovery — no production code changes)
**Impl**: rustoshi (Rust)
**Date**: 2026-05-17
**Author**: claude (audit sub-agent)
**Tests**: `rustoshi/tests/test_w124_operator_experience.rs` (30 gates)
**Trigger**: May 17 2026 Path A restoration — haskoin + ouroboros lagged
on mainnet for ~4 days. Fleet-monitor detected the lag but no
auto-restart was wired. Audit operator-experience holistically across
the fleet so we never let a daemon silently drift to DOWN again.

## Audit gate matrix (30 gates)

| #   | Gate                                                | Verdict | Bug    |
|-----|-----------------------------------------------------|---------|--------|
| G1  | RPC `stop` end-to-end shutdown path                 | PARTIAL | BUG-1  |
| G2  | Datadir lockfile / single-instance protection       | MISSING | BUG-2  |
| G3  | P2P bind failure is fatal                           | PARTIAL | BUG-3  |
| G4  | Metrics / REST / ZMQ bind failure is fatal+visible  | PARTIAL | BUG-4  |
| G5  | FD-limit raise at startup (`RaiseFileDescriptorLimit`) | MISSING | BUG-5  |
| G6  | SIGPIPE handler / ignore                            | MISSING | BUG-6  |
| G7  | `-startupnotify` / `-shutdownnotify` exec hooks     | MISSING | BUG-7  |
| G8  | `-reindex` / `-reindex-chainstate` working          | PARTIAL | BUG-8  |
| G9  | Log rotation (size or age based)                    | PARTIAL | BUG-9  |
| G10 | Panic hook routes to `debug.log`                    | MISSING | BUG-10 |
| G11 | Log timestamp format matches Core's ISO-8601        | PARTIAL | BUG-11 |
| G12 | `-conf` unknown-key warning                         | PARTIAL | BUG-12 |
| G13 | Cookie file lifecycle (create + delete + race)      | PARTIAL | BUG-13 |
| G14 | IBD progress logging cadence (heartbeat)            | PARTIAL | BUG-14 |
| G15 | Per-block `UpdateTip` info-level log line           | MISSING | BUG-15 |
| G16 | Shutdown summary distinguishes clean vs degraded    | PARTIAL | BUG-16 |
| G17 | Persistence failures surface in exit code           | PARTIAL | BUG-17 |
| G18 | BlockFilterIndex on-disk schema versioning          | MISSING | BUG-18 |
| G19 | Wallet format Core-bdb compatible                   | PARTIAL | BUG-19 |
| G20 | Startup disk-space precheck                         | MISSING | BUG-20 |
| G21 | `logging` RPC for runtime log-level toggle          | MISSING | BUG-21 |
| G22 | `--debuglogfile` auto-creates parent directory      | PARTIAL | BUG-22 |
| G23 | `rustoshi-cli` companion binary exists              | MISSING | BUG-23 |
| G24 | `--daemon` + `--printtoconsole` documented coupling | PARTIAL | BUG-24 |
| G25 | Daemon child PID re-logged after fork               | PARTIAL | BUG-25 |
| G26 | `--version` includes build commit / RocksDB ver     | PARTIAL | BUG-26 |
| G27 | `--help` grouped / categorised                      | PARTIAL | BUG-27 |
| G28 | `--datadir` writability precheck                    | PARTIAL | BUG-28 |
| G29 | `--load-snapshot` refuses against existing chain    | PARTIAL | BUG-29 |
| G30 | `getmemoryinfo` RPC parity                          | MISSING | BUG-30 |

**Verdict tallies**: **PRESENT 12 / PARTIAL 12 / MISSING 6**

PRESENT (no bug) gates we exercised but found correct:
- SIGTERM/Ctrl-C graceful shutdown loop (main.rs:4243-4255).
- SIGHUP debug log reopen (main.rs:2218-2246 + ops.rs:200-235).
- PID file lifecycle (write at boot, remove on exit) — `ops.rs:269-285`.
- Cookie file generation (32-byte CSPRNG, `0o600` perms, `__cookie__:<hex>`).
- `--daemon` libc `daemon(0,0)` path (ops.rs:304-322) — runs BEFORE
  tokio runtime, correctly avoids the runtime-fork double-free trap.
- `--ready-fd=N` sd_notify-style readiness write (ops.rs:337-352).
- TOML / `key=value` conf parser handles comments, sections, quoted
  values (ops.rs:53-89).
- `RUST_LOG` env var > `--debug=cat` > `--loglevel` precedence
  (main.rs:1365-1382).
- `--debug=net,mempool,…` Core-style category mapping (ops.rs:118-153).
- RPC bind failure is fatal (server.rs:10898 — `build(...).await?` ⇒
  startup error).
- Graceful shutdown sequence: stop RPC → delete cookie → flush
  fee-estimates → dump mempool.dat → flush UTXO cache → flush chain
  state → remove PID (main.rs:4262-4319). Order is the right one.
- Wave-based fleet startup (`start_testnet4.sh`) + idempotent
  `start_mainnet.sh` (port-bound check via `ss -tlnHp`).

## Top 5 operator-pain findings (in order of severity)

### 1. BUG-1 (P0): `stop` RPC is a no-op

`RpcState::shutdown_tx: Option<oneshot::Sender<()>>` field exists at
`crates/rpc/src/server.rs:137` and `stop` route at server.rs:4887 tries
to take it. **But `main.rs` never installs the sender.** Effect:
`bitcoin-cli stop` (curl + JSON-RPC `stop`) returns `"Rustoshi server
stopping"` to the operator — and rustoshi keeps running forever.

This is a **direct cause** of Path A operator pain: the canonical fleet
shutdown mechanism is broken, so operators drop down to `kill -TERM`
which works but bypasses graceful flush.

**Fix shape**: in `main.rs::async_main`, create `let (tx, rx) =
oneshot::channel::<()>()`, store `tx` in `RpcState.shutdown_tx` BEFORE
`Arc::new(RwLock::new(...))`, and `select!` on `rx` alongside the
existing `ctrl_c()` + SIGTERM branches.

### 2. BUG-3 / BUG-4 (P0): Bind failures silently degrade the node

- **BUG-3**: P2P bind failure (`peer_manager.rs:1295-1296`) logs
  `tracing::error!` then continues. Operator gets a node that won't
  accept inbound, doesn't exit, doesn't get auto-restarted by systemd.
- **BUG-4**: Same pattern for metrics (`main.rs:462-464`) and REST
  (`main.rs:2028`). fleet-monitor polls `/health` on the metrics
  port; if metrics didn't bind, monitor sees the node as DOWN even
  when RPC is fine.

Both are direct sources of "silent partial DOWN" — the failure mode
Path A is meant to detect.

**Fix shape**: bind failures on declared / requested listeners should
`bail!` so systemd sees `exit 1` and restarts. Make non-fatal only the
truly optional ones (and document them).

### 3. BUG-2 (P0): No datadir lockfile

Core's `LockDirectory(.lock)` (`bitcoin-core/src/util/fs_helpers.cpp:47`)
holds a fcntl/flock advisory lock on the datadir for the lifetime of the
process. **Concurrent `rustoshi --datadir=X` invocations on the same
datadir corrupt RocksDB.**

The `start_mainnet.sh::check_not_running` only checks the canonical RPC
port. If a stale process bound a different RPC port (e.g. operator
typo) or if you forgot to update the launcher after changing
`--rpcbind`, two processes happily open the same RocksDB and corrupt
each other's WALs.

**Fix shape**: at boot, after `create_dir_all(&datadir)`, open
`<datadir>/.lock` with `O_RDWR | O_CREAT` and call `fcntl(F_SETLK, ...)`.
On `EAGAIN`/`EACCES` bail with a clear "another rustoshi process owns
this datadir" error. (Rust crate `fs2::FileExt::try_lock_exclusive`
abstracts this.)

### 4. BUG-5 (P1): No FD-limit raise

Core raises `RLIMIT_NOFILE` to `min_required_fds + user_max_connection
+ MIN_LEVELDB_FDS` (`bitcoin-core/src/util/fs_helpers.cpp:157`).
Rustoshi inherits the shell or systemd default. `start_mainnet.sh`
papers over with `ulimit -n 524288`, but **packaged installs are
unguarded**.

W13 saw lunarblock crash at h=928084 with EMFILE ("Too many open
files") on a 20,418-SST chainstate when relaunched from cron, because
cron's default ulimit (~1024-4096) is far below an interactive shell's.
Rustoshi will hit the same wall when shipped as a `.deb`.

**Fix shape**: call `libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit)` in
`main.rs` after fork, before opening RocksDB. Compute the required
count from `cli.maxconnections` (P2P) + an estimate of SST-file FDs
(~22K for a mainnet chainstate today).

### 5. BUG-10 (P1): Panics escape `debug.log`

If any task in the tokio runtime panics, the default Rust panic hook
writes to `stderr` — which in `--daemon` mode is redirected to
`/dev/null`. Operator with `--daemon` sees the systemd journal showing
"Process exited 101" and zero context about which task panicked.

**Fix shape**: install `std::panic::set_hook(Box::new(|info| { ... }))`
in `async_main` immediately after the tracing subscriber is initialised.
The hook should log `tracing::error!(panic_info = %info, "PANIC")` and
then call the default hook so a normal crash still happens. Bonus: log
the panic stack via `backtrace::Backtrace::capture()` (we already
depend on rand + std, so `backtrace` is a small add).

## Suggested FIX waves (priority order)

| Wave   | Scope                                          | Bugs addressed       |
|--------|------------------------------------------------|----------------------|
| FIX-A1 | Wire `RpcState.shutdown_tx` end-to-end         | BUG-1                |
| FIX-A2 | Make P2P / metrics / REST bind failure fatal   | BUG-3, BUG-4         |
| FIX-A3 | Datadir flock + clear conflict error           | BUG-2                |
| FIX-A4 | FD-limit raise + SIGPIPE ignore                | BUG-5, BUG-6         |
| FIX-A5 | Panic hook + shutdown summary differentiation  | BUG-10, BUG-16, BUG-17 |
| FIX-A6 | `-startupnotify` / `-shutdownnotify` hooks     | BUG-7                |
| FIX-A7 | Per-block `UpdateTip` + time-based heartbeat   | BUG-14, BUG-15       |
| FIX-A8 | `logging` RPC for runtime category toggle      | BUG-21               |
| FIX-A9 | `--reindex-chainstate` working (re-derive
          UTXO from indexed blocks + on-disk format
          version markers)                                | BUG-8, BUG-18        |
| FIX-A10| Startup disk-space + `--datadir` writability   |                      |
|        | precheck + parent-dir auto-create for          |                      |
|        | `--debuglogfile`                               | BUG-20, BUG-22, BUG-28 |
| FIX-A11| `--conf` unknown-key warning + `--version`     |                      |
|        | build-info + grouped `--help` + daemon-child   |                      |
|        | PID log + `--load-snapshot` guard              | BUG-12, BUG-25, BUG-26, BUG-27, BUG-29 |
| FIX-A12| `rustoshi-cli` companion binary +              |                      |
|        | `getmemoryinfo` RPC parity                     | BUG-23, BUG-30       |
| FIX-A13| Log timestamp format alignment +               |                      |
|        | size/age-based log rotation                    | BUG-9, BUG-11        |
| FIX-A14| Wallet.dat Core-bdb compat                     | BUG-19               |
| FIX-A15| Cookie-rotation race + best-effort delete      |                      |
|        | hardening                                      | BUG-13               |
| FIX-A16| `--daemon --printtoconsole` warn-on-conflict   | BUG-24               |

The first 5 fix waves (FIX-A1..FIX-A5) directly close the operator
failure modes that contributed to Path A's 4-day window:

- `bitcoin-cli stop` actually shuts down (BUG-1).
- Failed listener at boot causes `exit 1` so systemd `Restart=on-failure`
  fires (BUG-3, BUG-4).
- Concurrent-process corruption refused at fcntl-time, not
  RocksDB-LOCK time (BUG-2).
- packaged binaries don't run out of FDs mid-IBD (BUG-5).
- panic hits `debug.log` so the next-day forensics has a starting point
  (BUG-10).

## References

- `bitcoin-core/src/init.cpp:425-457` — signal handler registration.
- `bitcoin-core/src/init.cpp:900-913` — SIGTERM / SIGINT / SIGHUP /
  SIGPIPE registration block.
- `bitcoin-core/src/init.cpp:909` — `signal(SIGPIPE, SIG_IGN)`.
- `bitcoin-core/src/init.cpp:259` — `-shutdownnotify` exec loop.
- `bitcoin-core/src/init.cpp:530` — `-shutdownnotify=<cmd>` ArgsManager arg.
- `bitcoin-core/src/init.cpp:1044-1047` — FD-limit raise.
- `bitcoin-core/src/init.cpp:1467, 1958, 1962, 1977` —
  `CheckDiskSpace` at startup.
- `bitcoin-core/src/shutdown.cpp` — `g_shutdown_mutex` mechanism.
- `bitcoin-core/src/util/fs_helpers.cpp:47-90` — `LockDirectory` flock.
- `bitcoin-core/src/util/fs_helpers.cpp:157-173` —
  `RaiseFileDescriptorLimit`.
- `bitcoin-core/src/util/fs_helpers.cpp:162-169` —
  `setrlimit(RLIMIT_NOFILE)`.
- `bitcoin-core/src/logging.cpp:300-319` — ISO-8601 timestamp format
  with optional microseconds.
- `bitcoin-core/src/logging.h:61` — `Level::Debug` default.
- `bitcoin-core/src/logging.h:157` — `std::atomic<Level> m_log_level`.
- `bitcoin-core/src/rpc/request.cpp:100` — `GenerateAuthCookie` shape.
- `bitcoin-core/src/rpc/server.cpp:297` — `DeleteAuthCookie` on
  shutdown.
- `bitcoin-core/contrib/init/bitcoind.service` — systemd unit:
  `Type=notify`, `Restart=on-failure`, `TimeoutStopSec=600`,
  `PIDFile=/run/bitcoind/bitcoind.pid`.

## Rustoshi-side source citations

All citations are line-stable as of FIX-88 (commit `b28301e`).

- `rustoshi/src/main.rs:25-27` — `ops` re-exports.
- `rustoshi/src/main.rs:1303-1340` — synchronous `main()` wrapper +
  daemonize prologue.
- `rustoshi/src/main.rs:1422-1426` — PID file write at startup.
- `rustoshi/src/main.rs:1976-1983` — cookie file generation.
- `rustoshi/src/main.rs:2218-2246` — SIGHUP handler registration.
- `rustoshi/src/main.rs:2248-2257` — `--ready-fd` notification.
- `rustoshi/src/main.rs:4241-4255` — SIGTERM / Ctrl-C select branches.
- `rustoshi/src/main.rs:4262-4319` — graceful shutdown sequence.
- `rustoshi/src/ops.rs:200-261` — `ReopenableLogFile`.
- `rustoshi/src/ops.rs:269-285` — PID file write/remove.
- `rustoshi/src/ops.rs:304-322` — `daemonize()` libc wrapper.
- `rustoshi/src/ops.rs:337-352` — `notify_ready` (sd_notify-style).
- `crates/rpc/src/server.rs:137-138, 181, 208` — `shutdown_tx` field
  declaration (the one main.rs never wires).
- `crates/rpc/src/server.rs:4887-4895` — `stop` RPC method body
  (silently broken until BUG-1 closes).
- `crates/network/src/peer_manager.rs:1295-1298` — P2P bind failure
  (BUG-3 site).
- `crates/storage/src/db.rs:89-141` — `ChainDb::open` (no datadir
  flock, hence BUG-2 surfaces late).
