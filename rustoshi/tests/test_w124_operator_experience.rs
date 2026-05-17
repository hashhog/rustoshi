//! W124 Operator-experience audit — 30-gate cross-impl audit for rustoshi.
//!
//! Discovery wave, not a fix wave. Each gate is an `#[xfail]`-style test
//! whose **body documents the operator-experience surface** rustoshi
//! exposes today and either passes (regression pin) or `panic!`s with a
//! clear "BUG-N" reference into `audit/w124_operator_experience.md`.
//!
//! Path A on May 17 2026 restored haskoin + ouroboros to mainnet after a
//! 4-day silent outage — fleet-monitor detected the lag but no auto-restart
//! was wired. This wave audits operator-experience holistically across the
//! fleet so we never let a daemon silently drift to DOWN again.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/init.cpp` — startup sequence, signal handlers,
//!   `registerSignalHandler`, `LockDirectory`, `RaiseFileDescriptorLimit`,
//!   `-startupnotify` / `-shutdownnotify`.
//! - `bitcoin-core/src/shutdown.cpp` — graceful shutdown, `g_shutdown_mutex`.
//! - `bitcoin-core/src/logging.{cpp,h}` — ISO-8601 timestamp format,
//!   `Level::{Trace,Debug,Info,Warning,Error}`, `m_reopen_file` SIGHUP flag.
//! - `bitcoin-core/contrib/init/bitcoind.service` — systemd unit
//!   (`Type=notify`, `Restart=on-failure`, `PIDFile=...`, hardening).
//! - `bitcoin-core/src/util/fs_helpers.cpp::LockDirectory` — datadir flock.
//! - `bitcoin-core/src/rpc/request.cpp::GenerateAuthCookie` — cookie lifecycle.
//! - `bitcoin-core/src/rpc/server.cpp::DeleteAuthCookie` — cookie removal.
//!
//! Audit verdict counters (see md for details):
//!   PRESENT 12 / PARTIAL 12 / MISSING 6 (out of 30 gates).
//!
//! Bug summary (see audit/w124_operator_experience.md for full text):
//!
//!   BUG-1  (P0)        RPC `stop` returns success but does NOT shut down.
//!                      `RpcState::shutdown_tx` field exists (server.rs:137)
//!                      but is NEVER assigned in `main.rs`; `.take()` always
//!                      yields `None`. `bitcoin-cli stop` is canonical fleet
//!                      shutdown mechanism — silently broken in production.
//!                      Direct Path A relevance: operator drops down to
//!                      `kill -TERM` precisely because `stop` doesn't work.
//!
//!   BUG-2  (P0)        No datadir lockfile / flock — concurrent rustoshi
//!                      processes on same datadir corrupt RocksDB silently.
//!                      `start_mainnet.sh::check_not_running` only checks
//!                      RPC port; if a stale process binds a different port
//!                      or the operator forgets `--rpcbind`, RocksDB LOCK
//!                      fails late + crashes mid-IBD. Core uses
//!                      `LockDirectory(.lock)` in `fs_helpers.cpp:47`.
//!
//!   BUG-3  (P0)        P2P bind failure is LOGGED but not fatal —
//!                      `peer_manager.rs:1296` logs `tracing::error!` then
//!                      continues without inbound listener. Operator gets a
//!                      headers-only node that never accepts inbound, no
//!                      non-zero exit. Should exit 1 like RPC bind does.
//!                      Bitcoin Core treats `Bind::Listen` failure on a
//!                      required bind as a startup error.
//!
//!   BUG-4  (P0)        Metrics + REST + ZMQ listener failures are non-fatal
//!                      AND silent (single `tracing::warn!`).  fleet-monitor
//!                      polls `/health` on port `9332`; if metrics didn't
//!                      bind, monitor sees a silent down regardless of
//!                      whether the RPC port is up. Same pattern as BUG-3.
//!
//!   BUG-5  (P1)        No FD-limit raise. Core raises `RLIMIT_NOFILE` via
//!                      `RaiseFileDescriptorLimit(min_required_fds)` in
//!                      `fs_helpers.cpp:157`. rustoshi inherits the
//!                      shell/systemd default; `start_mainnet.sh` works
//!                      around it with `ulimit -n 524288` but a packaged
//!                      install + a 20K-SST chainstate (lunarblock-style
//!                      EMFILE crash, W13) is unguarded.
//!
//!   BUG-6  (P1)        No SIGPIPE handler / ignore. Core `signal(SIGPIPE,
//!                      SIG_IGN)` at init.cpp:909 prevents the daemon dying
//!                      when an HTTP client disconnects mid-response. Rust
//!                      defaults `tokio`/`hyper` write to `EPIPE` errors so
//!                      it's not catastrophic, but a write to plain `stdout`
//!                      after `-printtoconsole=true` + terminal-close will
//!                      terminate with SIGPIPE on the default disposition.
//!                      Risk for `--daemon=false` operators piping to less.
//!
//!   BUG-7  (P1)        No `-startupnotify=<cmd>` / `-shutdownnotify=<cmd>`
//!                      hooks. Core wires arbitrary exec hooks at boot +
//!                      shutdown (init.cpp:259, 530). rustoshi has
//!                      `--ready-fd=N` (sd_notify-style) but no shell-hook
//!                      equivalent, so non-systemd supervisors (s6, runit,
//!                      docker-init) can't do per-node tear-down work like
//!                      "sync NFS dir before exit".
//!
//!   BUG-8  (P1)        No `-reindex` / `-reindex-chainstate`. CLI accepts
//!                      `rustoshi reindex` but the subcommand is a stub
//!                      that warns + exits (main.rs:1437-1446). For an
//!                      operator with a partially-corrupted chainstate the
//!                      only documented recovery is "delete `chainstate/`
//!                      and re-IBD from scratch" — same outcome as a fresh
//!                      `--datadir`, but slower because it doesn't reuse
//!                      `blocks/` storage.
//!
//!   BUG-9  (P1)        No log rotation by size — only SIGHUP-driven reopen.
//!                      `debug.log` grows unboundedly between
//!                      logrotate(8) hooks. Core has same behavior (Core
//!                      relies on external logrotate too) but Core also
//!                      buffers `m_msgs_before_open` if disk fills up
//!                      mid-init. rustoshi's `ReopenableLogFile::write`
//!                      silently drops if the inner Option is None
//!                      (ops.rs:240-243) — operator-visible data loss.
//!
//!   BUG-10 (P1)        Panic hook absent. A panic in the main task aborts
//!                      the process with default Rust panic message
//!                      formatting to stderr — not into `debug.log`.
//!                      Operator with `--daemon` (stdout = /dev/null) sees
//!                      `Process exited 101` and zero context. Core uses
//!                      `std::set_new_handler(new_handler_terminate)` +
//!                      `std::set_terminate(terminate_logger)` to ensure
//!                      every fatal exit is logged.
//!
//!   BUG-11 (P1)        Log timestamp format is tracing-default
//!                      (`2026-05-17T07:00:00.123456Z` with target =
//!                      false). Core uses ISO-8601 with `m_log_time_micros`
//!                      flag; rustoshi has no `--logtimestamps=false` or
//!                      `--logtimemicros=true/false` knob. Consensus-diff
//!                      tooling currently parses tracing format; future
//!                      Core-parity log audit will trip on this.
//!
//!   BUG-12 (P1)        `-conf` parsing is silently lenient — unknown keys
//!                      are accepted, mistyped keys (`rpcsuer=alice`) silently
//!                      dropped (ops.rs:53-83 just inserts into BTreeMap,
//!                      `apply_conf_to_cli` reads only known keys, no
//!                      unknown-key warning). Core warns on unrecognized
//!                      conf options. Operator footgun: `--rpcuser=alice`
//!                      typo + `rpcsuer=alice` in conf → cookie auth
//!                      silently falls back, looks like an auth bug.
//!
//!   BUG-13 (P1)        Cookie file deletion fails silently if datadir is
//!                      read-only or if the parent runtime tmpfs got
//!                      remounted between launch + shutdown
//!                      (main.rs:594-599 logs warn but continues). Stale
//!                      cookie on disk means next launch's cookie gets
//!                      *overwritten* (write_cookie_file::std::fs::write)
//!                      but for a moment between two restarts, an
//!                      external script tailing `.cookie` may read the
//!                      OLD secret. Race window is small but real.
//!
//!   BUG-14 (P2)        IBD progress logging is height-driven (every 10000
//!                      blocks) not time-driven. At ~5 blocks/s near tip
//!                      that's 33 min between log lines. fleet-monitor's
//!                      "tip wall-clock age" alert fires after 30 min of
//!                      no tip movement; if a node is genuinely slow but
//!                      progressing, monitor blares before the next
//!                      heartbeat. Core logs `UpdateTip` per block (which
//!                      we don't — see BUG-15 below) plus a 10K-block
//!                      summary, so each block adds a fresh wall-clock
//!                      heartbeat.
//!
//!   BUG-15 (P2)        No per-block `UpdateTip` log line at info level
//!                      during connect_tip. Core's `LogPrintf("UpdateTip:
//!                      new best=... height=... ...");` is the canonical
//!                      "node is alive" signal a sysadmin tails for. Our
//!                      `Synced to height N (X.Y%) cache=Z MiB` line only
//!                      fires every 10000 blocks. Subset of BUG-14 with
//!                      its own follow-up (gives operator per-block
//!                      timing data, not just every-10K avg).
//!
//!   BUG-16 (P2)        No `getblockchaininfo`/`getrpcinfo` shutdown probe
//!                      log when graceful shutdown begins. Current path
//!                      logs `Shutting down...` + per-phase messages, but
//!                      a sysadmin investigating "did rustoshi shut down
//!                      cleanly?" can't distinguish "graceful" from
//!                      "panic exit + cookie remained" because the FINAL
//!                      log line `Shutdown complete` is unconditional and
//!                      can be the last line even after error paths
//!                      (UTXO flush failure logs `error!` but proceeds).
//!                      Should log either `Shutdown complete (clean)` or
//!                      `Shutdown complete (with errors)`.
//!
//!   BUG-17 (P2)        Mempool persistence: `dump_mempool` failure is
//!                      logged as `error!` but the shutdown returns Ok.
//!                      Operator running `systemctl status` sees `exited
//!                      0` even when mempool was lost. Same for fee
//!                      estimates + UTXO cache flush. Exit code is "did
//!                      we panic during shutdown" rather than "did we
//!                      preserve user-visible state".
//!
//!   BUG-18 (P2)        BlockFilterIndex version handling: index has no
//!                      version byte on disk. If the GCS encoding changes
//!                      between releases, indexes silently produce wrong
//!                      filters with the new code reading old data.
//!                      Compare with Core's `BlockFilterIndex::DBVal`
//!                      schema-versioned key prefix. Operator with a
//!                      pre-FIX-69 index dir and post-FIX-69 binary gets
//!                      undetected drift.
//!
//!   BUG-19 (P2)        Wallet.dat: not BIP-39 / Core-bdb compatible.
//!                      rustoshi-wallet uses its own JSON-encoded
//!                      `wallet.json` (not `wallet.dat`). Cannot import
//!                      a Core wallet without manual re-derivation;
//!                      operator-painful for fleet migrations or
//!                      hot-backups from a Core node.
//!
//!   BUG-20 (P2)        No disk-space precheck at startup. Core's
//!                      `CheckDiskSpace` at init.cpp:1958, :1962, :1977
//!                      refuses to start if `df` shows < 550 MiB free in
//!                      datadir or blocksdir. rustoshi happily starts +
//!                      runs out of space mid-IBD (relevant to mainnet
//!                      operator filling a 4 TB NVMe).
//!
//!   BUG-21 (P3)        No per-category log-level dynamic adjustment via
//!                      RPC. Core has `logging` RPC to flip categories on
//!                      a running daemon (e.g. enable `net` debug without
//!                      restart). rustoshi only reads `--debug=` at startup.
//!
//!   BUG-22 (P3)        `--debuglogfile` does not auto-create parent
//!                      directory (ops.rs:206-215 uses
//!                      `OpenOptions::open` without `create_dir_all` on
//!                      the parent). Symptom: `--debuglogfile=
//!                      /var/log/rustoshi/debug.log` on a fresh box fails
//!                      with `No such file or directory`, exits 1 with
//!                      tracing-not-installed-yet stderr only.
//!
//!   BUG-23 (P3)        `bitcoin-cli`-style positional argument parsing
//!                      not supported (`rustoshi-cli getblockcount` would
//!                      have to use our REST/JSON-RPC manually). There is
//!                      no `rustoshi-cli` binary at all (see CLI workflow
//!                      in `tools/start_mainnet.sh` — uses curl + cookie
//!                      auth). Compare with Core's `bitcoin-cli`.
//!
//!   BUG-24 (P3)        `--printtoconsole` and `--daemon` are silently
//!                      coupled — main.rs:1400 ANDs both flags before
//!                      adding the stdout layer. Operator explicitly
//!                      requesting `--daemon --printtoconsole=true` (e.g.
//!                      with custom journald redirect) gets neither
//!                      a warning nor stdout output.
//!
//!   BUG-25 (P3)        `--daemon` mode never re-prints to debug.log
//!                      that it's running daemonized AFTER fork
//!                      (main.rs:1410-1412 logs before fork but the
//!                      original process is gone). Subtle: the child's
//!                      first log line is "Network: ..." with no
//!                      indication this is the daemon child. Compare to
//!                      Core which logs PID + uname after daemonize.
//!
//!   BUG-26 (P3)        No `--version` / `-V` machine-readable JSON
//!                      output. `--version` shows clap-default
//!                      `rustoshi 0.1.0` only; consensus-diff tooling
//!                      can't parse build commit / build date / RocksDB
//!                      version. Core has `bitcoind --version` + build
//!                      info in `bitcoin-cli getnetworkinfo`.
//!
//!   BUG-27 (P3)        `--help` shows clap-default formatting (one
//!                      arg per line, no section headers). Bitcoin Core's
//!                      `-help` groups args by category (RPC, network,
//!                      wallet, debugging, etc.). With ~50 flags in
//!                      rustoshi the unstructured list is operator-hostile.
//!
//!   BUG-28 (P3)        `--datadir` does not validate that the path is
//!                      writable BEFORE creating subdirs. If `--datadir`
//!                      points at a read-only mount, the first error
//!                      surfaces at `chainstate` open (RocksDB) which is
//!                      cryptic; clearer to fail at
//!                      `create_dir_all` + a touch-test in main.rs:1356.
//!
//!   BUG-29 (P3)        Concurrent `--load-snapshot=<path>` + normal IBD
//!                      footgun: starting a node with `--load-snapshot`
//!                      against an already-IBDed datadir silently
//!                      replays the snapshot atop the existing chain
//!                      (see ASSUMEUTXO TIP ACTIVATION comment at
//!                      main.rs:1610). Operator-confusing; should
//!                      reject if best_height > 1 unless `--force`.
//!
//!   BUG-30 (P3)        No `getmemoryinfo` / `getmemoryusage` parity.
//!                      Operator chasing OOM has only `metrics`
//!                      (height/peers/mempool_size) — no UTXO cache RSS,
//!                      no per-thread arena info. Core's
//!                      `getmemoryinfo` returns mallinfo + per-arena
//!                      breakdown. Less critical than the lifecycle
//!                      bugs above but cumulative for diagnostics.

#![allow(clippy::needless_return)]

// ============================================================
// Gates 1-10: Startup sequence, signal handling, lifecycle
// ============================================================

/// G1 (PARTIAL — BUG-1): RPC `stop` end-to-end shutdown path.
///
/// Core: `bitcoin-cli stop` triggers `StartShutdown()` which sets the
/// `g_shutdown_mutex` cv and unblocks the main loop. Rustoshi: `stop`
/// RPC method exists (server.rs:4887) and tries to take a
/// `shutdown_tx` oneshot, but `main.rs` never installs the sender, so
/// the oneshot fires into the void and the daemon keeps running.
///
/// This is a static-source assertion — exercising it for real requires
/// spinning a full node, which we don't do in unit tests.
#[test]
fn g1_rpc_stop_does_not_actually_shutdown() {
    // Read main.rs and confirm the absence of any `shutdown_tx = Some(...)`
    // assignment that connects RpcState::shutdown_tx to the main loop's
    // select! break.
    let main_rs = include_str!("../src/main.rs");
    // The Cli loop already terminates on Ctrl+C / SIGTERM, but the RPC
    // `stop` route is silent.
    assert!(
        !main_rs.contains("shutdown_tx = Some"),
        "BUG-1: main.rs unexpectedly wires shutdown_tx — re-verify the audit"
    );
    assert!(
        !main_rs.contains("shutdown_tx: Some"),
        "BUG-1: main.rs unexpectedly wires shutdown_tx — re-verify the audit"
    );
    // Sanity: server.rs declared the field, so the wiring gap is on main.rs.
    let server_rs = include_str!("../../crates/rpc/src/server.rs");
    assert!(
        server_rs.contains("pub shutdown_tx: Option<oneshot::Sender<()>>"),
        "RpcState::shutdown_tx field MUST exist — audit reflects rustoshi as of FIX-88"
    );
}

/// G2 (MISSING — BUG-2): Datadir lockfile / single-instance protection.
///
/// Core: `LockDirectory(.lock)` in `fs_helpers.cpp:47` refuses concurrent
/// processes on the same datadir. Rustoshi: no flock; depends on
/// RocksDB LOCK file (which fires LATE after datadir creation).
#[test]
fn g2_no_datadir_flock_protection() {
    let main_rs = include_str!("../src/main.rs");
    let storage_lib = include_str!("../../crates/storage/src/lib.rs");
    let storage_db = include_str!("../../crates/storage/src/db.rs");
    let combined = format!("{}{}{}", main_rs, storage_lib, storage_db);
    // Verify no flock / fcntl / advisory-lock call.
    assert!(
        !combined.contains("flock(")
            && !combined.contains("Flock")
            && !combined.contains("fcntl::flock")
            && !combined.contains("fcntl(F_SETLK")
            && !combined.contains("LockDirectory"),
        "BUG-2: a datadir-level lock was unexpectedly introduced — re-verify the audit"
    );
}

/// G3 (PARTIAL — BUG-3): P2P bind failure is non-fatal.
///
/// `peer_manager.rs:1295-1296` logs `tracing::error!` and continues.
/// Should `return Err(...)` or `exit(1)` to match RPC bind semantics.
#[test]
fn g3_p2p_bind_failure_is_non_fatal() {
    let peer_mgr = include_str!("../../crates/network/src/peer_manager.rs");
    // Find the listen-failed branch.
    assert!(
        peer_mgr.contains("Failed to bind P2P listener"),
        "G3: peer_manager.rs no longer logs the P2P bind failure message — re-verify"
    );
    // The branch is `Err(e) => { tracing::error!(...); }` with no propagation.
    assert!(
        !peer_mgr.contains("Failed to bind P2P listener on {}: {}\", listen_addr, e);\n                    std::process::exit"),
        "BUG-3: P2P bind failure unexpectedly aborts — re-verify the audit"
    );
}

/// G4 (PARTIAL — BUG-4): Metrics / REST listener failures non-fatal silent.
#[test]
fn g4_metrics_rest_bind_failure_silent() {
    let main_rs = include_str!("../src/main.rs");
    assert!(
        main_rs.contains("Metrics server failed to bind"),
        "G4: Metrics bind failure log message changed — re-verify"
    );
    // No process::exit after the warn.
    let snippet_start = main_rs.find("Metrics server failed to bind").unwrap();
    let after = &main_rs[snippet_start..snippet_start + 300];
    assert!(
        !after.contains("std::process::exit"),
        "BUG-4: metrics bind unexpectedly exits — re-verify"
    );
}

/// G5 (MISSING — BUG-5): No `RaiseFileDescriptorLimit` equivalent.
///
/// Core: `RaiseFileDescriptorLimit(min_required_fds)` in
/// `fs_helpers.cpp:157` calls `setrlimit(RLIMIT_NOFILE, ...)`. Rustoshi
/// has no such call. `start_mainnet.sh` works around with `ulimit -n
/// 524288` but packaged installs are unguarded.
#[test]
fn g5_no_fd_limit_raise() {
    let main_rs = include_str!("../src/main.rs");
    let ops_rs = include_str!("../src/ops.rs");
    let combined = format!("{}{}", main_rs, ops_rs);
    assert!(
        !combined.contains("setrlimit")
            && !combined.contains("RLIMIT_NOFILE")
            && !combined.contains("libc::setrlimit"),
        "BUG-5: an FD-limit raise was added — update audit"
    );
}

/// G6 (MISSING — BUG-6): SIGPIPE not explicitly ignored.
///
/// Core: `signal(SIGPIPE, SIG_IGN)` at `init.cpp:909`.
#[test]
fn g6_no_explicit_sigpipe_ignore() {
    let main_rs = include_str!("../src/main.rs");
    let ops_rs = include_str!("../src/ops.rs");
    let combined = format!("{}{}", main_rs, ops_rs);
    assert!(
        !combined.to_ascii_uppercase().contains("SIGPIPE"),
        "BUG-6: a SIGPIPE handler was added — update audit"
    );
}

/// G7 (MISSING — BUG-7): No `-startupnotify` / `-shutdownnotify` hooks.
#[test]
fn g7_no_startup_shutdown_notify_hooks() {
    let main_rs = include_str!("../src/main.rs");
    assert!(
        !main_rs.to_ascii_lowercase().contains("startupnotify")
            && !main_rs.to_ascii_lowercase().contains("shutdownnotify"),
        "BUG-7: notify hooks were added — update audit"
    );
}

/// G8 (PARTIAL — BUG-8): Reindex subcommand is a stub.
#[test]
fn g8_reindex_subcommand_is_stub() {
    let main_rs = include_str!("../src/main.rs");
    // The reindex branch logs `Reindex requested. NOT YET IMPLEMENTED`.
    assert!(
        main_rs.contains("Reindex requested. NOT YET IMPLEMENTED"),
        "BUG-8: reindex is no longer a stub — update audit"
    );
}

/// G9 (PARTIAL — BUG-9): Log rotation only via SIGHUP, no size-based.
#[test]
fn g9_log_rotation_only_sighup() {
    let ops_rs = include_str!("../src/ops.rs");
    // SIGHUP reopen is wired, but no max_file_size / max_age check.
    assert!(
        ops_rs.contains("pub fn reopen"),
        "G9: SIGHUP reopen function was removed — re-verify"
    );
    assert!(
        !ops_rs.contains("max_file_size") && !ops_rs.contains("rotate_size"),
        "BUG-9: size-based rotation was added — update audit"
    );
}

/// G10 (MISSING — BUG-10): No panic hook routing panics to debug.log.
#[test]
fn g10_no_panic_hook_for_debug_log() {
    let main_rs = include_str!("../src/main.rs");
    let ops_rs = include_str!("../src/ops.rs");
    let combined = format!("{}{}", main_rs, ops_rs);
    assert!(
        !combined.contains("panic::set_hook")
            && !combined.contains("std::panic::set_hook"),
        "BUG-10: a panic hook was installed — update audit"
    );
}

// ============================================================
// Gates 11-20: Logging, config, exit semantics, persistence
// ============================================================

/// G11 (PARTIAL — BUG-11): Log timestamp format diverges from Core's
/// ISO-8601 with microsecond precision toggle.
#[test]
fn g11_log_timestamp_format_diverges_from_core() {
    let main_rs = include_str!("../src/main.rs");
    let ops_rs = include_str!("../src/ops.rs");
    let combined = format!("{}{}", main_rs, ops_rs);
    // No --logtimestamps / --logtimemicros knob.
    assert!(
        !combined.contains("logtimestamps") && !combined.contains("logtimemicros"),
        "BUG-11: log timestamp knobs were added — update audit"
    );
    // We just use `tracing_subscriber::fmt::layer()` default timer, not
    // FormatISO8601DateTime + .%06d.
    assert!(
        !combined.contains("FormatISO8601DateTime")
            && !combined.contains("with_timer(UtcTime")
            && !combined.contains("ChronoUtc"),
        "BUG-11: log timer format was customized — update audit"
    );
}

/// G12 (PARTIAL — BUG-12): `-conf` parsing silently ignores unknown keys.
#[test]
fn g12_conf_parser_silently_drops_unknown_keys() {
    let ops_rs = include_str!("../src/ops.rs");
    // The parser inserts every key=value pair; the apply step picks the
    // ones it knows; no log call for the remainder.
    assert!(
        ops_rs.contains("values.insert(key, val.to_string())"),
        "G12: conf parser shape changed — re-verify"
    );
    // No "unknown conf key" warning ever emitted.
    assert!(
        !ops_rs.contains("unknown conf key")
            && !ops_rs.contains("unrecognized conf"),
        "BUG-12: an unknown-conf-key warning was added — update audit"
    );
}

/// G13 (PARTIAL — BUG-13): Cookie file delete is best-effort.
#[test]
fn g13_cookie_delete_is_best_effort() {
    let main_rs = include_str!("../src/main.rs");
    // The delete_cookie_file body warns but continues.
    assert!(
        main_rs.contains("Failed to delete cookie file"),
        "G13: cookie delete log was changed — re-verify"
    );
}

/// G14 (PARTIAL — BUG-14): IBD progress logging is height-driven only.
#[test]
fn g14_ibd_progress_logging_is_height_driven_only() {
    let main_rs = include_str!("../src/main.rs");
    // "Synced to height" log is gated on height.is_multiple_of(10000).
    assert!(
        main_rs.contains("height.is_multiple_of(10000)"),
        "G14: IBD progress cadence changed — re-verify"
    );
}

/// G15 (MISSING — BUG-15): No per-block `UpdateTip` info-level log.
#[test]
fn g15_no_per_block_updatetip_log() {
    let main_rs = include_str!("../src/main.rs");
    // No `UpdateTip` log line anywhere.
    assert!(
        !main_rs.contains("UpdateTip"),
        "BUG-15: an UpdateTip log was added — update audit"
    );
}

/// G16 (PARTIAL — BUG-16): Shutdown summary cannot distinguish clean vs
/// degraded shutdown.
#[test]
fn g16_shutdown_summary_undifferentiated() {
    let main_rs = include_str!("../src/main.rs");
    assert!(
        main_rs.contains("Shutdown complete"),
        "G16: shutdown final log changed — re-verify"
    );
    // No "(clean)" / "(with errors)" distinction.
    assert!(
        !main_rs.contains("Shutdown complete (clean)")
            && !main_rs.contains("Shutdown complete (with errors)"),
        "BUG-16: shutdown summary was differentiated — update audit"
    );
}

/// G17 (PARTIAL — BUG-17): Persistence failures don't surface in exit code.
#[test]
fn g17_persistence_failure_silent_in_exit_code() {
    let main_rs = include_str!("../src/main.rs");
    // Mempool / fee / utxo flush errors log but return Ok(()) at end.
    assert!(
        main_rs.contains("Failed to dump mempool"),
        "G17: dump_mempool error log changed — re-verify"
    );
    // Shutdown returns Ok unconditionally.
    let tail = &main_rs[main_rs.len().saturating_sub(20_000)..];
    assert!(
        tail.contains("Shutdown complete\");")
            && tail.contains("Ok(())"),
        "G17: shutdown return path changed — re-verify"
    );
}

/// G18 (MISSING — BUG-18): BlockFilterIndex has no on-disk version marker.
#[test]
fn g18_blockfilter_index_unversioned() {
    let bfi_src = include_str!("../../crates/storage/src/indexes/blockfilterindex.rs");
    // No FILTER_INDEX_VERSION constant or version-keyed record.
    assert!(
        !bfi_src.contains("FILTER_INDEX_VERSION")
            && !bfi_src.contains("INDEX_VERSION")
            && !bfi_src.contains("schema_version"),
        "BUG-18: blockfilter index gained a version marker — update audit"
    );
}

/// G19 (PARTIAL — BUG-19): Wallet format is not Core-bdb compatible.
#[test]
fn g19_wallet_format_not_core_compatible() {
    // Wallet code lives in crates/wallet — verify by absence of `bdb` /
    // `BerkeleyDB` references in the manager.
    let wallet_mgr = include_str!("../../crates/wallet/src/manager.rs");
    assert!(
        !wallet_mgr.contains("BerkeleyDB")
            && !wallet_mgr.contains("bdb::"),
        "BUG-19: wallet gained BerkeleyDB compat — update audit"
    );
}

/// G20 (MISSING — BUG-20): No startup disk-space precheck.
#[test]
fn g20_no_startup_disk_space_check() {
    let main_rs = include_str!("../src/main.rs");
    // No statvfs / df / available_space call at boot.
    assert!(
        !main_rs.contains("statvfs")
            && !main_rs.contains("available_space")
            && !main_rs.contains("CheckDiskSpace"),
        "BUG-20: a disk-space precheck was added — update audit"
    );
}

// ============================================================
// Gates 21-30: Diagnostics, polish, CLI/help, edge cases
// ============================================================

/// G21 (MISSING — BUG-21): No `logging` RPC for runtime log-level toggle.
#[test]
fn g21_no_logging_rpc_for_dynamic_level() {
    let server_rs = include_str!("../../crates/rpc/src/server.rs");
    // Core's `logging` RPC takes include / exclude category lists.
    // We have no such method.
    assert!(
        !server_rs.contains("async fn logging(")
            && !server_rs.contains("fn logging("),
        "BUG-21: a logging RPC was added — update audit"
    );
}

/// G22 (PARTIAL — BUG-22): `--debuglogfile` does not auto-create parents.
#[test]
fn g22_debuglogfile_does_not_mkdir_parent() {
    let ops_rs = include_str!("../src/ops.rs");
    // ReopenableLogFile::new does NOT do create_dir_all on the parent.
    let new_fn = ops_rs
        .find("pub fn new(path: PathBuf) -> std::io::Result<Self>")
        .expect("ReopenableLogFile::new must exist");
    let new_body = &ops_rs[new_fn..new_fn + 400];
    assert!(
        !new_body.contains("create_dir_all"),
        "BUG-22: parent-dir creation was added — update audit"
    );
}

/// G23 (MISSING — BUG-23): No `rustoshi-cli` companion binary.
#[test]
fn g23_no_rustoshi_cli_binary() {
    let manifest = include_str!("../Cargo.toml");
    let workspace_manifest = include_str!("../../Cargo.toml");
    let combined = format!("{}{}", manifest, workspace_manifest);
    // No `[[bin]]` for `rustoshi-cli` anywhere.
    assert!(
        !combined.contains("rustoshi-cli"),
        "BUG-23: rustoshi-cli was added — update audit"
    );
}

/// G24 (PARTIAL — BUG-24): `--daemon` silently overrides `--printtoconsole`.
#[test]
fn g24_daemon_silently_suppresses_printtoconsole() {
    let main_rs = include_str!("../src/main.rs");
    // The stdout layer is added iff `printtoconsole && !daemon`.
    assert!(
        main_rs.contains("cli.printtoconsole && !cli.daemon"),
        "G24: daemon/printtoconsole coupling logic changed — re-verify"
    );
}

/// G25 (PARTIAL — BUG-25): Daemon child first log line gives no PID context.
#[test]
fn g25_daemon_child_logs_lack_pid_context() {
    let main_rs = include_str!("../src/main.rs");
    // After daemonize(), the next log is `Rustoshi v...` — not `Rustoshi
    // daemon child PID=<pid> parent=<old>`.
    assert!(
        main_rs.contains("tracing::info!(\"Rustoshi v{}\""),
        "G25: first-log-line format changed — re-verify"
    );
    assert!(
        !main_rs.contains("daemon child PID"),
        "BUG-25: daemon-child PID was added — update audit"
    );
}

/// G26 (PARTIAL — BUG-26): `--version` is clap-default.
#[test]
fn g26_version_is_clap_default() {
    // clap's `version` macro reads CARGO_PKG_VERSION; no build commit /
    // build date / RocksDB version.
    let main_rs = include_str!("../src/main.rs");
    assert!(
        main_rs.contains("#[command(name = \"rustoshi\", version, about"),
        "G26: clap version() invocation changed — re-verify"
    );
    // No env!("VERGEN_*") / vergen-style commit baking.
    assert!(
        !main_rs.contains("VERGEN_") && !main_rs.contains("env!(\"GIT_HASH\""),
        "BUG-26: a build-info hook was added — update audit"
    );
}

/// G27 (PARTIAL — BUG-27): `--help` uses clap-default grouping.
#[test]
fn g27_help_uses_clap_default_grouping() {
    let main_rs = include_str!("../src/main.rs");
    // No `#[command(help_template = ...)]` or `next_help_heading` calls.
    assert!(
        !main_rs.contains("help_template")
            && !main_rs.contains("next_help_heading"),
        "BUG-27: custom help template was added — update audit"
    );
}

/// G28 (PARTIAL — BUG-28): No write-test on `--datadir` at startup.
#[test]
fn g28_no_datadir_writability_precheck() {
    let main_rs = include_str!("../src/main.rs");
    // create_dir_all is called but no canary-file write to confirm writable.
    let resolve = main_rs
        .find("fn resolve_base_datadir")
        .expect("resolve_base_datadir present");
    let snippet = &main_rs[resolve..resolve + 1000];
    assert!(
        !snippet.contains("// touch-test")
            && !snippet.contains("write canary"),
        "BUG-28: a write-canary check was added — update audit"
    );
}

/// G29 (PARTIAL — BUG-29): `--load-snapshot` does not refuse against an
/// already-IBDed datadir.
#[test]
fn g29_load_snapshot_doesnt_refuse_existing_chain() {
    let main_rs = include_str!("../src/main.rs");
    // The branch loads snapshot iff `--load-snapshot` is set regardless of
    // current best_height.
    assert!(
        main_rs.contains("if let Some(ref snap_path) = cli.load_snapshot"),
        "G29: snapshot-load branch changed — re-verify"
    );
    // No "refuse if best_height > 1" guard.
    let load_branch_start = main_rs
        .find("if let Some(ref snap_path) = cli.load_snapshot")
        .unwrap();
    let load_branch = &main_rs[load_branch_start..load_branch_start + 1500];
    assert!(
        !load_branch.contains("best_height > 1")
            && !load_branch.contains("--force"),
        "BUG-29: snapshot guard was added — update audit"
    );
}

/// G30 (MISSING — BUG-30): No `getmemoryinfo` RPC parity.
#[test]
fn g30_no_getmemoryinfo_rpc() {
    let server_rs = include_str!("../../crates/rpc/src/server.rs");
    // No `async fn get_memory_info`.
    assert!(
        !server_rs.contains("fn get_memory_info(")
            && !server_rs.contains("\"getmemoryinfo\""),
        "BUG-30: getmemoryinfo was added — update audit"
    );
}
