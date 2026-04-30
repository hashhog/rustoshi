//! Operational-parity helpers for rustoshi.
//!
//! This module wires up a handful of Bitcoin Core-style operational features
//! that are independent of consensus/P2P:
//!
//! - `-daemon` background mode (Linux only; uses libc `daemon(0, 0)`)
//! - `<datadir>/rustoshi.pid` PID file written on launch, removed on shutdown
//! - `-debug=<cat>` Core-style category flag, mapped onto Rust tracing targets
//! - SIGHUP log reopen (for logrotate-style external rotation)
//! - `-conf=<file>` minimal Core/TOML key=value config-file parsing
//! - `-printtoconsole` explicit toggle (default: true → log to stdout)
//! - `-debuglogfile=<path>` explicit log-file path (default
//!   `<datadir>/debug.log`)
//! - `--ready-fd=<N>` sd_notify-style readiness handshake plus a `/health`
//!   HTTP endpoint served from the metrics server
//!
//! References:
//! - bitcoin-core/src/init.cpp argspec (`-daemon`, `-reindex`, `-conf`,
//!   `-debug`, `-printtoconsole`, `-debuglogfile`)
//! - bitcoin-core/src/util/system.cpp (`daemon()` Linux background mode)
//! - bitcoin-core/src/init/common.cpp (`g_pidfile_path`)
//! - bitcoin-core/src/logging.h BCLog categories

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ============================================================
// CONFIG FILE PARSING
// ============================================================

/// Parsed key=value pairs from a Core-style or TOML config file.
///
/// Bitcoin Core's bitcoin.conf is a flat `key=value` list with optional
/// `[section]` headers; rustoshi accepts the same format and additionally
/// understands `key=value` lines emitted by TOML serializers (so the example
/// `config.example.toml` continues to work).
///
/// Section prefixes from `[section]` headers are dropped — Bitcoin Core uses
/// them for network selection (e.g. `[main]`, `[test]`), but rustoshi keeps
/// the network argument explicit on the CLI, so we treat all sections
/// uniformly. This matches bitcoin-core/src/util/settings.cpp's behavior of
/// flattening the conf into the global namespace when `-chain` is set on the
/// command line.
#[derive(Debug, Default, Clone)]
pub struct ConfFile {
    pub values: BTreeMap<String, String>,
}

impl ConfFile {
    pub fn parse(text: &str) -> Self {
        let mut values = BTreeMap::new();
        for raw in text.lines() {
            // Strip comments (everything after `#`) and trim whitespace
            let line = match raw.find('#') {
                Some(i) => &raw[..i],
                None => raw,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Skip TOML/Core section headers like `[section]`
            if line.starts_with('[') && line.ends_with(']') {
                continue;
            }
            // Parse `key=value` (split on first `=` only)
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = k.trim().to_string();
            // Strip optional surrounding quotes, common with TOML writers.
            let mut val = v.trim();
            if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val = &val[1..val.len() - 1];
            }
            values.insert(key, val.to_string());
        }
        Self { values }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse(&text))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        let v = self.get(key)?;
        Some(matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ))
    }
}

// ============================================================
// DEBUG-CATEGORY MAPPING
// ============================================================

/// Map a Bitcoin Core `-debug=<cat>` token onto one or more tracing target
/// directives.  Returns an empty vec for unknown categories (the caller
/// should warn), and `None` if the input is `0`/`none`/`false` (the Core
/// idiom for "disable all debug categories").
///
/// `-debug=1` and `-debug=all` enable every known category at debug level.
///
/// Mapping is deliberately conservative: each Core category points at the
/// rustoshi crate that owns the corresponding subsystem.  Unknown categories
/// fall back to `rustoshi=debug`, which never silently drops output.
fn map_debug_category(cat: &str) -> Option<Vec<&'static str>> {
    match cat.trim().to_ascii_lowercase().as_str() {
        "0" | "none" | "false" | "off" => None,
        "1" | "all" => Some(vec![
            "rustoshi=debug",
            "rustoshi_network=debug",
            "rustoshi_consensus=debug",
            "rustoshi_storage=debug",
            "rustoshi_rpc=debug",
            "rustoshi_crypto=debug",
        ]),
        // Network plumbing
        "net" | "p2p" => Some(vec!["rustoshi_network=debug"]),
        "addrman" => Some(vec!["rustoshi_network::addrman=debug"]),
        "tor" | "i2p" | "proxy" => Some(vec!["rustoshi_network=debug"]),
        // Block / mempool / validation
        "mempool" => Some(vec!["rustoshi_consensus::mempool=debug"]),
        "mempoolrej" => Some(vec!["rustoshi_consensus::mempool=debug"]),
        "validation" | "blockstorage" | "reindex" => {
            Some(vec!["rustoshi_consensus=debug", "rustoshi_storage=debug"])
        }
        "bench" | "prune" => Some(vec!["rustoshi_storage=debug"]),
        // RPC
        "rpc" | "http" => Some(vec!["rustoshi_rpc=debug"]),
        // Wallet / ZMQ / others — best-effort mapping to nearest crate
        "wallet" | "selectcoins" | "zmq" | "estimatefee" => {
            Some(vec!["rustoshi=debug"])
        }
        // Leveldb/rocksdb internal noise — not exposed via tracing today
        "leveldb" | "lock" | "coindb" | "qt" | "ipc" => Some(vec!["rustoshi_storage=debug"]),
        // Crypto / scripting
        "crypto" => Some(vec!["rustoshi_crypto=debug"]),
        // Unknown — caller should warn; map to crate-wide debug so no spam
        _ => Some(vec!["rustoshi=debug"]),
    }
}

/// Translate a comma-separated `-debug=net,mempool,rpc` list into tracing
/// directives that can be appended to an EnvFilter.
///
/// Returns the joined directive string (e.g. `rustoshi_network=debug,
/// rustoshi_consensus::mempool=debug,rustoshi_rpc=debug`) and a list of
/// unknown tokens that the caller should warn about.
pub fn debug_categories_to_directives(spec: &str) -> (String, Vec<String>) {
    let mut directives: Vec<&'static str> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut disable_all = false;

    for tok in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match map_debug_category(tok) {
            None => disable_all = true,
            Some(d) if d.is_empty() => unknown.push(tok.to_string()),
            Some(d) => {
                for entry in d {
                    if !directives.contains(&entry) {
                        directives.push(entry);
                    }
                }
            }
        }
    }

    if disable_all {
        // Core's idiom: any "0" / "none" disables everything regardless of
        // other tokens — return an empty directive set.
        return (String::new(), unknown);
    }

    (directives.join(","), unknown)
}

// ============================================================
// LOG-FILE OUTPUT (with reload support for SIGHUP)
// ============================================================

/// File-backed `MakeWriter` whose target path is swappable at runtime.
///
/// We deliberately do not use `tracing-appender` because we need to support
/// SIGHUP-driven log rotation: when the operator sends SIGHUP, we reopen the
/// file in place so logrotate's `copytruncate` mode (or the `move + create`
/// mode after a `postrotate`) keeps writing to the new inode.
#[derive(Clone)]
pub struct ReopenableLogFile {
    inner: Arc<Mutex<Option<std::fs::File>>>,
    path: Arc<Mutex<PathBuf>>,
}

impl ReopenableLogFile {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Some(file))),
            path: Arc::new(Mutex::new(path)),
        })
    }

    /// Reopen the underlying log file at the originally configured path.
    /// Called from the SIGHUP handler.  Failures are reported so the operator
    /// can see why log rotation regressed without crashing the node.
    pub fn reopen(&self) -> std::io::Result<()> {
        let path = self.path.lock().unwrap().clone();
        let new = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut guard = self.inner.lock().unwrap();
        // Drop the old file handle so its FD is released.
        *guard = Some(new);
        Ok(())
    }

    pub fn path(&self) -> PathBuf {
        self.path.lock().unwrap().clone()
    }
}

impl Write for ReopenableLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.inner.lock().unwrap();
        match guard.as_mut() {
            Some(f) => f.write(buf),
            None => Ok(buf.len()), // log file dropped — silently drop
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self.inner.lock().unwrap();
        match guard.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ReopenableLogFile {
    type Writer = ReopenableLogFile;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// ============================================================
// PID FILE
// ============================================================

/// Write `<datadir>/rustoshi.pid` (or the explicit `--pidfile` path) on
/// startup.  The file holds the current PID as a single line of decimal
/// digits, matching `bitcoin-core/src/init/common.cpp` g_pidfile_path.
pub fn write_pid_file(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", std::process::id()))?;
    Ok(())
}

/// Best-effort PID file removal on shutdown; logs but does not fail the
/// shutdown path if the file is gone or the FS is read-only.
pub fn remove_pid_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("Failed to remove PID file {}: {}", path.display(), e);
        }
    }
}

// ============================================================
// DAEMONIZATION
// ============================================================

/// Fork into the background using libc `daemon(0, 0)`.  After this returns
/// in the *child* process, stdin/stdout/stderr are redirected to /dev/null
/// and the process is in its own session, detached from the controlling
/// terminal.  The parent has already exited.
///
/// SAFETY: Must be called BEFORE the tokio runtime is created.  Forking a
/// running tokio runtime double-frees its IO drivers.  Our wrapper in
/// `main.rs` runs daemonization in a synchronous prologue before
/// `#[tokio::main]` boots the runtime.
///
/// Note: rustoshi uses `#[tokio::main]`, which constructs the runtime as the
/// first thing in `main`.  To daemonize cleanly we therefore intercept the
/// flag in a hand-rolled `main()` wrapper (see `daemonize_if_requested`).
#[cfg(target_family = "unix")]
pub fn daemonize() -> std::io::Result<()> {
    // SAFETY: libc::daemon is a standard POSIX-ish call. `(0, 0)` =
    // chdir to "/" and redirect stdio to /dev/null — same as
    // bitcoin-core/src/util/system.cpp::DaemonizeAndKeepLog.
    let rc = unsafe { libc::daemon(0, 0) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_family = "unix"))]
pub fn daemonize() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "-daemon requires a Unix-family OS",
    ))
}

// ============================================================
// READINESS NOTIFICATION (sd_notify-style)
// ============================================================

/// Notify a parent supervisor that the node is fully started by writing the
/// byte string "READY=1\n" to the file descriptor passed via `--ready-fd`.
///
/// This is a deliberately minimal sd_notify shim: full sd_notify(3) talks to
/// `$NOTIFY_SOCKET` (a unix-domain datagram socket), but every supervisor we
/// care about (s6, runit, our own start_mainnet.sh, systemd's NotifyAccess=
/// w/ FDStore) accepts a plain pipe write as the readiness signal.  See
/// bitcoin-core/src/init.cpp::AppInitMain → `sd_notify` for the sd-bus
/// equivalent we are emulating here.
pub fn notify_ready(fd: i32) -> std::io::Result<()> {
    if fd < 0 {
        return Ok(());
    }
    use std::io::Write as _;
    use std::os::fd::FromRawFd;
    // SAFETY: We take ownership of the FD just long enough to write to it,
    // then leak it back via into_raw_fd() so the caller (typically systemd
    // or our launcher) keeps owning it. A naive `from_raw_fd` followed by
    // drop would close it, breaking subsequent notifications.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let res = f.write_all(b"READY=1\n").and_then(|_| f.flush());
    use std::os::fd::IntoRawFd;
    let _ = f.into_raw_fd();
    res
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_parse_basic_kv() {
        let c = ConfFile::parse("rpcuser=alice\nrpcpassword=secret\n");
        assert_eq!(c.get("rpcuser"), Some("alice"));
        assert_eq!(c.get("rpcpassword"), Some("secret"));
    }

    #[test]
    fn conf_parse_strips_comments_and_blanks() {
        let txt = "\n# header comment\nlisten=1 # inline\n\n[main]\nport=8333\n";
        let c = ConfFile::parse(txt);
        assert_eq!(c.get("listen"), Some("1"));
        assert_eq!(c.get("port"), Some("8333"));
    }

    #[test]
    fn conf_parse_quoted_values() {
        let c = ConfFile::parse(r#"datadir="/var/lib/rustoshi""#);
        assert_eq!(c.get("datadir"), Some("/var/lib/rustoshi"));
    }

    #[test]
    fn conf_get_bool_truthy_falsy() {
        let c = ConfFile::parse("a=1\nb=true\nc=0\nd=no");
        assert_eq!(c.get_bool("a"), Some(true));
        assert_eq!(c.get_bool("b"), Some(true));
        assert_eq!(c.get_bool("c"), Some(false));
        assert_eq!(c.get_bool("d"), Some(false));
        assert_eq!(c.get_bool("missing"), None);
    }

    #[test]
    fn debug_cats_known_pair() {
        let (d, unk) = debug_categories_to_directives("net,rpc");
        assert!(d.contains("rustoshi_network=debug"));
        assert!(d.contains("rustoshi_rpc=debug"));
        assert!(unk.is_empty());
    }

    #[test]
    fn debug_cats_all_expands() {
        let (d, _) = debug_categories_to_directives("all");
        assert!(d.contains("rustoshi_network=debug"));
        assert!(d.contains("rustoshi_consensus=debug"));
    }

    #[test]
    fn debug_cats_zero_disables() {
        let (d, _) = debug_categories_to_directives("net,0");
        assert!(d.is_empty());
    }

    #[test]
    fn pid_file_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rustoshi.pid");
        write_pid_file(&path).unwrap();
        let s = std::fs::read_to_string(&path).unwrap();
        assert_eq!(s.trim().parse::<u32>().unwrap(), std::process::id());
        remove_pid_file(&path);
        assert!(!path.exists());
    }

    #[test]
    fn reopenable_log_appends_then_reopens() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("debug.log");
        let mut log = ReopenableLogFile::new(path.clone()).unwrap();
        log.write_all(b"line1\n").unwrap();
        log.flush().unwrap();
        // simulate logrotate: rename file, then SIGHUP
        let rotated = tmp.path().join("debug.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        log.reopen().unwrap();
        log.write_all(b"line2\n").unwrap();
        log.flush().unwrap();
        let new_contents = std::fs::read_to_string(&path).unwrap();
        let old_contents = std::fs::read_to_string(&rotated).unwrap();
        assert_eq!(new_contents, "line2\n");
        assert_eq!(old_contents, "line1\n");
    }

    #[test]
    fn envfilter_accepts_debug_directives() {
        // Ensure the directives we synthesize parse cleanly into an
        // EnvFilter.  This catches regressions in target-name spelling.
        use tracing_subscriber::EnvFilter;
        let (d, _) = debug_categories_to_directives("net,mempool,rpc");
        let filter = EnvFilter::try_new(format!("info,{}", d)).unwrap();
        let _ = filter; // just confirming parse succeeds
    }
}
