//! rustoshi - A Bitcoin full node in Rust.
//!
//! This is the main entry point that wires all subsystems together:
//! - Parse CLI arguments
//! - Initialize the database
//! - Start the P2P network
//! - Begin chain synchronization
//! - Launch the RPC server
//! - Handle graceful shutdown

use clap::{Parser, Subcommand};
use rand::RngCore;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tokio::io::AsyncWriteExt;

mod ops;
use ops::{
    daemonize, debug_categories_to_directives, notify_ready, remove_pid_file, write_pid_file,
    ConfFile, ReopenableLogFile,
};

use rustoshi_consensus::{
    dump_mempool, get_block_proof, load_mempool, ChainParams, ChainState, ChainWork, FeeEstimator,
    NetworkId, ValidationError,
};
use rustoshi_network::{
    asmap as asmap_mod, BlockDownloader, CFCheckptMessage, CFHeadersMessage, CFilterMessage,
    HeaderSync, InvType, InvVector, MisbehaviorReason, NetGroupManager, NetworkMessage, PeerEvent,
    PeerManager, PeerManagerConfig, CFCHECKPT_INTERVAL, MAX_GETCFHEADERS_SIZE,
    MAX_GETCFILTERS_SIZE, NODE_COMPACT_FILTERS,
};
use rustoshi_primitives::{Encodable, Hash256, OutPoint};
use rustoshi_rpc::{start_rest_server, start_rpc_server, PeerState, RestConfig, RpcConfig, RpcState};
use rustoshi_storage::{
    block_store::{BlockIndexEntry, BlockStatus, TxIndexEntry},
    indexes::BlockFilterIndex,
    BlockStore, ChainDb,
};

// ============================================================
// CLI DEFINITIONS
// ============================================================

#[derive(Parser, Debug)]
#[command(name = "rustoshi", version, about = "A Bitcoin full node in Rust")]
struct Cli {
    /// Network to connect to: mainnet, testnet3, testnet4, signet, regtest
    #[arg(long, default_value = "testnet4")]
    network: String,

    /// Data directory for blockchain data and configuration
    #[arg(long, default_value = "~/.rustoshi")]
    datadir: String,

    /// RPC bind address
    #[arg(long, default_value = "127.0.0.1:8332")]
    rpcbind: String,

    /// RPC authentication user
    #[arg(long)]
    rpcuser: Option<String>,

    /// RPC authentication password
    #[arg(long)]
    rpcpassword: Option<String>,

    /// Path to a PEM-encoded TLS certificate (chain) for the JSON-RPC server.
    ///
    /// When BOTH `--rpc-tls-cert` and `--rpc-tls-key` are set, rustoshi binds
    /// the RPC endpoint as HTTPS instead of HTTP. When neither is set,
    /// behaviour is unchanged (HTTP). Setting only one is a startup error.
    ///
    /// Mirrors Bitcoin Core's libevent+OpenSSL HTTPS pattern from
    /// `bitcoin-core/src/httpserver.cpp` (W119 / FIX-64). Required for
    /// clearnet PayJoin (BIP-78) which mandates HTTPS or .onion.
    #[arg(long = "rpc-tls-cert", value_name = "PATH")]
    rpc_tls_cert: Option<String>,

    /// Path to a PEM-encoded private key (PKCS#8, RSA, or SEC1) for the
    /// JSON-RPC server.  See `--rpc-tls-cert` for activation semantics.
    #[arg(long = "rpc-tls-key", value_name = "PATH")]
    rpc_tls_key: Option<String>,

    /// Listen for incoming P2P connections
    #[arg(long, default_value = "true")]
    listen: bool,

    /// Advertise NODE_BLOOM (BIP 37) and serve BIP 35 mempool requests.
    /// Mirrors Bitcoin Core's `-peerbloomfilters` (default: disabled, per
    /// `bitcoin-core/src/net_processing.h:44 DEFAULT_PEERBLOOMFILTERS=false`).
    #[arg(long, default_value = "false")]
    peerbloomfilters: bool,

    /// FIX-88 W121 G29: enable the BIP-157/158 compact-block-filter index.
    ///
    /// Mirrors Bitcoin Core's `-blockfilterindex=basic` (default: disabled,
    /// per `bitcoin-core/src/index/blockfilterindex.h` and `init.cpp:992`).
    /// When set, every block connected (and the genesis block at startup)
    /// is indexed into `CF_BLOCKFILTER` + `CF_BLOCKFILTER_HEADER` so the
    /// node can serve `getcfilters` / `getcfheaders` / `getcfcheckpt` P2P
    /// messages and `getblockfilter` / REST `/rest/blockfilter` queries.
    ///
    /// Accepts the same values as Core: `0`/`false`/`basic`/`1`/`true`.
    /// rustoshi only supports the BIP-158 basic filter type; any non-zero
    /// value enables it.  `--peerblockfilters` REQUIRES this flag, per Core
    /// `init.cpp:994-996`.
    #[arg(
        long = "blockfilterindex",
        default_value = "false",
        value_name = "0|1|basic",
    )]
    blockfilterindex: String,

    /// FIX-88 W121 G30: advertise `NODE_COMPACT_FILTERS` (BIP-157) and
    /// serve BIP-157 P2P filter messages.
    ///
    /// Mirrors Bitcoin Core's `-peerblockfilters` (default: disabled, per
    /// `bitcoin-core/src/init.cpp:993 DEFAULT_PEERBLOCKFILTERS`).  Core
    /// rejects `-peerblockfilters` without `-blockfilterindex` (init.cpp
    /// 994-996); rustoshi enforces the same precondition at startup.
    /// The service bit is gated through
    /// `crates/network/src/peer_manager.rs::should_advertise_compact_filters`,
    /// which also requires `BIP157_P2P_HANDLERS_REGISTERED` (FIX-82).
    #[arg(long, default_value = "false")]
    peerblockfilters: bool,

    /// P2P listen port (overrides network default)
    #[arg(long)]
    port: Option<u16>,

    /// Maximum number of outbound connections
    #[arg(long, default_value = "8")]
    maxconnections: usize,

    /// Connect only to this peer (for testing)
    #[arg(long)]
    connect: Option<String>,

    /// Enable transaction indexing
    #[arg(long)]
    txindex: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    loglevel: String,

    /// Prometheus metrics port (0 to disable)
    #[arg(long, default_value = "9332")]
    metrics_port: u16,

    /// Prune blockchain data to this many MiB
    #[arg(long)]
    prune: Option<u64>,

    /// Import blocks from blk*.dat files or stdin (use "-" for stdin).
    /// For blk*.dat: pass the directory containing the files.
    /// For stdin: pipe framed data [4B height LE][4B size LE][block bytes].
    #[arg(long, value_name = "PATH")]
    import_blocks: Option<String>,

    /// Run as a background daemon (Bitcoin Core `-daemon`).
    /// Forks via libc daemon(0,0), detaches stdio, writes a PID file.
    #[arg(long, default_value = "false")]
    daemon: bool,

    /// Path to PID file (default: `<datadir>/rustoshi.pid`).
    /// Always written on launch, removed on graceful shutdown.
    #[arg(long, value_name = "PATH")]
    pidfile: Option<String>,

    /// Bitcoin Core-style debug-category list, comma-separated.
    /// E.g. `--debug=net,mempool,rpc`. `--debug=all` enables every category;
    /// `--debug=0` disables all. Stacks on top of `--loglevel`.
    #[arg(long = "debug", value_name = "CATEGORIES")]
    debug_categories: Option<String>,

    /// Path to a TOML or Bitcoin Core-style key=value config file.
    /// Parsed before CLI defaults so CLI flags always win.
    /// Default search order: explicit `--conf`, then `<datadir>/rustoshi.conf`,
    /// then `~/.rustoshi/rustoshi.conf`.
    #[arg(long = "conf", value_name = "PATH")]
    conf: Option<String>,

    /// If true, write logs to stdout in addition to the debug log file.
    /// Mirrors Bitcoin Core's `-printtoconsole` (default: true).
    /// Use `--no-printtoconsole` to disable stdout logging while keeping the
    /// debug log file.  Implicitly disabled when `--daemon` is set.
    #[arg(
        long = "printtoconsole",
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
    )]
    printtoconsole: bool,

    /// Path to the rustoshi debug log file (default: `<datadir>/debug.log`).
    /// SIGHUP reopens this file in place for logrotate compatibility.
    #[arg(long = "debuglogfile", value_name = "PATH")]
    debuglogfile: Option<String>,

    /// File descriptor for sd_notify-style readiness signaling.
    /// When set, rustoshi writes "READY=1\n" to the FD once startup is
    /// complete, allowing process supervisors to detect successful launch.
    #[arg(long = "ready-fd", value_name = "FD")]
    ready_fd: Option<i32>,

    /// Path to a Bitcoin Core-format UTXO snapshot to load on startup.
    /// Mirrors Core's `-loadsnapshot=<path>` (see
    /// `bitcoin-core/src/rpc/blockchain.cpp::loadtxoutset`). The snapshot's
    /// blockhash must be in `chainparams.assumeutxo_data` and its serialized
    /// UTXO hash must match the recorded value, otherwise the load is
    /// rejected and the node continues a normal genesis IBD.
    #[arg(long = "load-snapshot", value_name = "PATH")]
    load_snapshot: Option<String>,

    /// Enable the unauthenticated REST HTTP server.
    /// Mirrors Bitcoin Core's `-rest` (default off; see
    /// `bitcoin-core/src/init.cpp DEFAULT_REST_ENABLE = false`). When set,
    /// rustoshi binds an axum server on `--restbind` exposing the same
    /// `/rest/*` URI surface as Core 31.99 (`bitcoin-core/src/rest.cpp`).
    #[arg(long = "rest", default_value = "false")]
    rest: bool,

    /// REST bind address (e.g. `127.0.0.1:8333`). Defaults to the RPC bind
    /// IP with the RPC port + 100 — i.e. mainnet 127.0.0.1:8432, testnet4
    /// 127.0.0.1:48432. Bitcoin Core multiplexes REST on the same port as
    /// JSON-RPC; rustoshi uses a separate port because the underlying RPC
    /// server (`jsonrpsee 0.22`) owns its listener and does not expose a
    /// hookable HTTP router. The REST surface is otherwise byte-compatible
    /// with Core's. Has no effect unless `--rest` is also set.
    #[arg(long = "restbind", value_name = "ADDR")]
    restbind: Option<String>,

    /// Path to an ASMap binary file for AS-based IP bucketing (anti-eclipse).
    /// If not absolute, the path is resolved relative to the datadir.
    /// When loaded, peers are grouped by Autonomous System Number (ASN)
    /// instead of /16 subnet prefix, providing stronger eclipse-attack protection.
    ///
    /// Mirrors Bitcoin Core's `-asmap=<file>` from `src/init.cpp`.
    #[arg(long = "asmap", value_name = "PATH")]
    asmap: Option<String>,

    /// SOCKS5 proxy for clearnet (IPv4/IPv6) outbound connections.
    ///
    /// Mirrors Bitcoin Core's `-proxy=<host:port>`. When set, all clearnet
    /// outbound connections go through this proxy. Also used as the Tor
    /// fallback when `--onion` is unset.
    ///
    /// Example: `--proxy=127.0.0.1:9050`
    #[arg(long = "proxy", value_name = "HOST:PORT")]
    proxy: Option<String>,

    /// Dedicated SOCKS5 proxy for Tor v3 (.onion) outbound connections.
    ///
    /// Mirrors Bitcoin Core's `-onion=<host:port>`. Takes precedence over
    /// `--proxy` for Tor v3 peers learned via ADDRv2.
    ///
    /// Example: `--onion=127.0.0.1:9050`
    #[arg(long = "onion", value_name = "HOST:PORT")]
    onion: Option<String>,

    /// I2P SAM 3.1 bridge address for I2P outbound connections.
    ///
    /// Mirrors Bitcoin Core's `-i2psam=<host:port>`. When set, I2P peers
    /// learned via ADDRv2 become reachable through the SAM bridge.
    ///
    /// Example: `--i2psam=127.0.0.1:7656`
    #[arg(long = "i2psam", value_name = "HOST:PORT")]
    i2psam: Option<String>,

    /// Treat CJDNS addresses (fc00::/8 IPv6) as reachable.
    ///
    /// Mirrors Bitcoin Core's `-cjdnsreachable`. Enable only when the host
    /// has a working CJDNS interface and can route fc00::/8 natively.
    #[arg(long = "cjdnsreachable", default_value = "false")]
    cjdnsreachable: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Reindex the blockchain from stored block data
    Reindex,
    /// Wipe and resync the blockchain
    Resync,
}

// ============================================================
// DATA DIRECTORY HANDLING
// ============================================================

/// Resolve the data directory path, expanding ~ and appending network subdirectory.
///
/// Mainnet data is stored directly in the data directory, while other networks
/// use subdirectories (following Bitcoin Core's convention).
/// Expand `~` in a datadir string and return the base path (no network
/// subdirectory).  The cookie file is written here so that all
/// implementations share the same `<datadir>/.cookie` convention.
fn resolve_base_datadir(datadir: &str) -> PathBuf {
    let expanded = if datadir.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        datadir.replacen('~', &home, 1)
    } else {
        datadir.to_string()
    };
    PathBuf::from(expanded)
}

/// Median of a (partial) median-time-past timestamp window.
///
/// Mirrors Bitcoin Core `CBlockIndex::GetMedianTimePast` (chain.h):
/// Core fills a fixed-size buffer by walking `pprev` for up to
/// `nMedianTimeSpan` (11) steps, **stopping early when `pindex` is null**,
/// then returns the middle element of the *populated* range. Near genesis
/// that range is shorter than 11 — Core does not special-case it, it just
/// medians whatever it has. This helper does the same: it takes the
/// timestamps already gathered (in any order) and returns the median, or
/// `None` for an empty slice.
fn median_time_past(timestamps: &mut [u32]) -> Option<u32> {
    if timestamps.is_empty() {
        return None;
    }
    timestamps.sort_unstable();
    Some(timestamps[timestamps.len() / 2])
}

/// Compute the median-time-past (MTP) of the block at `tip_hash` by walking
/// up to 11 ancestors via the block store.
///
/// Returns the median of **whatever ancestor timestamps are reachable** —
/// the full 11-block window when available, a shorter window when the walk
/// runs off the front of the chain (genesis-adjacent) or hits a header
/// that isn't stored. This matches Core's `GetMedianTimePast`, which
/// likewise medians a partial window rather than refusing to produce a
/// value.
///
/// Returns `None` only when **zero** ancestor headers are reachable, e.g.
/// when `tip_hash` is the base block of a freshly-loaded assumeUTXO
/// snapshot whose own header was never downloaded. Callers that connect
/// blocks past a snapshot base must use [`mtp_for_connect`] instead, which
/// falls back to the trusted `AssumeutxoData::base_mtp` chainparams
/// constant in that case.
fn compute_mtp_via_store(
    block_store: &BlockStore,
    tip_hash: &rustoshi_primitives::Hash256,
) -> Option<u32> {
    use rustoshi_consensus::params::MEDIAN_TIME_PAST_WINDOW;
    let mut timestamps: Vec<u32> = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
    let mut current = *tip_hash;
    for _ in 0..MEDIAN_TIME_PAST_WINDOW {
        match block_store.get_header(&current) {
            Ok(Some(header)) => {
                timestamps.push(header.timestamp);
                if header.prev_block_hash == rustoshi_primitives::Hash256::ZERO {
                    // Walked off the front of the chain.
                    break;
                }
                current = header.prev_block_hash;
            }
            // Header not stored (e.g. the parent is below an assumeUTXO
            // snapshot base): stop the walk here and median what we have,
            // exactly as Core stops at a null `pprev`.
            _ => break,
        }
    }
    median_time_past(&mut timestamps)
}

/// MTP to use as the `IsFinalTx` / `ContextualCheckBlock` `nLockTimeCutoff`
/// when connecting the block whose parent is `parent_hash`.
///
/// This is [`compute_mtp_via_store`] plus the assumeUTXO boundary case.
/// On a freshly-loaded snapshot node, header sync starts *at* the snapshot
/// base, so neither the base block nor its 10 ancestors have stored
/// headers. The first post-snapshot block (e.g. mainnet 944,184) is then
/// connected with its parent being that header-less base, and
/// `compute_mtp_via_store` returns `None`.
///
/// Before this path existed, the connect loop did `.unwrap_or(0)`, so the
/// `nLockTimeCutoff` collapsed to `0` and every transaction with a
/// time-based `nLockTime` in the first post-snapshot block was rejected as
/// `bad-txns-nonfinal` — wedging the chain at the snapshot base (mainnet
/// 2026-05-20). Bitcoin Core never hits this because it validates the
/// whole header chain before activating a snapshot, so the base block's
/// `CBlockIndex` always has a real `GetMedianTimePast()`.
///
/// When the store yields no MTP and `parent_hash` is a configured
/// assumeUTXO snapshot base, we fall back to the trusted
/// `AssumeutxoData::base_mtp` chainparams constant (the median of the 11
/// block timestamps ending at the snapshot base height). Once a few
/// post-snapshot headers are stored, `compute_mtp_via_store`'s partial
/// window takes over and converges to the exact 11-block MTP.
fn mtp_for_connect(
    block_store: &BlockStore,
    parent_hash: &rustoshi_primitives::Hash256,
    params: &rustoshi_consensus::ChainParams,
) -> Option<u32> {
    if let Some(mtp) = compute_mtp_via_store(block_store, parent_hash) {
        return Some(mtp);
    }
    // No ancestor headers reachable. If the parent is a trusted assumeUTXO
    // snapshot base, use its pinned MTP so the first post-snapshot block
    // validates `IsFinalTx` correctly.
    params
        .assumeutxo_for_blockhash(parent_hash)
        .and_then(|d| d.base_mtp)
}

/// Pattern C0 (txindex-on-connect): persist a `txid -> block_hash` mapping
/// for every transaction in `block`. Called from every block-connect path
/// (stdin import, framed import, IBD validation interval, IBD per-block
/// validation) so that `getrawtransaction` can resolve a tx via the
/// txindex without an explicit blockhash. Errors are logged but do not
/// abort the connect — failing to write the txindex is a soft failure
/// (the block has been validated, the UTXO is correct; the worst case is
/// that `getrawtransaction(txid)` returns "not found" until the txindex
/// is rebuilt).
///
/// Mirrors `bitcoin-core/src/index/txindex.cpp::CustomAppend` (fired from
/// `BaseIndex::BlockConnected`).
///
/// See CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
/// for the cross-impl finding that motivated this wiring.
fn write_tx_index_entries(
    block_store: &BlockStore,
    block: &rustoshi_primitives::Block,
    block_hash: rustoshi_primitives::Hash256,
) {
    for tx in &block.transactions {
        let entry = TxIndexEntry {
            block_hash,
            tx_offset: 0,
            tx_length: 0,
        };
        if let Err(e) = block_store.put_tx_index(&tx.txid(), &entry) {
            tracing::warn!(
                "tx_index write failed for {} in block {}: {}",
                tx.txid(), block_hash, e
            );
        }
    }
}

/// Update the BIP-157/158 BlockFilterIndex for a newly connected block.
///
/// Mirrors `bitcoin-core/src/index/blockfilterindex.cpp::CustomAppend` (fired
/// from `BaseIndex::BlockConnected`).  Must be called after a successful
/// `ChainState::process_block` so that:
///   - The block's basic GCS filter (BIP-158) is built and persisted.
///   - The filter header chain (BIP-157) is extended.
///   - The /rest/blockfilter and /rest/blockfilterheaders REST endpoints can
///     serve light clients.
///
/// W121 BUG-16 P0 (FIX-69): prior to this wiring, the entire ~6500 LOC
/// GCS + index + REST stack in `rustoshi-storage::indexes` was DEAD CODE
/// because no production code path ever called `BlockFilterIndex::index_block`.
/// Light clients querying /rest/blockfilter would get 404 after a full IBD.
fn write_block_filter_index(
    block_store: &BlockStore,
    block: &rustoshi_primitives::Block,
    height: u32,
    undo: &rustoshi_consensus::validation::UndoData,
) {
    let idx = BlockFilterIndex::new(block_store.db());
    match idx.connect_block(height, block, undo) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "BlockFilterIndex update failed for {} at height {}: {}",
                block.block_hash(), height, e
            );
        }
    }
}

fn resolve_datadir(datadir: &str, params: &ChainParams) -> PathBuf {
    let mut path = resolve_base_datadir(datadir);

    // Append network subdirectory (except mainnet)
    match params.network_id {
        NetworkId::Mainnet => {}
        NetworkId::Testnet3 => {
            path.push("testnet3");
        }
        NetworkId::Testnet4 => {
            path.push("testnet4");
        }
        NetworkId::Signet => {
            path.push("signet");
        }
        NetworkId::Regtest => {
            path.push("regtest");
        }
    }

    path
}

// ============================================================
// PROMETHEUS METRICS SERVER
// ============================================================

/// Start a lightweight HTTP server that serves Prometheus-format metrics.
async fn start_metrics_server(
    port: u16,
    rpc_state: Arc<RwLock<RpcState>>,
    peer_state: Arc<RwLock<PeerState>>,
) {
    if port == 0 {
        return;
    }
    let addr = format!("0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Metrics server failed to bind to {}: {}", addr, e);
            return;
        }
    };
    tracing::info!("Prometheus metrics server listening on {}", addr);

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let rpc_state = rpc_state.clone();
        let peer_state = peer_state.clone();
        tokio::spawn(async move {
            // Read the HTTP request line so we can route by path.
            let mut buf = [0u8; 4096];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await
                .unwrap_or(0);
            let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
            // Extract first request line, then the path token.
            let path = req.lines().next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();

            // /health: minimal liveness endpoint for process supervisors.
            // Returns 200 once the node has booted (we're inside the running
            // metrics task, which only starts after RPC is up). Body is
            // small JSON so curl/jq scripts can consume it.
            if path == "/health" || path == "/healthz" || path == "/livez" {
                let height = {
                    let state = rpc_state.read().await;
                    state.best_height
                };
                let peers = {
                    let ps = peer_state.read().await;
                    ps.peer_manager.as_ref().map_or(0, |pm| pm.peer_count() as u32)
                };
                let body = format!(
                    "{{\"status\":\"ok\",\"height\":{},\"peers\":{}}}\n",
                    height, peers
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                return;
            }

            // Default: Prometheus /metrics body.
            let (height, mempool_size) = {
                let state = rpc_state.read().await;
                (state.best_height, state.mempool.size())
            };
            let peers = {
                let ps = peer_state.read().await;
                ps.peer_manager.as_ref().map_or(0, |pm| pm.peer_count() as u32)
            };

            let body = format!(
                "# HELP bitcoin_blocks_total Current block height\n\
                 # TYPE bitcoin_blocks_total gauge\n\
                 bitcoin_blocks_total {}\n\
                 # HELP bitcoin_peers_connected Number of connected peers\n\
                 # TYPE bitcoin_peers_connected gauge\n\
                 bitcoin_peers_connected {}\n\
                 # HELP bitcoin_mempool_size Mempool transaction count\n\
                 # TYPE bitcoin_mempool_size gauge\n\
                 bitcoin_mempool_size {}\n",
                height, peers, mempool_size,
            );

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// Get the appropriate RPC port for a network.
fn default_rpc_port(network_id: NetworkId) -> u16 {
    match network_id {
        NetworkId::Mainnet => 8332,
        NetworkId::Testnet3 => 18332,
        NetworkId::Testnet4 => 48332,
        NetworkId::Signet => 38332,
        NetworkId::Regtest => 18443,
    }
}

// ============================================================
// COOKIE AUTH HELPERS
// ============================================================

/// Generate a 32-byte random secret and write the Bitcoin Core-style cookie
/// file to `<datadir>/.cookie`.
///
/// The file contains a single line: `__cookie__:<64-hex-chars>`.
/// File permissions are set to 0o600 (owner read/write only) so that only
/// the process owner can read the credentials.
///
/// Returns the raw hex secret (the password half of the cookie string).
fn write_cookie_file(datadir: &std::path::Path) -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = hex::encode(bytes);

    let cookie_content = format!("__cookie__:{}", secret);
    let cookie_path = datadir.join(".cookie");

    std::fs::write(&cookie_path, &cookie_content)?;

    // Restrict to owner read/write (0o600) — same as Bitcoin Core.
    std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600))?;

    tracing::info!("Cookie file written to {}", cookie_path.display());
    Ok(secret)
}

/// Delete the cookie file on shutdown so stale credentials don't linger.
fn delete_cookie_file(datadir: &std::path::Path) {
    let cookie_path = datadir.join(".cookie");
    if let Err(e) = std::fs::remove_file(&cookie_path) {
        // Not fatal — the file may already be gone, or on a read-only FS.
        tracing::warn!("Failed to delete cookie file {}: {}", cookie_path.display(), e);
    } else {
        tracing::debug!("Cookie file deleted: {}", cookie_path.display());
    }
}

// ============================================================
// BLOCK IMPORT FROM BLK*.DAT FILES
// ============================================================

/// Location of a block within a blk*.dat file.
struct BlkLocation {
    file_num: u32,
    offset: u64,
    size: u32,
}

/// Detect the XOR obfuscation key used by Bitcoin Core 28.0+.
/// Returns the 8-byte key (all zeros if no obfuscation is detected).
fn detect_xor_key(blocks_dir: &std::path::Path, expected_magic: &[u8; 4]) -> [u8; 8] {
    use std::io::Read;

    let path = blocks_dir.join("blk00000.dat");
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return [0u8; 8],
    };

    let mut header = [0u8; 8];
    if file.read_exact(&mut header).is_err() {
        return [0u8; 8];
    }

    // Check if already plaintext
    if header[0..4] == *expected_magic {
        return [0u8; 8];
    }

    // Derive key: first 4 bytes XOR'd with magic, next 4 with expected size
    // The genesis block is 285 bytes = 0x011d for mainnet
    // But we can derive the full 8-byte key from just the magic:
    // key[0..4] = file[0..4] XOR magic
    // For bytes 4..8: the block size is a LE uint32, and the key repeats
    // every 8 bytes, so key[4..8] = file[4..8] XOR size_bytes
    // Since we know the genesis block size, derive key[4..8] from that
    let mut key = [0u8; 8];
    for i in 0..4 {
        key[i] = header[i] ^ expected_magic[i];
    }
    // The genesis block size varies by network, but we can derive key[4..8]
    // by recognizing that the XOR key repeats: use first block's size field
    // We'll try decoding with just the first 4 bytes known, and figure out
    // the rest from the pattern (Bitcoin Core uses the same 8-byte key cyclically)
    // Actually, the key is stored in LevelDB, but we can derive all 8 bytes
    // from the file since we know bytes 8..12 must be version=1 (01000000 LE):
    let _more = [0u8; 4];
    // Read bytes 8..12 (first 4 bytes of actual block header after magic+size)
    // but we need bytes 4..8 first. We know key repeats with period 8.
    // Derive from bytes at offset 8: they should be block version (01 00 00 00)
    let mut buf12 = [0u8; 4];
    if file.read_exact(&mut buf12).is_ok() {
        // offset 8..12, after XOR should be version=1 LE = [01, 00, 00, 00]
        let expected_version = [0x01u8, 0x00, 0x00, 0x00];
        // key index at file offset 8 = 8 % 8 = 0, so these use key[0..4]
        // That means file[8..12] XOR key[0..4] should equal version
        // We already have key[0..4], let's verify:
        let decoded_version: Vec<u8> = buf12.iter().zip(key[0..4].iter()).map(|(a, b)| a ^ b).collect();
        if decoded_version == expected_version {
            // Now derive key[4..8] from file[4..8]:
            // file[4..8] XOR key[4..8] = size bytes
            // We need to know the size. But file[12..16] at key offset 4..8
            // should be prev_block_hash[0..4] = 0000...0 for genesis
            let mut buf16 = [0u8; 4];
            if file.read_exact(&mut buf16).is_ok() {
                // file offset 12..16, key offset 12%8=4, so key[4..8]
                // decoded should be prevhash[0..4] = [0,0,0,0]
                key[4..(4 + 4)].copy_from_slice(&buf16); // ^ 0 = buf16[i]
            }
        }
    }

    tracing::info!("Detected XOR obfuscation key: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
    key
}

/// Apply XOR deobfuscation to a buffer, starting at given file offset.
fn xor_deobfuscate(data: &mut [u8], file_offset: u64, key: &[u8; 8]) {
    if *key == [0u8; 8] {
        return;
    }
    for (i, byte) in data.iter_mut().enumerate() {
        let key_idx = ((file_offset + i as u64) % 8) as usize;
        *byte ^= key[key_idx];
    }
}

/// Scan all blk*.dat files in `blocks_dir` and build a hash-to-location index.
fn scan_blk_files(
    blocks_dir: &std::path::Path,
    expected_magic: &[u8; 4],
) -> anyhow::Result<(std::collections::HashMap<rustoshi_primitives::Hash256, BlkLocation>, [u8; 8])> {
    use rustoshi_primitives::{BlockHeader, Decodable};
    use std::io::{Read, Seek, SeekFrom};

    let xor_key = detect_xor_key(blocks_dir, expected_magic);
    let mut index = std::collections::HashMap::new();
    let mut file_num: u32 = 0;

    loop {
        let path = blocks_dir.join(format!("blk{:05}.dat", file_num));
        if !path.exists() {
            break;
        }

        let file = std::fs::File::open(&path)?;
        let file_len = file.metadata()?.len();
        let mut reader = std::io::BufReader::with_capacity(4 * 1024 * 1024, file);
        let mut pos: u64 = 0;
        let mut blocks_in_file = 0u32;

        while pos + 8 <= file_len {
            // Read magic + size
            let mut header = [0u8; 8];
            if reader.read_exact(&mut header).is_err() {
                break;
            }
            xor_deobfuscate(&mut header, pos, &xor_key);

            let magic = &header[0..4];
            let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

            // Check for zero padding at end of file
            if magic == [0, 0, 0, 0] || header == [0u8; 8] {
                break;
            }

            if magic != expected_magic {
                tracing::warn!(
                    "Bad magic at blk{:05}.dat offset {} ({:02x}{:02x}{:02x}{:02x}), skipping",
                    file_num, pos, magic[0], magic[1], magic[2], magic[3]
                );
                break;
            }

            if size == 0 || size > 4_000_000 {
                tracing::warn!(
                    "Invalid block size {} at blk{:05}.dat offset {}",
                    size, file_num, pos
                );
                break;
            }

            let block_offset = pos + 8; // offset of the raw block data

            // Read just the 80-byte header to get the block hash
            let mut header_bytes = [0u8; 80];
            if reader.read_exact(&mut header_bytes).is_err() {
                break;
            }
            xor_deobfuscate(&mut header_bytes, block_offset, &xor_key);
            let block_header = BlockHeader::deserialize(&header_bytes)?;
            let hash = block_header.block_hash();

            // Skip the rest of the block (size - 80 bytes already read)
            let remaining = size as u64 - 80;
            if reader.seek(SeekFrom::Current(remaining as i64)).is_err() {
                break;
            }

            index.insert(hash, BlkLocation {
                file_num,
                offset: block_offset,
                size,
            });

            blocks_in_file += 1;
            pos = block_offset + size as u64;
        }

        tracing::info!(
            "Scanned blk{:05}.dat: {} blocks (total index: {})",
            file_num, blocks_in_file, index.len()
        );
        file_num += 1;
    }

    if file_num == 0 {
        anyhow::bail!("No blk*.dat files found in {}", blocks_dir.display());
    }

    tracing::info!(
        "Block index built: {} blocks from {} files",
        index.len(), file_num
    );
    Ok((index, xor_key))
}

/// Read a single block from a blk*.dat file at the given location.
fn read_block_at(
    blocks_dir: &std::path::Path,
    loc: &BlkLocation,
    xor_key: &[u8; 8],
) -> anyhow::Result<rustoshi_primitives::Block> {
    use rustoshi_primitives::{Block, Decodable};
    use std::io::{Read, Seek, SeekFrom};

    let path = blocks_dir.join(format!("blk{:05}.dat", loc.file_num));
    let mut file = std::fs::File::open(&path)?;
    file.seek(SeekFrom::Start(loc.offset))?;

    let mut buf = vec![0u8; loc.size as usize];
    file.read_exact(&mut buf)?;
    xor_deobfuscate(&mut buf, loc.offset, xor_key);

    let block = Block::deserialize(&buf)?;
    Ok(block)
}

/// Run the block import from blk*.dat files.
/// Reads blocks from disk and feeds them to validation in height order.
fn run_import_from_blk_files(
    blocks_dir: &std::path::Path,
    params: &ChainParams,
    block_store: &BlockStore,
    chain_state: &mut ChainState,
    utxo_view: &mut rustoshi_storage::BlockStoreUtxoView<'_>,
    start_height: u32,
) -> anyhow::Result<u32> {
    let magic = params.network_magic.0;
    tracing::info!("Scanning blk*.dat files in {} ...", blocks_dir.display());
    let (index, xor_key) = scan_blk_files(blocks_dir, &magic)?;

    let mut height = start_height + 1;
    let mut imported = 0u32;
    let import_start = std::time::Instant::now();
    let mut batch_start = std::time::Instant::now();

    loop {
        // Look up the expected block hash at this height from our header chain
        let hash = match block_store.get_hash_by_height(height) {
            Ok(Some(h)) => h,
            _ => {
                tracing::info!(
                    "No header at height {} — end of header chain. Imported {} blocks.",
                    height, imported
                );
                break;
            }
        };

        // Find the block in our blk file index
        let loc = match index.get(&hash) {
            Some(l) => l,
            None => {
                tracing::warn!(
                    "Block {} at height {} not found in blk files. Stopping import.",
                    hash, height
                );
                break;
            }
        };

        // Read and deserialize the block
        let block = read_block_at(blocks_dir, loc, &xor_key)?;

        // Store header
        if let Err(e) = block_store.put_header(&hash, &block.header) {
            tracing::error!("Failed to store header at height {}: {}", height, e);
        }

        // BIP-113: compute the median-time-past of the parent (current tip)
        // for `lock_time_cutoff` in `is_final_tx`.  Returns 0 near genesis
        // (fewer than 11 ancestors), which matches Core's behaviour.
        let prev_block_mtp =
            compute_mtp_via_store(block_store, &chain_state.tip_hash()).unwrap_or(0);

        // Validate and process (f_requested=true: import-from-Core-datadir is
        // a requested/trusted path — no fTooFarAhead guard needed).
        let undo = match chain_state.process_block(&block, utxo_view, prev_block_mtp, true, rustoshi_consensus::current_time_secs()) {
            Ok((u, _fees)) => u,
            Err(e) => {
                tracing::error!("Block validation failed at height {}: {}", height, e);
                break;
            }
        };

        // Store block index entry so getblockheader can return correct height/nTx/chainwork.
        {
            let prev_work = if block.header.prev_block_hash != Hash256::ZERO {
                block_store
                    .get_block_index(&block.header.prev_block_hash)
                    .ok()
                    .flatten()
                    .map(|e| ChainWork::from_be_bytes(e.chain_work))
                    .unwrap_or(ChainWork::ZERO)
            } else {
                ChainWork::ZERO
            };
            let this_work = prev_work.saturating_add(&get_block_proof(block.header.bits));
            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_SCRIPTS);
            status.set(BlockStatus::HAVE_DATA);
            let entry = BlockIndexEntry {
                height,
                status,
                n_tx: block.transactions.len() as u32,
                timestamp: block.header.timestamp,
                bits: block.header.bits,
                nonce: block.header.nonce,
                version: block.header.version,
                prev_hash: block.header.prev_block_hash,
                chain_work: this_work.0,
            };
            if let Err(e) = block_store.put_block_index(&hash, &entry) {
                tracing::error!("Failed to store block index at height {}: {}", height, e);
            }
        }

        // Pattern C0 (txindex-on-connect): persist tx_index for every tx so
        // that getrawtransaction works post-IBD. See write_tx_index_entries
        // for the Core reference + audit-doc citation.
        write_tx_index_entries(block_store, &block, hash);

        // BIP-157/158 block filter index — FIX-69 W121 BUG-16.  Build and
        // persist the basic GCS filter + filter header for this block so
        // that /rest/blockfilter, /rest/blockfilterheaders, and (when wired
        // upstream) BIP-157 P2P serving can respond. Mirrors Core
        // `BlockFilterIndex::CustomAppend` fired from BaseIndex::BlockConnected.
        write_block_filter_index(block_store, &block, height, &undo);

        // Flush UTXO cache if needed
        if utxo_view.needs_flush() {
            let cache_mb = utxo_view.estimated_memory() / (1024 * 1024);
            let entries = utxo_view.cache_len();
            if let Err(e) = utxo_view.flush() {
                tracing::error!("UTXO cache flush failed: {}", e);
            } else {
                tracing::info!(
                    "UTXO cache flushed: {} entries, ~{} MiB at height {}",
                    entries, cache_mb, height
                );
            }
        }

        // Update database tip
        if let Err(e) = block_store.set_best_block(&hash, height) {
            tracing::error!("Failed to update best block: {}", e);
        }

        imported += 1;
        height += 1;

        // Progress logging every 1000 blocks
        if imported.is_multiple_of(1000) {
            let elapsed = batch_start.elapsed();
            let bps = 1000.0 / elapsed.as_secs_f64();
            let total_elapsed = import_start.elapsed();
            tracing::info!(
                "Import progress: height {} ({} blocks imported, {:.0} blocks/sec, {:.0} blocks/min, elapsed {:.1}s)",
                height - 1,
                imported,
                bps,
                bps * 60.0,
                total_elapsed.as_secs_f64(),
            );
            batch_start = std::time::Instant::now();
        }
    }

    let total_elapsed = import_start.elapsed();
    if imported > 0 {
        let bps = imported as f64 / total_elapsed.as_secs_f64();
        tracing::info!(
            "Import complete: {} blocks in {:.1}s ({:.0} blocks/sec, {:.0} blocks/min)",
            imported,
            total_elapsed.as_secs_f64(),
            bps,
            bps * 60.0,
        );
    }

    Ok(imported)
}

/// Run the block import from stdin in framed format.
/// Frame: [4 bytes height LE] [4 bytes size LE] [size bytes raw block data]
fn run_import_from_stdin(
    _params: &ChainParams,
    block_store: &BlockStore,
    chain_state: &mut ChainState,
    utxo_view: &mut rustoshi_storage::BlockStoreUtxoView<'_>,
    start_height: u32,
) -> anyhow::Result<u32> {
    use rustoshi_primitives::{Block, Decodable};
    use std::io::Read;

    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::with_capacity(4 * 1024 * 1024, stdin.lock());

    let mut imported = 0u32;
    let import_start = std::time::Instant::now();
    let mut batch_start = std::time::Instant::now();

    tracing::info!("Reading blocks from stdin (framed format) starting after height {} ...", start_height);

    loop {
        // Read frame header: [4B height LE][4B size LE]
        let mut frame_header = [0u8; 8];
        match reader.read_exact(&mut frame_header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::info!("End of stdin stream.");
                break;
            }
            Err(e) => return Err(e.into()),
        }

        let frame_height = u32::from_le_bytes([
            frame_header[0], frame_header[1], frame_header[2], frame_header[3],
        ]);
        let frame_size = u32::from_le_bytes([
            frame_header[4], frame_header[5], frame_header[6], frame_header[7],
        ]);

        if frame_size == 0 || frame_size > 4_000_000 {
            anyhow::bail!("Invalid frame size {} at height {}", frame_size, frame_height);
        }

        // Skip blocks we already have
        if frame_height <= start_height {
            // Seek past the block data
            let mut remaining = frame_size as usize;
            let mut skip_buf = [0u8; 8192];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, skip_buf.len());
                reader.read_exact(&mut skip_buf[..to_read])?;
                remaining -= to_read;
            }
            continue;
        }

        // Read block data
        let mut block_data = vec![0u8; frame_size as usize];
        reader.read_exact(&mut block_data)?;

        let block = Block::deserialize(&block_data)?;
        let hash = block.block_hash();

        // Store header + height index if not already stored
        if let Err(e) = block_store.put_header(&hash, &block.header) {
            tracing::error!("Failed to store header at height {}: {}", frame_height, e);
        }
        if let Err(e) = block_store.put_height_index(frame_height, &hash) {
            tracing::error!("Failed to store height index at height {}: {}", frame_height, e);
        }

        // BIP-113: compute the median-time-past of the parent (current tip)
        // so `is_final_tx` uses the right `lock_time_cutoff` once CSV is
        // active.  Returns 0 near genesis (matches Core).
        let prev_block_mtp =
            compute_mtp_via_store(block_store, &chain_state.tip_hash()).unwrap_or(0);

        // Validate and process (f_requested=true: snapshot-import is a
        // requested/trusted path — no fTooFarAhead guard needed).
        let undo = match chain_state.process_block(&block, utxo_view, prev_block_mtp, true, rustoshi_consensus::current_time_secs()) {
            Ok((u, _fees)) => u,
            Err(e) => {
                tracing::error!("Block validation failed at height {}: {}", frame_height, e);
                break;
            }
        };

        // Store block index entry so getblockheader can return correct height/nTx/chainwork.
        {
            let prev_work = if block.header.prev_block_hash != Hash256::ZERO {
                block_store
                    .get_block_index(&block.header.prev_block_hash)
                    .ok()
                    .flatten()
                    .map(|e| ChainWork::from_be_bytes(e.chain_work))
                    .unwrap_or(ChainWork::ZERO)
            } else {
                ChainWork::ZERO
            };
            let this_work = prev_work.saturating_add(&get_block_proof(block.header.bits));
            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_SCRIPTS);
            status.set(BlockStatus::HAVE_DATA);
            let entry = BlockIndexEntry {
                height: frame_height,
                status,
                n_tx: block.transactions.len() as u32,
                timestamp: block.header.timestamp,
                bits: block.header.bits,
                nonce: block.header.nonce,
                version: block.header.version,
                prev_hash: block.header.prev_block_hash,
                chain_work: this_work.0,
            };
            if let Err(e) = block_store.put_block_index(&hash, &entry) {
                tracing::error!("Failed to store block index at height {}: {}", frame_height, e);
            }
        }

        // Pattern C0 (txindex-on-connect): persist tx_index for every tx in
        // this block so getrawtransaction works post-IBD. See
        // `write_tx_index_entries` for the Core reference + audit-doc citation.
        write_tx_index_entries(block_store, &block, hash);

        // BIP-157/158 block filter index — FIX-69 W121 BUG-16.
        // See `write_block_filter_index` for the Core reference.
        write_block_filter_index(block_store, &block, frame_height, &undo);

        // Flush UTXO cache if needed
        if utxo_view.needs_flush() {
            let cache_mb = utxo_view.estimated_memory() / (1024 * 1024);
            let entries = utxo_view.cache_len();
            if let Err(e) = utxo_view.flush() {
                tracing::error!("UTXO cache flush failed: {}", e);
            } else {
                tracing::info!(
                    "UTXO cache flushed: {} entries, ~{} MiB at height {}",
                    entries, cache_mb, frame_height
                );
            }
        }

        // Update database tip
        if let Err(e) = block_store.set_best_block(&hash, frame_height) {
            tracing::error!("Failed to update best block: {}", e);
        }

        imported += 1;

        // Progress logging every 1000 blocks
        if imported.is_multiple_of(1000) {
            let elapsed = batch_start.elapsed();
            let bps = 1000.0 / elapsed.as_secs_f64();
            let total_elapsed = import_start.elapsed();
            tracing::info!(
                "Import progress: height {} ({} blocks imported, {:.0} blocks/sec, {:.0} blocks/min, elapsed {:.1}s)",
                frame_height,
                imported,
                bps,
                bps * 60.0,
                total_elapsed.as_secs_f64(),
            );
            batch_start = std::time::Instant::now();
        }
    }

    let total_elapsed = import_start.elapsed();
    if imported > 0 {
        let bps = imported as f64 / total_elapsed.as_secs_f64();
        tracing::info!(
            "Import complete: {} blocks in {:.1}s ({:.0} blocks/sec, {:.0} blocks/min)",
            imported,
            total_elapsed.as_secs_f64(),
            bps,
            bps * 60.0,
        );
    }

    Ok(imported)
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================

/// Apply settings parsed from `--conf` over an existing `Cli`, but only for
/// values that the user hasn't already set explicitly on the command line.
///
/// We do this by re-parsing the CLI from a synthesized argv where the
/// conf-file values are inserted *before* the user's argv tokens; clap's
/// "later wins" precedence then ensures CLI flags override the config file.
/// Because that approach is fragile across long-flag names, we instead apply
/// each conf field manually below — it's a finite list and matches Bitcoin
/// Core's bitcoind.cpp behavior of merging only specific known keys.
fn apply_conf_to_cli(cli: &mut Cli, conf: &ConfFile, raw_argv: &[String]) {
    fn was_set(argv: &[String], long: &str) -> bool {
        // Crude detector: any token equal to `--<long>`, `--<long>=...`, or
        // bitcoind-style `-<long>`/`-<long>=...`.
        let dd = format!("--{}", long);
        let dd_eq = format!("--{}=", long);
        let single = format!("-{}", long);
        let single_eq = format!("-{}=", long);
        argv.iter().any(|a| {
            a == &dd || a == &single || a.starts_with(&dd_eq) || a.starts_with(&single_eq)
        })
    }

    // Strings
    macro_rules! merge_str {
        ($field:ident, $key:expr) => {
            if !was_set(raw_argv, $key) {
                if let Some(v) = conf.get($key) {
                    cli.$field = v.to_string();
                }
            }
        };
    }
    macro_rules! merge_opt_str {
        ($field:ident, $key:expr) => {
            if !was_set(raw_argv, $key) {
                if let Some(v) = conf.get($key) {
                    cli.$field = Some(v.to_string());
                }
            }
        };
    }
    macro_rules! merge_bool {
        ($field:ident, $key:expr) => {
            if !was_set(raw_argv, $key) {
                if let Some(v) = conf.get_bool($key) {
                    cli.$field = v;
                }
            }
        };
    }

    merge_str!(network, "network");
    merge_str!(datadir, "datadir");
    merge_str!(rpcbind, "rpcbind");
    merge_opt_str!(rpcuser, "rpcuser");
    merge_opt_str!(rpcpassword, "rpcpassword");
    merge_opt_str!(rpc_tls_cert, "rpc-tls-cert");
    merge_opt_str!(rpc_tls_key, "rpc-tls-key");
    merge_bool!(listen, "listen");
    merge_bool!(peerbloomfilters, "peerbloomfilters");
    // FIX-88 W121 G29/G30: conf-file plumbing for the new compact-filter flags.
    if !was_set(raw_argv, "blockfilterindex") {
        if let Some(v) = conf.get("blockfilterindex") {
            cli.blockfilterindex = v.to_string();
        }
    }
    merge_bool!(peerblockfilters, "peerblockfilters");
    if !was_set(raw_argv, "port") {
        if let Some(v) = conf.get("port") {
            if let Ok(p) = v.parse::<u16>() {
                cli.port = Some(p);
            }
        }
    }
    if !was_set(raw_argv, "maxconnections") {
        if let Some(v) = conf.get("maxconnections") {
            if let Ok(n) = v.parse::<usize>() {
                cli.maxconnections = n;
            }
        }
    }
    merge_opt_str!(connect, "connect");
    merge_bool!(txindex, "txindex");
    merge_str!(loglevel, "loglevel");
    if !was_set(raw_argv, "metrics-port") && !was_set(raw_argv, "metrics_port") {
        if let Some(v) = conf.get("metrics_port") {
            if let Ok(p) = v.parse::<u16>() {
                cli.metrics_port = p;
            }
        }
    }
    if !was_set(raw_argv, "prune") {
        if let Some(v) = conf.get("prune") {
            if let Ok(n) = v.parse::<u64>() {
                cli.prune = Some(n);
            }
        }
    }
    merge_bool!(daemon, "daemon");
    merge_opt_str!(pidfile, "pidfile");
    merge_opt_str!(debug_categories, "debug");
    merge_bool!(printtoconsole, "printtoconsole");
    merge_opt_str!(debuglogfile, "debuglogfile");
    merge_bool!(rest, "rest");
    merge_opt_str!(restbind, "restbind");
    merge_opt_str!(asmap, "asmap");
    // W117 BUG-2 proxy wiring — Bitcoin Core compatible flag names.
    merge_opt_str!(proxy, "proxy");
    merge_opt_str!(onion, "onion");
    merge_opt_str!(i2psam, "i2psam");
    merge_bool!(cjdnsreachable, "cjdnsreachable");
}

/// Locate a config file path: explicit `--conf`, then `<datadir>/rustoshi.conf`,
/// then `~/.rustoshi/rustoshi.conf`.  Returns `None` if none of the candidates
/// exist (so a missing config file is non-fatal — Core behaves the same).
fn find_conf_file(cli: &Cli) -> Option<PathBuf> {
    if let Some(p) = &cli.conf {
        // Explicit path: require it to exist (mirrors Core's `-conf` strictness)
        let path = PathBuf::from(p);
        return path.exists().then_some(path);
    }
    let datadir = resolve_base_datadir(&cli.datadir);
    let candidate = datadir.join("rustoshi.conf");
    if candidate.exists() {
        return Some(candidate);
    }
    if let Ok(home) = std::env::var("HOME") {
        let alt = PathBuf::from(home).join(".rustoshi").join("rustoshi.conf");
        if alt.exists() {
            return Some(alt);
        }
    }
    None
}

fn main() -> anyhow::Result<()> {
    let raw_argv: Vec<String> = std::env::args().collect();
    let mut cli = Cli::parse();

    // Merge config-file values BEFORE we daemonize / start the runtime, so
    // `-daemon=1` in the conf file works the same as on the CLI.
    if let Some(conf_path) = find_conf_file(&cli) {
        match ConfFile::load(&conf_path) {
            Ok(conf) => {
                apply_conf_to_cli(&mut cli, &conf, &raw_argv);
                // We can't log via tracing yet — buffer this for after init.
                eprintln!("rustoshi: loaded config from {}", conf_path.display());
            }
            Err(e) => {
                eprintln!(
                    "rustoshi: failed to load conf file {}: {}",
                    conf_path.display(),
                    e
                );
            }
        }
    }

    // Daemonize (if requested) BEFORE constructing the tokio runtime; tokio's
    // IO driver does not survive a fork.
    if cli.daemon {
        if let Err(e) = daemonize() {
            eprintln!("rustoshi: -daemon: {}", e);
            std::process::exit(1);
        }
    }

    // Now build the tokio runtime and run the async body.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // Resolve network early so we can place the debug log under the
    // network-specific data directory.
    let params = match cli.network.as_str() {
        "mainnet" | "main" => ChainParams::mainnet(),
        "testnet3" | "testnet" => ChainParams::testnet3(),
        "testnet4" => ChainParams::testnet4(),
        "signet" => ChainParams::signet(),
        "regtest" => ChainParams::regtest(),
        _ => anyhow::bail!("Unknown network: {}", cli.network),
    };

    // Resolve datadirs eagerly so we can write the PID file + debug log.
    let base_datadir = resolve_base_datadir(&cli.datadir);
    std::fs::create_dir_all(&base_datadir)?;
    let datadir = resolve_datadir(&cli.datadir, &params);
    std::fs::create_dir_all(&datadir)?;

    // ---------- LOGGING SETUP ----------
    //
    // Build an EnvFilter from `loglevel`, then layer `-debug=<cat>` directives
    // on top.  `RUST_LOG` (if present) wins over both, matching the original
    // behavior.
    let base_filter = match std::env::var("RUST_LOG") {
        Ok(env) => EnvFilter::try_new(env)
            .unwrap_or_else(|_| EnvFilter::new(&cli.loglevel)),
        Err(_) => {
            let mut spec = cli.loglevel.clone();
            if let Some(ref dbg) = cli.debug_categories {
                let (extra, unknown) = debug_categories_to_directives(dbg);
                if !extra.is_empty() {
                    spec.push(',');
                    spec.push_str(&extra);
                }
                for cat in &unknown {
                    eprintln!("rustoshi: -debug: unknown category '{}'", cat);
                }
            }
            EnvFilter::try_new(&spec).unwrap_or_else(|_| EnvFilter::new(&cli.loglevel))
        }
    };

    let log_file_path = match &cli.debuglogfile {
        Some(p) => PathBuf::from(p),
        None => datadir.join("debug.log"),
    };
    let log_file = ReopenableLogFile::new(log_file_path.clone())
        .map_err(|e| anyhow::anyhow!("open debug log {}: {}", log_file_path.display(), e))?;

    // Compose stdout + file layers.  We use registry+layers so we can add a
    // file writer on top of the optional stdout writer.
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(log_file.clone());
    let registry = tracing_subscriber::registry()
        .with(base_filter)
        .with(file_layer);
    if cli.printtoconsole && !cli.daemon {
        let stdout_layer = tracing_subscriber::fmt::layer()
            .with_target(false);
        registry.with(stdout_layer).init();
    } else {
        registry.init();
    }

    tracing::info!("Rustoshi v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Debug log: {}", log_file_path.display());
    if cli.daemon {
        tracing::info!("Running as daemon (forked, stdio detached)");
    }

    tracing::info!("Network: {:?}", params.network_id);
    tracing::info!("Genesis: {}", params.genesis_hash);

    // ---------- PID FILE ----------
    let pid_path = match &cli.pidfile {
        Some(p) => PathBuf::from(p),
        None => datadir.join("rustoshi.pid"),
    };
    if let Err(e) = write_pid_file(&pid_path) {
        tracing::warn!("Failed to write PID file {}: {}", pid_path.display(), e);
    } else {
        tracing::info!("PID {} written to {}", std::process::id(), pid_path.display());
    }

    // Handle subcommands
    if let Some(cmd) = &cli.command {
        match cmd {
            Commands::Reindex => {
                // HONEST PROGRESS: full block-index rebuild from blk*.dat is
                // out of scope for this op-parity pass.  We still parse the
                // flag, log what would happen, and exit cleanly — same as
                // before, but with operator-visible context so it doesn't
                // look like a successful no-op reindex.
                tracing::warn!(
                    "Reindex requested. NOT YET IMPLEMENTED: rustoshi does not currently \
                     rebuild the block index from blk*.dat. To resync from scratch use \
                     `rustoshi resync` (also stubbed) or stop the node, delete the \
                     `chainstate` directory under `{}`, and restart. \
                     Tracking issue: rustoshi#TODO-reindex.",
                    datadir.display()
                );
                remove_pid_file(&pid_path);
                return Ok(());
            }
            Commands::Resync => {
                tracing::warn!("Resync requested - not yet implemented");
                remove_pid_file(&pid_path);
                return Ok(());
            }
        }
    }

    // (datadir + base_datadir already resolved above for PID/log setup)
    tracing::info!("Data directory: {}", datadir.display());

    // Open database with IBD-tuned RocksDB settings:
    //   - 512 MiB shared block cache (vs the 64 MiB default in `ChainDb::open`)
    //   - 64 MiB write buffer per CF, 128 MiB for CF_UTXO
    //   - 4 background jobs (parallel compaction)
    //   - level_compaction_dynamic_level_bytes for better space-amp on a
    //     growing UTXO set
    //
    // `ChainDb::open_optimized` was added in March 2026 (commit e8c9ec2,
    // "rocksdb performance tuning for IBD workloads") but never wired in.
    // The unoptimized defaults (64 MiB block cache vs ~14 GB chainstate at
    // height 367k, 1 background job for compaction) caused IBD pace to
    // decay from ~430 blocks/min → ~30 blocks/min between days 1 and 2
    // of the 2026-05-26 re-IBD: each 2,000-block flush grew from ~2 min
    // (h=170k) to ~87 min (h=367k) as the cache filled with 11M entries
    // and every UTXO lookup missed the 64 MiB cache. Mirrors Bitcoin
    // Core's default of `DEFAULT_KERNEL_CACHE = 450 MiB` in
    // `bitcoin-core/src/kernel/caches.h`.
    let db_path = datadir.join("chainstate");
    let db = Arc::new(ChainDb::open_optimized(&db_path)?);
    let block_store = BlockStore::new(&db);

    // Note: if the DB contains stale block data from a previous run that stored
    // full blocks in CF_BLOCKS, stop the node and run with --cleanup-blocks to
    // reclaim space. Don't run compaction during normal operation as it inflates
    // RSS while processing hundreds of GB of data.

    // Initialize with genesis block
    block_store.init_genesis(&params)?;

    // Load chain state.
    // The stored best_height may be a stale cumulative counter from a bug in
    // earlier versions. Derive the actual height from the block index instead.
    //
    // `best_hash` / `best_height` are intentionally mutable: when an
    // assumeUTXO snapshot is loaded below (`--load-snapshot=<path>`), the
    // snapshot's tip becomes the new chain tip and these values must be
    // re-pointed at it BEFORE we wire `ChainState`, `HeaderSync`, and
    // `BlockDownloader` (otherwise foreground IBD silently runs from
    // genesis and never catches up to the snapshot tip — that was the
    // 2026-05-03 mainnet wedge: tip claimed h=944,183 via RPC while the
    // single foreground chain state was grinding `Connected block ...
    // at height 245,000` from genesis).
    let mut best_hash = block_store.get_best_block_hash()?.unwrap();
    let stored_height = block_store.get_best_height()?.unwrap();

    // Try to find the actual height by looking up the best hash in the height index
    let mut best_height = {
        let mut found = stored_height;
        // Scan backwards from stored height to find the hash
        for h in (0..=std::cmp::min(stored_height, 1_000_000)).rev() {
            if let Ok(Some(hash)) = block_store.get_hash_by_height(h) {
                if hash == best_hash {
                    found = h;
                    break;
                }
            }
            // Only scan 10000 heights to avoid long startup
            if stored_height > h + 10000 {
                break;
            }
        }
        // If stored height is unreasonably high (>1M and hash not found),
        // it's the cumulative counter bug. Reset to 0.
        if found == stored_height && stored_height > 1_000_000 {
            tracing::warn!("Stored height {} looks like cumulative counter, scanning for actual height", stored_height);
            // Binary search to find the highest height with data in the
            // height index. This is O(log n) instead of scanning all heights.
            let mut lo = 0u32;
            let mut hi = 1_000_000u32;
            // First, find the highest height that has any stored hash
            while lo < hi {
                let mid = lo + (hi - lo).div_ceil(2);
                if block_store.get_hash_by_height(mid).ok().flatten().is_some() {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            let highest_stored = lo;
            // Now scan from highest_stored down to find the best_hash
            let mut actual = 0u32;
            if highest_stored > 0 {
                for h in (0..=highest_stored).rev() {
                    if let Ok(Some(hash)) = block_store.get_hash_by_height(h) {
                        if hash == best_hash {
                            actual = h;
                            break;
                        }
                    }
                    // Don't scan more than 10000 heights
                    if highest_stored.saturating_sub(h) > 10000 {
                        break;
                    }
                }
            }
            if actual > 0 {
                tracing::info!("Found actual height: {} (highest stored: {})", actual, highest_stored);
                actual
            } else if highest_stored > 0 {
                // best_hash not found in height index near tip; use highest
                // stored height as best approximation and update best_hash
                tracing::warn!(
                    "Best hash not found in height index, using highest stored height {} as tip",
                    highest_stored
                );
                highest_stored
            } else {
                // No data in height index at all
                tracing::warn!("Could not determine actual height, defaulting to 0");
                0
            }
        } else {
            found
        }
    };

    // Fix the stored height
    if best_height != stored_height {
        tracing::info!("Correcting stored height from {} to {}", stored_height, best_height);
        block_store.set_best_block(&best_hash, best_height)?;
    }

    tracing::info!("Chain tip: {} (height {})", best_hash, best_height);

    // ============================================================
    // BLOCK IMPORT MODE (--import-blocks)
    // ============================================================
    if let Some(ref import_path) = cli.import_blocks {
        tracing::info!("Block import mode enabled: {}", import_path);

        let mut chain_state = ChainState::new(best_hash, best_height, params.clone());
        let mut utxo_view = block_store.utxo_view();

        let imported = if import_path == "-" {
            run_import_from_stdin(&params, &block_store, &mut chain_state, &mut utxo_view, best_height)?
        } else {
            let path = std::path::PathBuf::from(import_path);
            if path.is_dir() {
                run_import_from_blk_files(&path, &params, &block_store, &mut chain_state, &mut utxo_view, best_height)?
            } else {
                anyhow::bail!(
                    "--import-blocks path must be a directory containing blk*.dat files, or \"-\" for stdin"
                );
            }
        };

        // Final UTXO flush
        if utxo_view.cache_len() > 0 {
            let entries = utxo_view.cache_len();
            let mem_mb = utxo_view.estimated_memory() / (1024 * 1024);
            match utxo_view.flush() {
                Ok(()) => tracing::info!("Final UTXO flush: {} entries, ~{} MiB", entries, mem_mb),
                Err(e) => tracing::error!("Final UTXO flush failed: {}", e),
            }
        }

        // Flush chain state
        let _ = block_store.set_best_block(&chain_state.tip_hash(), chain_state.tip_height());
        tracing::info!(
            "Import finished: {} blocks imported, tip at height {}",
            imported, chain_state.tip_height()
        );

        remove_pid_file(&pid_path);
        return Ok(());
    }

    // NOTE: `ChainState` initialization is intentionally deferred until
    // AFTER the optional `--load-snapshot` block below. With assumeUTXO
    // we may bump `best_hash` / `best_height` from genesis to the
    // snapshot tip (e.g. h=944,183 on the 2026-05-03 mainnet snapshot),
    // and `ChainState::new` must observe those bumped values — otherwise
    // the foreground IBD path runs `process_block` from genesis forward
    // forever and never extends past the snapshot tip. See the
    // ASSUMEUTXO TIP ACTIVATION block (a few hundred lines below) for
    // the full rationale.

    // Determine RPC bind address with appropriate port
    let rpc_bind = if cli.rpcbind == "127.0.0.1:8332" {
        // Use default, adjust port based on network
        format!("127.0.0.1:{}", default_rpc_port(params.network_id))
    } else {
        cli.rpcbind.clone()
    };

    // Initialize RPC state.
    //
    // BIP-159 / Core-parity: when `--prune=N` is set, route through
    // `with_prune_config` so `getblockchaininfo` reports `pruned: true`
    // (and `pruneheight` / `prune_target_size`), and so the
    // `pruneblockchain` RPC handler (and the auto-prune trigger in the
    // connect-block loop below) actually fire. `prune_target_bytes`
    // mirrors Core's `nPruneTarget` (bytes, not MiB):
    //   - None / Some(0)   → 0          → pruning disabled
    //   - Some(1)          → 1          → manual-only sentinel
    //   - Some(N) ≥ 550    → N * MiB    → auto-prune target
    //   - Some(2..=549)    → 1          → defensive collapse to manual
    let prune_target_bytes: u64 = match cli.prune {
        None | Some(0) => 0,
        Some(1) => rustoshi_storage::PRUNE_MANUAL_SENTINEL,
        Some(n) if n < 550 => rustoshi_storage::PRUNE_MANUAL_SENTINEL,
        Some(n) => n.saturating_mul(1024 * 1024),
    };
    let mut rpc_state_inner = if prune_target_bytes > 0 {
        rustoshi_rpc::RpcState::with_prune_config(db.clone(), params.clone(), prune_target_bytes)
    } else {
        RpcState::new(db.clone(), params.clone())
    };
    rpc_state_inner.data_dir = Some(datadir.clone());
    rpc_state_inner.init_from_db().map_err(|e| anyhow::anyhow!(e))?;

    // If `--load-snapshot=<path>` was provided, ingest the Core-format UTXO
    // snapshot before any P2P/RPC services come up. Mirrors Core's
    // `-loadsnapshot` initial-block-download fast path. We deliberately do
    // this BEFORE binding the RPC port so external clients can never observe
    // a half-loaded UTXO set.
    if let Some(ref snap_path) = cli.load_snapshot {
        let path = if std::path::Path::new(snap_path).is_absolute() {
            std::path::PathBuf::from(snap_path)
        } else {
            datadir.join(snap_path)
        };
        tracing::info!("Loading UTXO snapshot from {}", path.display());
        let file = std::fs::File::open(&path)
            .map_err(|e| anyhow::anyhow!("open snapshot {}: {}", path.display(), e))?;
        let reader = rustoshi_storage::SnapshotReader::open(file, &params.network_magic)
            .map_err(|e| anyhow::anyhow!("snapshot header parse: {}", e))?;

        let blockhash = reader.metadata().base_blockhash;
        let assume = params
            .assumeutxo_for_blockhash(&blockhash)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "snapshot blockhash {} not in chainparams.assumeutxo_data",
                    blockhash.to_hex()
                )
            })?;
        let coins_total = reader.metadata().coins_count;
        tracing::info!(
            "Snapshot recognized: height={} coins={} expected_hash={}",
            assume.height,
            coins_total,
            assume.hash_serialized.0.to_hex()
        );

        // G8: wire base_height now that assume.height is known; read_coin will
        // reject any coin whose recorded height exceeds the snapshot tip.
        // Mirrors Core validation.cpp::PopulateAndValidateSnapshot L5814-5819.
        let mut reader = reader.with_base_height(assume.height);

        let store = BlockStore::new(&db);
        use sha2::Digest as _;
        // Maintain TWO hash accumulators in parallel, mirroring the RPC
        // `loadtxoutset` path in `crates/rpc/src/server.rs::load_tx_outset`.
        //
        //   1. `legacy_hasher` — pre-Core rustoshi-only TxOutSer-shaped layout
        //      (preserved so historical snapshots produced by old `dumptxoutset`
        //      still validate against legacy-form `assumeutxo` entries).
        //   2. `core_hasher`  — Core's `kernel/coinstats.cpp::TxOutSer`:
        //        outpoint || u32_LE((height<<1)|coinbase) || i64_LE(value)
        //        || CompactSize(script.len()) || script
        //      This is what `AssumeutxoData::hash_serialized` is anchored to in
        //      Bitcoin Core and what every other hashhog impl + the canonical
        //      `tools/compute-snapshot-hash.py` produce.
        //
        // We accept either form so existing pinned hashes keep working AND
        // fresh Core-compatible snapshots load. Without this fan-out the CLI
        // load path would only ever match the legacy form, which is what
        // caused the 2026-05-03 mainnet `loadtxoutset` failure
        // (computed 566fbadc… vs expected 2eaf7172… — the Core-form anchor).
        let mut legacy_hasher = sha2::Sha256::new();
        let mut core_hasher = sha2::Sha256::new();
        let mut loaded: u64 = 0;
        while let Some((outpoint, coin)) = reader
            .read_coin()
            .map_err(|e| anyhow::anyhow!("snapshot body parse: {}", e))?
        {
            // Legacy rustoshi layout (NOT Core-compatible).
            let mut legacy_bytes =
                Vec::with_capacity(32 + 4 + 4 + 1 + 8 + coin.tx_out.script_pubkey.len());
            legacy_bytes.extend_from_slice(outpoint.txid.as_bytes());
            legacy_bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
            legacy_bytes.extend_from_slice(&coin.height.to_le_bytes());
            legacy_bytes.push(if coin.is_coinbase { 1 } else { 0 });
            legacy_bytes.extend_from_slice(&coin.tx_out.value.to_le_bytes());
            legacy_bytes.extend_from_slice(&coin.tx_out.script_pubkey);
            legacy_hasher.update(&legacy_bytes);

            // Core HASH_SERIALIZED layout (kernel/coinstats.cpp::TxOutSer).
            let script_len = coin.tx_out.script_pubkey.len() as u64;
            let mut core_bytes =
                Vec::with_capacity(32 + 4 + 4 + 8 + 9 + coin.tx_out.script_pubkey.len());
            core_bytes.extend_from_slice(outpoint.txid.as_bytes());
            core_bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
            let code: u32 = (coin.height << 1) | (coin.is_coinbase as u32);
            core_bytes.extend_from_slice(&code.to_le_bytes());
            core_bytes.extend_from_slice(&(coin.tx_out.value as i64).to_le_bytes());
            if script_len < 0xFD {
                core_bytes.push(script_len as u8);
            } else if script_len <= 0xFFFF {
                core_bytes.push(0xFD);
                core_bytes.extend_from_slice(&(script_len as u16).to_le_bytes());
            } else if script_len <= 0xFFFF_FFFF {
                core_bytes.push(0xFE);
                core_bytes.extend_from_slice(&(script_len as u32).to_le_bytes());
            } else {
                core_bytes.push(0xFF);
                core_bytes.extend_from_slice(&script_len.to_le_bytes());
            }
            core_bytes.extend_from_slice(&coin.tx_out.script_pubkey);
            core_hasher.update(&core_bytes);

            let entry = coin.to_entry();
            store
                .put_utxo(&outpoint, &entry)
                .map_err(|e| anyhow::anyhow!("put_utxo: {}", e))?;
            loaded += 1;
            if loaded % 1_000_000 == 0 {
                tracing::info!(
                    "snapshot import progress: {} / {} coins ({:.1}%)",
                    loaded,
                    coins_total,
                    (loaded as f64 / coins_total.max(1) as f64) * 100.0
                );
            }
        }
        if loaded != coins_total {
            return Err(anyhow::anyhow!(
                "snapshot coins_count mismatch: header={} body={}",
                coins_total,
                loaded
            ));
        }
        // G8 trailing-bytes guard: reject snapshot files with appended garbage.
        // Mirrors Bitcoin Core validation.cpp::PopulateAndValidateSnapshot L5872-5883:
        //   "Snapshot file has trailing data"
        reader
            .verify_complete()
            .map_err(|e| anyhow::anyhow!("snapshot trailing data check: {}", e))?;
        let finalize_sha256d = |h: sha2::Sha256| -> rustoshi_primitives::Hash256 {
            let first = h.finalize();
            let mut second = sha2::Sha256::new();
            second.update(first);
            let final_hash = second.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&final_hash);
            rustoshi_primitives::Hash256(bytes)
        };
        let computed_legacy = finalize_sha256d(legacy_hasher);
        let computed_core = finalize_sha256d(core_hasher);
        let expected = assume.hash_serialized.0;
        if computed_legacy != expected && computed_core != expected {
            return Err(anyhow::anyhow!(
                "snapshot txoutset_hash mismatch: computed {} (core form; legacy form was {}) expected {}",
                computed_core.to_hex(),
                computed_legacy.to_hex(),
                expected.to_hex()
            ));
        }
        rpc_state_inner.best_hash = blockhash;
        rpc_state_inner.best_height = assume.height;
        if rpc_state_inner.header_height < assume.height {
            rpc_state_inner.header_height = assume.height;
        }
        let _ = rustoshi_storage::write_snapshot_blockhash(&datadir, &blockhash);

        // ============================================================
        // ASSUMEUTXO TIP ACTIVATION
        // ============================================================
        //
        // After the snapshot's UTXO set has been ingested into the DB,
        // we must also (1) jump the chain-state machinery to the snapshot
        // tip and (2) persist that tip so a subsequent restart loads it.
        // Without this block the prior CLI snapshot path was a half-fix:
        // the UTXO set was correct but every other tip-tracking
        // structure (`ChainState`, `HeaderSync`, `BlockDownloader`,
        // persisted `META_BEST_BLOCK_HASH/HEIGHT`) still pointed at
        // genesis, so foreground IBD silently re-validated from height 1
        // upward and never reached the snapshot tip — observed live on
        // mainnet 2026-05-03 (rustoshi RPC reported `blocks=944,183`
        // while the foreground chain state was at h~245,000 and growing
        // at <1k blk/hr from genesis, ~17h after snapshot load).
        //
        // We mirror Core's `validation.cpp::ActivateSnapshot` effects
        // (`Chainstate::m_chain.SetTip`, plus the persisted "best block"
        // pointer in the leveldb meta column).  Background validation of
        // 0..snapshot is NOT performed here — it requires a second
        // chainstate + a separate UTXO column family, which this single-
        // chainstate codebase doesn't have.  The trade-off is that the
        // snapshot is treated as a hard checkpoint until proper dual-
        // chainstate support lands; the operator-facing benefit is that
        // the node is at the snapshot tip immediately and can serve the
        // mainnet tip ~minutes after recovery instead of ~weeks.
        //
        // chain_work for the snapshot tip is set to `minimum_chain_work`
        // from chainparams. We don't have the real cumulative work
        // without scanning history, but the snapshot tip is hardcoded as
        // trustworthy in `assumeutxo_data`, so accepting it as crossing
        // the minimum-work threshold is correct by construction. The
        // first foreground block past the snapshot then accumulates
        // `minimum_chain_work + block_proof(snapshot+1)` and onward.
        let snapshot_chain_work = ChainWork::from_be_bytes(params.minimum_chain_work);

        // The snapshot block's full BlockHeader is unknown at this point
        // (the snapshot file carries the UTXO set, not the block itself).
        // We populate the BlockIndexEntry with the fields we know and
        // zero/placeholder values for the rest. The header sync that
        // follows will fetch the actual headers — including the snapshot
        // block's neighbours — so callers needing the real header can
        // wait for that. RPCs that consult only height/chain_work/n_tx
        // (e.g. `getblockchaininfo`'s difficulty/chainwork fields) work
        // from this entry directly.
        let mut snap_status = BlockStatus::new();
        snap_status.set(BlockStatus::VALID_HEADER);
        snap_status.set(BlockStatus::VALID_TREE);
        snap_status.set(BlockStatus::VALID_TRANSACTIONS);
        snap_status.set(BlockStatus::VALID_CHAIN);
        snap_status.set(BlockStatus::VALID_SCRIPTS);
        snap_status.set(BlockStatus::HAVE_DATA);
        let snap_index_entry = BlockIndexEntry {
            height: assume.height,
            status: snap_status,
            n_tx: 0, // unknown without the block body
            timestamp: 0,
            bits: 0,
            nonce: 0,
            version: 0,
            prev_hash: Hash256::ZERO,
            chain_work: snapshot_chain_work.0,
        };
        if let Err(e) = block_store.put_block_index(&blockhash, &snap_index_entry) {
            return Err(anyhow::anyhow!(
                "snapshot activation: put_block_index failed: {}", e
            ));
        }
        if let Err(e) = block_store.put_height_index(assume.height, &blockhash) {
            return Err(anyhow::anyhow!(
                "snapshot activation: put_height_index failed: {}", e
            ));
        }
        if let Err(e) = block_store.set_best_block(&blockhash, assume.height) {
            return Err(anyhow::anyhow!(
                "snapshot activation: set_best_block failed: {}", e
            ));
        }

        // Re-point the local `best_hash` / `best_height` so the
        // `ChainState`, `HeaderSync`, `BlockDownloader` constructors that
        // run after this block see the snapshot tip rather than genesis.
        best_hash = blockhash;
        best_height = assume.height;

        tracing::info!(
            "Snapshot loaded + activated: {} coins, tip {} at height {} (chain_work=minimum_chain_work; \
             foreground IBD will extend past this point — background validation of 0..{} is NOT \
             performed in this single-chainstate build)",
            loaded,
            blockhash.to_hex(),
            assume.height,
            assume.height,
        );
    }

    // Load persisted fee estimates if available
    let fee_estimates_path = datadir.join("fee_estimates.json");
    let loaded_estimator = FeeEstimator::load(&fee_estimates_path);
    if loaded_estimator.current_height() > 0 {
        tracing::info!("Loaded fee estimates from disk (height {})", loaded_estimator.current_height());
    }
    rpc_state_inner.fee_estimator = loaded_estimator;

    // Load persisted mempool from `mempool.dat` (Core-format, byte-compatible).
    // Failures here are non-fatal: a missing or corrupt file just means we
    // start with an empty mempool, exactly like Bitcoin Core.
    let mempool_dat_path = datadir.join("mempool.dat");
    rpc_state_inner.mempool_dat_path = Some(mempool_dat_path.clone());
    if mempool_dat_path.exists() {
        let db_for_lookup = db.clone();
        let utxo_lookup = move |outpoint: &OutPoint| {
            let store = BlockStore::new(&db_for_lookup);
            store
                .get_utxo(outpoint)
                .ok()
                .flatten()
                .map(|c| rustoshi_consensus::validation::CoinEntry {
                    height: c.height,
                    is_coinbase: c.is_coinbase,
                    value: c.value,
                    script_pubkey: c.script_pubkey,
                })
        };
        match load_mempool(&mut rpc_state_inner.mempool, &mempool_dat_path, &utxo_lookup) {
            Ok(stats) => tracing::info!(
                "Loaded mempool from disk: {} accepted, {} failed, {} expired/skipped, {} unbroadcast (file v{})",
                stats.accepted,
                stats.failed,
                stats.total.saturating_sub(stats.accepted + stats.failed),
                stats.unbroadcast,
                stats.version,
            ),
            Err(e) => tracing::warn!(
                "Failed to load mempool from {}: {}. Continuing anyway.",
                mempool_dat_path.display(),
                e,
            ),
        }
    }

    let rpc_state = Arc::new(RwLock::new(rpc_state_inner));

    // Build the prune coordinator config once. Re-used by every
    // auto-prune trigger in the connect-block loop below. The
    // assumeutxo floor mirrors Core's `m_chainman.GetSnapshotBaseHeight()`
    // — we never delete data above the highest configured snapshot base
    // height, because the background-validation chain may need to
    // rendezvous against it.
    let assumeutxo_floor: u32 = params
        .assumeutxo_data
        .iter()
        .map(|d| d.height)
        .max()
        .unwrap_or(0);
    let prune_cfg = rustoshi_storage::PruneCoordConfig::from_mib(cli.prune, assumeutxo_floor);
    if prune_cfg.is_prune_mode() {
        tracing::info!(
            "Prune mode enabled: target={}B (manual_only={}, auto={}), assumeutxo_floor={}",
            prune_cfg.target_bytes,
            prune_cfg.is_manual_only(),
            prune_cfg.auto_prune_enabled(),
            prune_cfg.assumeutxo_height,
        );
    }

    // Initialize peer state (empty for now, will be updated)
    let peer_state = Arc::new(RwLock::new(PeerState::default()));

    // Generate cookie file for RPC auth (Bitcoin Core pattern).
    // The cookie is always written so that tools like bitcoin-cli can
    // authenticate without needing --rpcuser/--rpcpassword on the CLI.
    let cookie_secret = write_cookie_file(&base_datadir)?;

    // Start RPC server
    let rpc_config = RpcConfig {
        bind_address: rpc_bind.clone(),
        auth_user: cli.rpcuser.clone(),
        auth_password: cli.rpcpassword.clone(),
        cookie_secret: Some(cookie_secret),
        tls_cert: cli.rpc_tls_cert.clone().map(PathBuf::from),
        tls_key: cli.rpc_tls_key.clone().map(PathBuf::from),
    };
    let tls_enabled = rpc_config.tls_cert.is_some() && rpc_config.tls_key.is_some();
    let rpc_handle = start_rpc_server(rpc_config, rpc_state.clone(), peer_state.clone()).await?;
    if tls_enabled {
        tracing::info!("RPC server listening on https://{} (TLS)", rpc_bind);
    } else {
        tracing::info!("RPC server listening on http://{}", rpc_bind);
    }

    // Start unauthenticated REST HTTP server (Bitcoin Core `-rest`).
    // Default off, matching Core's `DEFAULT_REST_ENABLE = false`. When enabled,
    // we bind axum on `--restbind` (or `<rpc_ip>:<rpc_port + 100>` if not set)
    // and serve the same `/rest/*` URI surface as Core. Held in `_rest_handle`
    // so the listener task keeps running for the lifetime of `main`.
    let _rest_handle = if cli.rest {
        let restbind = match cli.restbind.clone() {
            Some(addr) => addr,
            None => {
                // Default: same IP as RPC bind, port+100 (so 8332→8432, 48332→48432)
                let (ip, port) = rpc_bind
                    .rsplit_once(':')
                    .map(|(i, p)| (i.to_string(), p.parse::<u16>().unwrap_or(0)))
                    .unwrap_or_else(|| ("127.0.0.1".to_string(), 8432));
                format!("{}:{}", ip, port.saturating_add(100))
            }
        };
        let rest_cfg = RestConfig {
            bind_address: restbind.clone(),
        };
        match start_rest_server(rest_cfg, rpc_state.clone()).await {
            Ok(handle) => {
                tracing::info!("REST server listening on {}", restbind);
                Some(handle)
            }
            Err(e) => {
                tracing::error!("Failed to start REST server on {}: {}", restbind, e);
                None
            }
        }
    } else {
        None
    };

    // Start Prometheus metrics server
    tokio::spawn(start_metrics_server(
        cli.metrics_port,
        rpc_state.clone(),
        peer_state.clone(),
    ));

    // Load ASMap for AS-based IP bucketing (anti-eclipse) — `-asmap=<file>`.
    //
    // Mirrors Bitcoin Core's `src/init.cpp:1591-1628` asmap loading + hash log.
    // If the path is relative, it is resolved relative to the network datadir.
    // A failed load (bad path, oversized, or sanity-check failure) is non-fatal:
    // the node continues with /16 subnet-based bucketing (the default).
    //
    // MAX_ASMAP_FILESIZE = 8 MiB (enforced inside decode_asmap).
    let asmap_data: Vec<u8> = if let Some(ref asmap_arg) = cli.asmap {
        let asmap_path = {
            let p = PathBuf::from(asmap_arg);
            if p.is_absolute() {
                p
            } else {
                datadir.join(&p) // relative → prepend network datadir
            }
        };
        let data = asmap_mod::decode_asmap(&asmap_path);
        if !data.is_empty() {
            // Log file path + first 8 hex chars of SHA256 — mirrors Core's startup log.
            let version_hex = asmap_mod::asmap_version_hex(&data);
            tracing::info!(
                "Using asmap version {} for IP bucketing ({})",
                version_hex,
                asmap_path.display()
            );
        }
        data
    } else {
        Vec::new()
    };

    // Build NetGroupManager: with asmap if loaded, otherwise random-key only.
    let netgroup_manager = if !asmap_data.is_empty() {
        NetGroupManager::with_asmap(rand::random(), asmap_data)
    } else {
        NetGroupManager::new()
    };

    // W117 BUG-2 proxy wiring: parse -proxy / -onion / -i2psam socket addrs.
    // Bitcoin Core accepts both `host:port` and `[ipv6]:port` forms; we
    // delegate to Rust's `SocketAddr::FromStr` which handles both. A bad
    // value is fatal — better to refuse to start than silently fall back
    // to direct TCP and leak the operator's clearnet IP.
    fn parse_proxy_arg(name: &str, val: Option<&String>) -> Option<std::net::SocketAddr> {
        val.map(|s| {
            s.parse::<std::net::SocketAddr>().unwrap_or_else(|e| {
                tracing::error!("Invalid --{} value '{}': {}", name, s, e);
                std::process::exit(1);
            })
        })
    }
    let tor_proxy = parse_proxy_arg("proxy", cli.proxy.as_ref());
    let onion_proxy = parse_proxy_arg("onion", cli.onion.as_ref());
    let i2p_sam = parse_proxy_arg("i2psam", cli.i2psam.as_ref());
    if tor_proxy.is_some() {
        tracing::info!("Clearnet SOCKS5 proxy: {}", tor_proxy.unwrap());
    }
    if onion_proxy.is_some() {
        tracing::info!("Tor onion SOCKS5 proxy: {}", onion_proxy.unwrap());
    }
    if i2p_sam.is_some() {
        tracing::info!("I2P SAM bridge: {}", i2p_sam.unwrap());
    }
    if cli.cjdnsreachable {
        tracing::info!("CJDNS reachability enabled (fc00::/8 native routing)");
    }

    // FIX-88 W121 G29/G30: parse the `-blockfilterindex` flag and enforce the
    // `-peerblockfilters REQUIRES -blockfilterindex` precondition.
    //
    // Mirrors Core init.cpp:992-999.  Accepted values for
    // `--blockfilterindex`: `0`/`false`/`""` => off; everything else
    // (including `1`, `true`, `basic`) => on.  rustoshi only supports the
    // BIP-158 basic filter type today.
    let blockfilterindex_enabled = match cli.blockfilterindex.to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        _ => true,
    };
    if cli.peerblockfilters && !blockfilterindex_enabled {
        tracing::error!(
            "-peerblockfilters requires -blockfilterindex (matches Core init.cpp:994-996)"
        );
        std::process::exit(1);
    }
    if blockfilterindex_enabled {
        tracing::info!(
            "BIP-157/158 block filter index ENABLED (peerblockfilters={})",
            cli.peerblockfilters
        );
    }

    // Configure peer manager
    let peer_config = PeerManagerConfig {
        max_outbound_full_relay: cli.maxconnections.saturating_sub(2),
        max_outbound_block_relay: 2, // Block-relay-only anchors for eclipse resistance
        // Phase B: maxconnections=0 is a fully offline node — no DNS seeds,
        // no outbound peers — that advances only via submitblock.
        offline: cli.maxconnections == 0,
        listen_port: cli.port.unwrap_or(params.default_port),
        listen: cli.listen,
        peer_bloom_filters: cli.peerbloomfilters,
        // FIX-88 W121 G29/G30 plumb: enable filter index + peer-serving gate.
        // FIX-71 wired `should_advertise_compact_filters` to gate NODE_COMPACT_FILTERS
        // on both flags being true.  FIX-82 set BIP157_P2P_HANDLERS_REGISTERED=true.
        // FIX-88 finally exposes the operator-facing knobs so the gate can flip.
        block_filter_index_enabled: blockfilterindex_enabled,
        peer_block_filters: cli.peerblockfilters,
        // BIP-159: advertise NODE_NETWORK_LIMITED when prune is enabled so peers
        // know not to request blocks below the recent-288 keep window.
        prune_mode: cli.prune.map(|n| n > 0).unwrap_or(false),
        data_dir: datadir.clone(),
        // W117: wire BIP-155 proxy infrastructure into the peer manager.
        tor_proxy,
        onion_proxy,
        i2p_sam,
        cjdns_reachable: cli.cjdnsreachable,
        ..Default::default()
    };
    let mut peer_manager = PeerManager::new_with_netgroup(peer_config, params.clone(), netgroup_manager);
    peer_manager.set_start_height(best_height as i32);

    // ASMap startup health check — log cardinality summary when an asmap is loaded.
    // AddrMan is empty at this point so mapped/unmapped counts are 0; the useful
    // numbers appear in the first periodic health check (after peers accumulate).
    if let Some(stats) = peer_manager.asmap_health_check(5) {
        tracing::info!("{}", stats.summary_line());
    }

    // Connect to specific peer if --connect is set
    if let Some(connect_addr) = &cli.connect {
        let addr: std::net::SocketAddr = connect_addr.parse().expect("Invalid --connect address");
        peer_manager.add_peer(addr);
        tracing::info!("Manual peer added: {}", addr);
    }

    // Take event receiver out of peer manager so we can poll it independently
    // without holding a lock on the peer manager.
    let mut event_rx = peer_manager
        .take_event_receiver()
        .expect("event receiver already taken");

    // Initialize chain state for local block processing.
    //
    // This is intentionally deferred until AFTER the optional snapshot
    // load so that `best_hash` / `best_height` reflect the snapshot tip
    // (when one was loaded) rather than the pre-snapshot persisted tip.
    // See the assumeUTXO activation block above for the full rationale.
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        best_hash,
        best_height,
        params.clone(),
    )));

    // Initialize header sync and block download.
    //
    // For the assumeUTXO case both of these MUST start at the snapshot
    // tip — not at genesis — otherwise:
    //   * `HeaderSync` would build locators rooted at genesis and
    //     re-walk every header from height 1, wasting bandwidth and
    //     never marking the snapshot tip as known.
    //   * `BlockDownloader::new(0, 0)` would treat block 1 as the next
    //     block to validate, re-validating from genesis indefinitely.
    let mut header_sync = HeaderSync::new(params.genesis_hash);
    header_sync.set_best_header(best_height, best_hash);
    let mut block_downloader = BlockDownloader::new(best_height, best_height);

    // Start peer connections (including TCP listener for inbound)
    peer_manager.start().await;

    // Move peer manager into peer_state so RPC handlers can access it
    {
        let mut ps = peer_state.write().await;
        ps.peer_manager = Some(peer_manager);
    }

    tracing::info!("Node started. Waiting for peers...");

    // ---------- SIGHUP HANDLER (log reopen for logrotate) ----------
    // Bitcoin Core reopens the debug log on SIGHUP so logrotate can move
    // the file out from under a running daemon. We do the same: spawn a
    // detached task that listens for SIGHUP and calls reopen() on the
    // ReopenableLogFile we created above.
    {
        use tokio::signal::unix::{signal, SignalKind};
        let log_file_for_hup = log_file.clone();
        match signal(SignalKind::hangup()) {
            Ok(mut hup) => {
                tokio::spawn(async move {
                    while hup.recv().await.is_some() {
                        match log_file_for_hup.reopen() {
                            Ok(()) => tracing::info!(
                                "SIGHUP received: reopened debug log {}",
                                log_file_for_hup.path().display()
                            ),
                            Err(e) => tracing::error!(
                                "SIGHUP: failed to reopen debug log {}: {}",
                                log_file_for_hup.path().display(),
                                e
                            ),
                        }
                    }
                });
            }
            Err(e) => tracing::warn!("Failed to install SIGHUP handler: {}", e),
        }
    }

    // ---------- READINESS SIGNAL (sd_notify-style) ----------
    // Tell our supervisor (systemd / runit / start_mainnet.sh / etc.) that
    // startup completed.  Best-effort: failures here are logged but not
    // fatal — the node is still operating.
    if let Some(fd) = cli.ready_fd {
        match notify_ready(fd) {
            Ok(()) => tracing::info!("Wrote READY=1 to fd {}", fd),
            Err(e) => tracing::warn!("Failed to notify readiness on fd {}: {}", fd, e),
        }
    }

    // UTXO cache for block validation, bounded to 2 GiB
    let mut utxo_view = block_store.utxo_view();

    // Durability bookkeeping for the connect loop.
    //
    // The persisted best-block (tip) pointer must NEVER advance ahead of
    // the durably-flushed UTXO set.  Previously the connect loop wrote the
    // tip pointer eagerly on every block (`set_best_block`) but only
    // flushed the UTXO cache when it hit 2 GiB — so a SIGKILL/OOM/crash in
    // that window left the tip pointing past coins that were never written
    // to disk, permanently wedging the node on restart (mainnet froze at
    // height 948,304 on 2026-05-07 — `missing input` on every block past
    // the un-flushed tip).
    //
    // Fix: `utxo_view.flush_with_tip()` writes the coin mutations and the
    // tip pointer in ONE atomic RocksDB batch (Core's `CCoinsViewDB::
    // BatchWrite` semantics).  We commit that batch on a block boundary
    // either when the cache hits its memory cap OR every
    // `UTXO_FLUSH_INTERVAL_BLOCKS` connected blocks, whichever comes
    // first.  Between commits the persisted tip simply lags the in-memory
    // tip; on restart the gap (persisted_tip+1 .. header_tip) is
    // re-downloaded and re-validated, which is already idempotent.
    //
    // 2000 blocks ≈ a few hundred MB of churn at mainnet sizes — small
    // enough that a crash re-validates only minutes of work, large enough
    // that the per-batch overhead is negligible during IBD.
    const UTXO_FLUSH_INTERVAL_BLOCKS: u32 = 2000;
    // Count of blocks connected since the last durable flush+tip commit.
    let mut blocks_since_flush: u32 = 0;

    // ============================================================
    // MAIN EVENT LOOP
    // ============================================================
    //
    // The event_rx was taken from PeerManager before it was moved into PeerState.
    // We poll event_rx directly here without holding any locks. When we need to
    // interact with the peer manager (send_to_peer, handle_event), we briefly
    // acquire the peer_state lock.
    // In-flight partial blocks keyed by (peer_id, block_hash).
    //
    // When the cmpctblock handler cannot fully reconstruct a block from the
    // mempool it sends getblocktxn to the peer and stores the PartiallyDownloadedBlock
    // here.  The blocktxn handler looks the entry up by (peer_id, block_hash),
    // calls fill_block() with the provided transactions, and submits the
    // completed block to the chain via block_downloader.block_received().
    //
    // One entry per (peer, block) is sufficient because Bitcoin Core only allows
    // one compact-block in flight per peer at a time (net_processing.cpp:5028).
    // We hold at most one entry per peer; the map is keyed by (peer_id_u64,
    // block_hash) so multiple peers can each have one in-flight block.
    let mut inflight_partial_blocks: std::collections::HashMap<
        (u64, rustoshi_primitives::Hash256),
        rustoshi_network::PartiallyDownloadedBlock,
    > = std::collections::HashMap::new();

    let mut block_retry_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    block_retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Fast validation timer — fires every 100ms to process buffered blocks.
    // This ensures block validation is never starved by a stream of peer
    // messages in the select loop.  The 10s retry timer handles download
    // retries and timeouts; this timer handles validation throughput.
    let mut validation_interval = tokio::time::interval(std::time::Duration::from_millis(100));
    validation_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // P2P maintenance tick — fires every 45s (Bitcoin Core's
    // EXTRA_PEER_CHECK_INTERVAL).  Drives stalled-peer eviction,
    // outbound-fill top-up, and re-issues `getheaders` if header sync
    // got stuck on a half-dead peer.  Without this tick the
    // peer_manager's StalePeerDetector + fill_outbound_connections
    // are never called outside the initial start() / Disconnected
    // events, so a peer that completes the version handshake and
    // then goes silent at the TCP layer wedges sync indefinitely
    // (observed 2026-05-07: 6+ hour freeze with one zombie peer).
    let mut maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(45));
    maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // ASMap health-check tick — fires every 3600 s (1 hour).
    // Logs ASN diversity stats (total entries, mapped/unmapped, unique ASNs,
    // top-N ASNs) to aid operators in detecting stale or low-coverage asmap
    // files.  No-ops when no asmap is loaded.
    let mut asmap_health_interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    // Skip is correct: if the node is behind, we do not need to catch up on
    // health-check ticks — just fire on the next natural 3600 s boundary.
    asmap_health_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate first tick so the first real fire is at t+3600 s
    // (the startup log above already covers t=0).
    asmap_health_interval.tick().await;

    loop {
        tokio::select! {
            // Fast validation tick — process buffered blocks frequently.
            // Checked with equal priority to peer events via random select.
            // Even if peer events dominate, this will statistically fire
            // ~50% of the time when both are ready.
            _ = validation_interval.tick() => {
                const MAX_BLOCKS_VALIDATE: usize = 8;
                let mut blocks_validated = 0usize;

                while blocks_validated < MAX_BLOCKS_VALIDATE {
                    let block = match block_downloader.next_block_to_validate() {
                        Some(b) => b,
                        None => break,
                    };
                    let block_hash = block.block_hash();
                    let height = block_downloader.validated_tip_height();

                    if let Err(e) = block_store.put_header(&block_hash, &block.header) {
                        tracing::error!("Failed to store header {}: {}", block_hash, e);
                    }

                    // Validate the block. If validation fails we MUST NOT persist
                    // the block index entry, advance set_best_block, or update
                    // RPC state — doing so would corrupt the persisted tip
                    // pointer to reference an unconnected block, and on the
                    // next restart ChainState::new would load that hash as
                    // tip even though no UTXO updates were applied. That
                    // bug previously broke rustoshi mainnet for ~21 days
                    // (first failure h=944601 on 2026-04-11; debug.log
                    // shows zero "Connected block" lines despite tip
                    // hash advancing across every restart).
                    let connected_undo: Option<rustoshi_consensus::validation::UndoData> = {
                        let mut cs = chain_state.write().await;
                        // BIP-113: compute parent MTP for `is_final_tx`'s
                        // `lock_time_cutoff`.  Without this, every tx with
                        // a timestamp-based `nLockTime > 0` is rejected
                        // post-CSV (mainnet h>=419,328) — wedged rustoshi's
                        // post-snapshot IBD at h=944,184 on 2026-05-02.
                        //
                        // `mtp_for_connect` (not `compute_mtp_via_store`)
                        // so the FIRST block past an assumeUTXO snapshot
                        // base — whose parent header was never downloaded
                        // — uses the trusted `base_mtp` chainparams
                        // constant instead of collapsing the cutoff to 0
                        // and rejecting every time-locked tx as
                        // `bad-txns-nonfinal` (mainnet wedge 2026-05-20:
                        // block 944,184).
                        let prev_block_mtp =
                            mtp_for_connect(&block_store, &cs.tip_hash(), &params)
                                .unwrap_or(0);
                        // f_requested=true: blocks from the IBD block downloader
                        // are actively requested via getdata — no fTooFarAhead guard.
                        match cs.process_block(&block, &mut utxo_view, prev_block_mtp, true, rustoshi_consensus::current_time_secs()) {
                            Ok((undo, _fees)) => Some(undo),
                            Err(e) => {
                                tracing::warn!(
                                    "Block validation failed at height {}: {}",
                                    height, e
                                );
                                None
                            }
                        }
                    };

                    if let Some(undo) = connected_undo {
                        // Store block index entry so getblockheader returns height/nTx/chainwork.
                        {
                            let prev_work = if block.header.prev_block_hash != Hash256::ZERO {
                                block_store
                                    .get_block_index(&block.header.prev_block_hash)
                                    .ok()
                                    .flatten()
                                    .map(|e| ChainWork::from_be_bytes(e.chain_work))
                                    .unwrap_or(ChainWork::ZERO)
                            } else {
                                ChainWork::ZERO
                            };
                            let this_work = prev_work.saturating_add(&get_block_proof(block.header.bits));
                            let mut status = BlockStatus::new();
                            status.set(BlockStatus::VALID_SCRIPTS);
                            status.set(BlockStatus::HAVE_DATA);
                            let idx_entry = BlockIndexEntry {
                                height,
                                status,
                                n_tx: block.transactions.len() as u32,
                                timestamp: block.header.timestamp,
                                bits: block.header.bits,
                                nonce: block.header.nonce,
                                version: block.header.version,
                                prev_hash: block.header.prev_block_hash,
                                chain_work: this_work.0,
                            };
                            if let Err(e) = block_store.put_block_index(&block_hash, &idx_entry) {
                                tracing::error!("Failed to store block index at height {}: {}", height, e);
                            }
                        }

                        // Pattern C0 (txindex-on-connect): persist tx_index for
                        // every tx in this block so getrawtransaction works
                        // post-IBD. See `write_tx_index_entries`.
                        write_tx_index_entries(&block_store, &block, block_hash);

                        // BIP-157/158 block filter index — FIX-69 W121 BUG-16.
                        // See `write_block_filter_index` for the Core reference.
                        write_block_filter_index(&block_store, &block, height, &undo);

                        // Durability: advance the persisted tip pointer ONLY
                        // as part of an atomic UTXO flush, never as a separate
                        // eager write.  Commit when the cache is full OR every
                        // UTXO_FLUSH_INTERVAL_BLOCKS blocks. See the
                        // `flush_with_tip` doc comment and `blocks_since_flush`
                        // declaration for the wedge this prevents (mainnet
                        // froze at h=948,304 on 2026-05-07).
                        blocks_since_flush += 1;
                        if utxo_view.needs_flush()
                            || blocks_since_flush >= UTXO_FLUSH_INTERVAL_BLOCKS
                        {
                            let cache_mb = utxo_view.estimated_memory() / (1024 * 1024);
                            let entries = utxo_view.cache_len();
                            match utxo_view.flush_with_tip(&block_hash, height) {
                                Ok(()) => {
                                    tracing::info!(
                                        "UTXO+tip flushed atomically: {} entries, ~{} MiB at height {}",
                                        entries, cache_mb, height
                                    );
                                    blocks_since_flush = 0;
                                }
                                Err(e) => {
                                    // Do NOT reset blocks_since_flush — retry
                                    // on the next block so a transient I/O
                                    // error cannot strand the tip behind.
                                    tracing::error!("UTXO+tip atomic flush failed: {}", e);
                                }
                            }
                        }

                        {
                            let mut rpc = rpc_state.write().await;
                            if height > rpc.best_height {
                                rpc.best_height = height;
                                rpc.best_hash = block_hash;
                            }

                            // Wire fee estimator: notify it of the newly connected
                            // block so confirmed_within buckets are populated.
                            // Skips coinbase (index 0) to match Core's
                            // processTransaction filter for coinbase txs.
                            let confirmed_txids: Vec<Hash256> = block
                                .transactions
                                .iter()
                                .skip(1)
                                .map(|tx| tx.txid())
                                .collect();
                            rpc.fee_estimator.process_block(height, &confirmed_txids);
                        }

                        // Auto-prune trigger (BIP-159 / Core parity).
                        // Only fires under `-prune=N` size mode (NOT under
                        // `-prune=1` manual-only); throttled to once per
                        // 100 connected blocks to avoid re-walking the
                        // index every block during IBD. See
                        // `bitcoin-core/src/validation.cpp::FlushStateToDisk`'s
                        // `fFlushForPrune` cadence.
                        if prune_cfg.auto_prune_enabled()
                            && (height.is_multiple_of(100) || height == prune_cfg.assumeutxo_height)
                        {
                            if let Err(e) = rustoshi_storage::auto_prune(&block_store, &prune_cfg, height) {
                                tracing::warn!("auto-prune failed at height {}: {}", height, e);
                            }
                        }

                        if height.is_multiple_of(10000) {
                            tracing::info!(
                                "Synced to height {} ({:.1}%) cache={} MiB",
                                height,
                                block_downloader.progress(),
                                utxo_view.estimated_memory() / (1024 * 1024),
                            );
                        }
                    }

                    blocks_validated += 1;
                    tokio::task::yield_now().await;
                }

                // Request more blocks if validation freed up received_blocks
                if blocks_validated > 0 {
                    let requests = block_downloader.assign_requests();
                    if !requests.is_empty() {
                        let ps = peer_state.read().await;
                        if let Some(ref pm) = ps.peer_manager {
                            for (peer, msg) in requests {
                                pm.send_to_peer(peer, msg).await;
                            }
                        }
                    }
                }
            }

            // Handle peer events (polled without holding any locks)
            event = event_rx.recv() => {
                match event {
                    Some(PeerEvent::Connected(peer_id, info, stats)) => {
                        // Register inbound peer handle in PeerManager
                        {
                            let mut ps = peer_state.write().await;
                            if let Some(ref mut pm) = ps.peer_manager {
                                pm.handle_event(PeerEvent::Connected(
                                    peer_id,
                                    info.clone(),
                                    std::sync::Arc::clone(&stats),
                                )).await;
                            }
                        }

                        tracing::info!(
                            "Peer {} connected: {} ({})",
                            peer_id.0, info.addr, info.user_agent
                        );
                        header_sync.register_peer(peer_id, info.start_height);
                        block_downloader.add_peer(peer_id);

                        // Start header sync if we need to catch up
                        match header_sync.start_sync(|h| {
                            block_store.get_hash_by_height(h).ok().flatten()
                        }) {
                            Some((target_peer, msg)) => {
                                tracing::info!("Sending getheaders to peer {}", target_peer.0);
                                let ps = peer_state.read().await;
                                if let Some(ref pm) = ps.peer_manager {
                                    let ok = pm.send_to_peer(target_peer, msg).await;
                                    tracing::info!("getheaders send result: {}", ok);
                                }
                            }
                            None => {
                                tracing::info!("No sync peer found (our height={}, peers={})",
                                    header_sync.best_header_height(),
                                    header_sync.peer_count());
                            }
                        }
                    }

                    Some(PeerEvent::Message(peer_id, msg)) => {
                        match msg {
                            NetworkMessage::Headers(headers) => {
                                let header_count = headers.len();
                                let current_header_height = header_sync.best_header_height();
                                // BIP-113 / Core ContextualCheckBlockHeader:
                                // header timestamp must NOT exceed wall-clock + 7200s.
                                // Captured once per Headers message so the check runs
                                // against a stable wall-clock reference for the whole
                                // batch.
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                let need_more = header_sync.process_headers(
                                    peer_id,
                                    headers,
                                    &mut |header, height| {
                                        // Canonical header-validation gates: 7200-future
                                        // (gate 3), BIP-94 timewarp (gate 2, mainnet no-op),
                                        // outdated-version BIP-34/65/66 (gate 4). Routes
                                        // through contextual_check_block_header — the same
                                        // helper now wired into chain_state::process_block
                                        // (rustoshi commit 630166f). Closes the header-side
                                        // half of G7/BUG-11. Until 2026-05-25 the
                                        // future-time check was inlined here as a workaround
                                        // for "audit Bug 0a" because the helper was dead
                                        // code; now it's not.
                                        //
                                        // We use StubChainContext (MTP=0) so gate 1 is a
                                        // no-op here; the REAL MTP enforcement stays inline
                                        // below where we have block_store access to walk
                                        // ancestors via compute_mtp_via_store. prev_entry
                                        // fields are placeholders — only `timestamp` is
                                        // read by gate 2, and only at BIP-94 retarget
                                        // boundaries (mainnet-disabled; on testnet4/regtest
                                        // the 0 placeholder can't spuriously fire since
                                        // block_time < (0 - MAX_TIMEWARP=600) is always
                                        // false for any real block).
                                        let prev_entry = rustoshi_consensus::BlockIndexEntry {
                                            height: 0,
                                            timestamp: 0,
                                            bits: 0,
                                            prev_hash: rustoshi_primitives::Hash256::ZERO,
                                            chain_work: [0u8; 32],
                                        };
                                        rustoshi_consensus::contextual_check_block_header(
                                            header,
                                            height,
                                            &prev_entry,
                                            &rustoshi_consensus::StubChainContext,
                                            &params,
                                            now_secs,
                                        )
                                        .map_err(|e| format!("{:?}", e))?;
                                        // BIP-113 MTP check: reject headers whose timestamp
                                        // is <= the median-time-past of the previous 11
                                        // blocks. Walks ancestors via block_store.
                                        // Skipped for the very first connection (genesis-
                                        // adjacent) where MTP=0 by convention.
                                        if let Some(mtp) = compute_mtp_via_store(
                                            &block_store,
                                            &header.prev_block_hash,
                                        ) {
                                            if header.timestamp <= mtp {
                                                return Err(format!(
                                                    "time-too-old: header timestamp {} <= MTP {}",
                                                    header.timestamp, mtp
                                                ));
                                            }
                                        }
                                        block_store
                                            .put_header(&header.block_hash(), header)
                                            .map_err(|e| e.to_string())?;
                                        block_store
                                            .put_height_index(height, &header.block_hash())
                                            .map_err(|e| e.to_string())?;
                                        Ok(())
                                    },
                                    &|hash| {
                                        // Walk back through the height index to find this hash.
                                        // This is the equivalent of Bitcoin Core's FindForkInGlobalIndex.
                                        for h in (0..=current_header_height).rev() {
                                            if let Ok(Some(stored_hash)) = block_store.get_hash_by_height(h) {
                                                if stored_hash == *hash {
                                                    return Some(h);
                                                }
                                            }
                                        }
                                        None
                                    },
                                );

                                match need_more {
                                    Ok(true) => {
                                        // Update RPC header height during ongoing sync
                                        {
                                            let hh = header_sync.best_header_height();
                                            let mut rpc = rpc_state.write().await;
                                            if hh > rpc.header_height {
                                                rpc.header_height = hh;
                                            }
                                        }
                                        // Request more headers
                                        if let Some((target, msg)) = header_sync.start_sync(|h| {
                                            block_store.get_hash_by_height(h).ok().flatten()
                                        }) {
                                            let ps = peer_state.read().await;
                                            if let Some(ref pm) = ps.peer_manager {
                                                pm.send_to_peer(target, msg).await;
                                            }
                                        }
                                    }
                                    Ok(false) => {
                                        let new_best = header_sync.best_header_height();
                                        if header_count > 0 {
                                            tracing::info!(
                                                "Headers caught up to height {}",
                                                new_best
                                            );
                                        }
                                        // Update RPC header height so getblockchaininfo
                                        // reports the correct value.
                                        {
                                            let mut rpc = rpc_state.write().await;
                                            if new_best > rpc.header_height {
                                                rpc.header_height = new_best;
                                            }
                                        }
                                        // Begin block download for blocks above our actual
                                        // validated chainstate tip.
                                        //
                                        // GAP-FILL: floor `old_best` at `chain_state.tip_height()`
                                        // — NOT at `block_downloader.best_header_height()` /
                                        // `validated_tip_height()`.  Both downloader counters
                                        // advance unconditionally:
                                        //   * `validated_tip_height` is incremented inside
                                        //     `next_block_to_validate()` even when the
                                        //     subsequent `process_block` fails.
                                        //   * `best_header_height` is bumped to `new_best`
                                        //     here (set_best_header_height a few lines down)
                                        //     regardless of whether we actually download
                                        //     and validate those blocks.
                                        // If we used either of those as the floor, a single
                                        // failed block would leave a permanent gap: the
                                        // failure removes the block from
                                        // pending_hashes/received_blocks, the downloader
                                        // counters keep advancing, and every subsequent
                                        // header arrival enqueues only the new tip's height
                                        // (e.g. just block N+3580 when we're stuck at N).
                                        // The next block then fails with "previous block
                                        // not found" because its parent never gets
                                        // re-requested, and the node wedges.
                                        //
                                        // Trusting `chain_state.tip_height()` ensures the
                                        // entire gap (chainstate_tip+1 .. header_tip) is
                                        // re-enqueued on every header arrival.  The
                                        // BlockDownloader's own per-hash dedup
                                        // (in_flight / received_blocks / pending_set)
                                        // prevents duplicate downloads of blocks already
                                        // in the pipeline, so this is cheap in the healthy
                                        // case where chainstate is keeping up.
                                        //
                                        // Live-reproduced 2026-05-03: snapshot loaded at
                                        // h=944,183, headers caught up to h=947,763, but
                                        // block 944,184 failed validation.  Subsequent
                                        // header arrivals (947,761, 947,762, 947,763) each
                                        // enqueued only their own height, the gap
                                        // 944,184..947,760 was never re-requested, and
                                        // every downloaded block failed with
                                        // "previous block not found".
                                        let chainstate_tip = {
                                            let cs = chain_state.read().await;
                                            cs.tip_height()
                                        };
                                        let old_best = chainstate_tip;
                                        block_downloader.set_best_header_height(new_best);

                                        // Receiving headers means peers are responsive —
                                        // clear any stall flags so they can serve blocks.
                                        block_downloader.clear_stalling();

                                        // Enqueue blocks we need to download.
                                        //
                                        // IMPORTANT: We chunk the enumeration into batches of
                                        // 1000 heights with yield points between each batch.
                                        // Previously this was a single loop over all heights
                                        // (e.g. 131K iterations on mainnet) doing synchronous
                                        // RocksDB reads, which blocked the tokio event loop for
                                        // minutes.  During that time no peer events, timers, or
                                        // retry logic could fire — peers disconnected, and the
                                        // node appeared permanently stuck at the tip with
                                        // "0 getdata requests" after the initial header sync.
                                        if new_best > old_best {
                                            const ENQUEUE_CHUNK_SIZE: u32 = 1000;
                                            let total = new_best - old_best;
                                            tracing::info!(
                                                "Enqueueing {} blocks for download (heights {}..={}), chunked by {}",
                                                total, old_best + 1, new_best, ENQUEUE_CHUNK_SIZE
                                            );

                                            let mut chunk_start = old_best + 1;
                                            while chunk_start <= new_best {
                                                let chunk_end = std::cmp::min(
                                                    chunk_start + ENQUEUE_CHUNK_SIZE - 1,
                                                    new_best,
                                                );
                                                let mut blocks_to_download = Vec::new();
                                                for h in chunk_start..=chunk_end {
                                                    if let Ok(Some(hash)) = block_store.get_hash_by_height(h) {
                                                        blocks_to_download.push((hash, h));
                                                    }
                                                }
                                                if !blocks_to_download.is_empty() {
                                                    block_downloader.enqueue_blocks(blocks_to_download);
                                                }

                                                // Send getdata requests for this chunk so
                                                // downloads start immediately while we
                                                // continue enqueuing.
                                                let requests = block_downloader.assign_requests();
                                                if !requests.is_empty() {
                                                    let ps = peer_state.read().await;
                                                    if let Some(ref pm) = ps.peer_manager {
                                                        for (peer, msg) in &requests {
                                                            pm.send_to_peer(*peer, msg.clone()).await;
                                                        }
                                                    }
                                                }

                                                chunk_start = chunk_end + 1;

                                                // Yield to the tokio executor between chunks
                                                // so peer events, timers, and other tasks can
                                                // make progress.
                                                tokio::task::yield_now().await;
                                            }

                                            tracing::info!("Block download: enqueue complete, queue_len={}",
                                                block_downloader.download_queue_len());
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("Header sync error from peer {}: {}", peer_id.0, e);

                                        // Classify the error: unconnecting-headers vs
                                        // genuinely-invalid-content (PoW, bad version, etc.).
                                        let is_unconnecting =
                                            e.contains("not connected") || e.contains("not in our chain");

                                        if is_unconnecting {
                                            // Core (net_processing.cpp::ProcessHeadersMessage)
                                            // tolerates up to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10
                                            // unconnecting-headers messages from a single peer
                                            // before disconnecting.  Until that bound is reached
                                            // we send `getheaders` to try to find a common
                                            // ancestor instead of banning.  This avoids tripping
                                            // honest peers caught in a transient reorg.
                                            let exceeded = header_sync.note_unconnecting_headers(peer_id);
                                            if exceeded {
                                                tracing::warn!(
                                                    "Peer {} exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS=10, disconnecting",
                                                    peer_id.0
                                                );
                                                let mut ps = peer_state.write().await;
                                                if let Some(ref mut pm) = ps.peer_manager {
                                                    pm.misbehaving(peer_id, MisbehaviorReason::HeadersDontConnect).await;
                                                }
                                            } else {
                                                // Re-issue getheaders with a full block locator
                                                // so the peer can find our fork point
                                                // (Core's FindForkInGlobalIndex behavior).
                                                tracing::info!(
                                                    "Re-requesting headers from peer {} with block locator to find fork point",
                                                    peer_id.0
                                                );
                                                if let Some((target, msg)) = header_sync.start_sync(|h| {
                                                    block_store.get_hash_by_height(h).ok().flatten()
                                                }) {
                                                    let ps = peer_state.read().await;
                                                    if let Some(ref pm) = ps.peer_manager {
                                                        pm.send_to_peer(target, msg).await;
                                                    }
                                                }
                                            }
                                        } else {
                                            // Any other header error (bad PoW, bad version,
                                            // timestamp in future/past, too many headers, etc.)
                                            // is genuinely invalid content — ban immediately.
                                            // Mirrors Bitcoin Core MaybePunishNodeForBlock:
                                            //   BLOCK_INVALID_HEADER → Misbehaving(peer, "bad-header")
                                            // W99 G17: previously only PoW errors reached this
                                            // branch; all other invalid-header errors were
                                            // silently ignored (no Misbehaving call).
                                            let mut ps = peer_state.write().await;
                                            if let Some(ref mut pm) = ps.peer_manager {
                                                pm.misbehaving(peer_id, MisbehaviorReason::InvalidBlockHeader).await;
                                            }
                                        }
                                    }
                                }
                            }

                            NetworkMessage::Block(block) => {
                                block_downloader.block_received(peer_id, block);

                                // Process blocks in order, but cap the number validated per
                                // event-loop iteration to prevent starving timers and peer I/O.
                                // Without this cap, the while-let loop runs synchronous RocksDB
                                // I/O (put_header, UTXO lookups, flush) inside the tokio runtime,
                                // blocking the entire executor.  The 10-second retry timer and
                                // peer event processing cannot fire until validation yields.
                                //
                                // At mainnet heights (800k+), each block has hundreds of txns
                                // with UTXO lookups that hit RocksDB synchronously.  Processing
                                // even a handful of blocks can block for seconds, causing the
                                // observed deadlock: no timer fires, no new getdata is sent,
                                // and the node appears hung.
                                const MAX_BLOCKS_PER_ITERATION: usize = 8;
                                let mut blocks_validated = 0usize;

                                while blocks_validated < MAX_BLOCKS_PER_ITERATION {
                                    let block = match block_downloader.next_block_to_validate() {
                                        Some(b) => b,
                                        None => break,
                                    };
                                    let block_hash = block.block_hash();
                                    let height = block_downloader.validated_tip_height();

                                    // Skip storing full blocks in RocksDB during IBD —
                                    // they're enormous (~500GB for mainnet) and inflate
                                    // RocksDB memory. Only store headers and UTXO data.
                                    // Blocks can be retrieved from peers if needed.
                                    if let Err(e) = block_store.put_header(&block_hash, &block.header) {
                                        tracing::error!("Failed to store header {}: {}", block_hash, e);
                                    }

                                    // Validate block and update UTXO set. If validation
                                    // fails we MUST NOT persist the block index entry,
                                    // advance set_best_block, or update RPC state — see
                                    // the matching site in the validation_interval branch
                                    // above for the full rationale.
                                    let connected_undo: Option<rustoshi_consensus::validation::UndoData> = {
                                        let mut cs = chain_state.write().await;
                                        // BIP-113: compute parent MTP for
                                        // `is_final_tx`'s `lock_time_cutoff`.
                                        // See validation_interval branch
                                        // above for full rationale, including
                                        // the assumeUTXO snapshot-base case
                                        // that `mtp_for_connect` handles.
                                        let prev_block_mtp =
                                            mtp_for_connect(&block_store, &cs.tip_hash(), &params)
                                                .unwrap_or(0);
                                        // f_requested=true: blocks from the P2P block downloader
                                        // are actively requested via getdata — no fTooFarAhead guard.
                                        match cs.process_block(&block, &mut utxo_view, prev_block_mtp, true, rustoshi_consensus::current_time_secs()) {
                                            Ok((undo, _fees)) => Some(undo),
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Block validation failed at height {}: {}",
                                                    height, e
                                                );
                                                // DoS: peer sent us an invalid block.
                                                // Distinguish BLOCK_MUTATED (merkle/witness
                                                // corruption) from generic invalid-block,
                                                // matching Bitcoin Core MaybePunishNodeForBlock:
                                                //   BLOCK_MUTATED → Misbehaving(peer, "mutated-block")
                                                //   other failures → Misbehaving(peer, "bad-blk-*")
                                                // Both are 100-pt instant bans.  W99 G16.
                                                let reason = match e {
                                                    ValidationError::BadMerkleRoot
                                                    | ValidationError::BadWitnessCommitment
                                                    | ValidationError::BadWitnessNonceSize
                                                    | ValidationError::UnexpectedWitness => {
                                                        MisbehaviorReason::MutatedBlock
                                                    }
                                                    _ => MisbehaviorReason::InvalidBlock,
                                                };
                                                let mut ps = peer_state.write().await;
                                                if let Some(ref mut pm) = ps.peer_manager {
                                                    pm.misbehaving(peer_id, reason).await;
                                                }
                                                None
                                            }
                                        }
                                    };

                                    if let Some(undo) = connected_undo {
                                        // Store block index entry so getblockheader returns height/nTx/chainwork.
                                        {
                                            let prev_work = if block.header.prev_block_hash != Hash256::ZERO {
                                                block_store
                                                    .get_block_index(&block.header.prev_block_hash)
                                                    .ok()
                                                    .flatten()
                                                    .map(|e| ChainWork::from_be_bytes(e.chain_work))
                                                    .unwrap_or(ChainWork::ZERO)
                                            } else {
                                                ChainWork::ZERO
                                            };
                                            let this_work = prev_work.saturating_add(&get_block_proof(block.header.bits));
                                            let mut status = BlockStatus::new();
                                            status.set(BlockStatus::VALID_SCRIPTS);
                                            status.set(BlockStatus::HAVE_DATA);
                                            let idx_entry = BlockIndexEntry {
                                                height,
                                                status,
                                                n_tx: block.transactions.len() as u32,
                                                timestamp: block.header.timestamp,
                                                bits: block.header.bits,
                                                nonce: block.header.nonce,
                                                version: block.header.version,
                                                prev_hash: block.header.prev_block_hash,
                                                chain_work: this_work.0,
                                            };
                                            if let Err(e) = block_store.put_block_index(&block_hash, &idx_entry) {
                                                tracing::error!("Failed to store block index at height {}: {}", height, e);
                                            }
                                        }

                                        // Pattern C0 (txindex-on-connect): persist tx_index for
                                        // every tx in this block so getrawtransaction works
                                        // post-IBD. See `write_tx_index_entries`.
                                        write_tx_index_entries(&block_store, &block, block_hash);

                                        // BIP-157/158 block filter index — FIX-69 W121 BUG-16.
                                        // See `write_block_filter_index` for the Core reference.
                                        write_block_filter_index(&block_store, &block, height, &undo);

                                        // Durability: advance the persisted tip
                                        // pointer ONLY as part of an atomic UTXO
                                        // flush, never as a separate eager write.
                                        // Commit when the cache is full OR every
                                        // UTXO_FLUSH_INTERVAL_BLOCKS blocks. See
                                        // the `flush_with_tip` doc comment for the
                                        // wedge this prevents (mainnet froze at
                                        // h=948,304 on 2026-05-07 when the eager
                                        // tip write outran the lazy flush).
                                        blocks_since_flush += 1;
                                        if utxo_view.needs_flush()
                                            || blocks_since_flush >= UTXO_FLUSH_INTERVAL_BLOCKS
                                        {
                                            let cache_mb = utxo_view.estimated_memory() / (1024 * 1024);
                                            let entries = utxo_view.cache_len();
                                            match utxo_view.flush_with_tip(&block_hash, height) {
                                                Ok(()) => {
                                                    tracing::info!(
                                                        "UTXO+tip flushed atomically: {} entries, ~{} MiB at height {}",
                                                        entries, cache_mb, height
                                                    );
                                                    blocks_since_flush = 0;
                                                }
                                                Err(e) => {
                                                    // Do NOT reset the counter —
                                                    // retry on the next block.
                                                    tracing::error!("UTXO+tip atomic flush failed: {}", e);
                                                }
                                            }
                                        }

                                        // Update RPC state and clean mempool
                                        {
                                            let mut rpc = rpc_state.write().await;
                                            if height > rpc.best_height {
                                                rpc.best_height = height;
                                                rpc.best_hash = block_hash;
                                            }

                                            // Remove confirmed transactions from mempool
                                            let block_txids: Vec<Hash256> = block
                                                .transactions
                                                .iter()
                                                .map(|tx| tx.txid())
                                                .collect();
                                            let block_spent: Vec<OutPoint> = block
                                                .transactions
                                                .iter()
                                                .flat_map(|tx| {
                                                    tx.inputs.iter().map(|i| i.previous_output.clone())
                                                })
                                                .collect();
                                            rpc.mempool
                                                .remove_for_block(&block_txids, &block_spent);

                                            // Wire fee estimator: notify it of the confirmed
                                            // block. Skip coinbase (index 0) to match Core's
                                            // processTransaction filter.
                                            let non_cb_txids: Vec<Hash256> = block
                                                .transactions
                                                .iter()
                                                .skip(1)
                                                .map(|tx| tx.txid())
                                                .collect();
                                            rpc.fee_estimator
                                                .process_block(height, &non_cb_txids);

                                            // Same housekeeping for the
                                            // orphan tx pool: drop orphans
                                            // that are now invalid (parent
                                            // outpoint spent) or that the
                                            // block already includes.
                                            rpc.orphanage
                                                .erase_for_block(&block_txids, &block_spent);

                                            // Clear recently-rejected filter -- rejection reasons
                                            // may no longer apply after a new block
                                            rpc.recently_rejected.clear();
                                        }

                                        // Auto-prune trigger (BIP-159 / Core parity).
                                        // Mirrors the trigger in the foreground IBD
                                        // path above. Throttled to 1-in-100 connected
                                        // blocks to avoid re-walking the index every
                                        // block.
                                        if prune_cfg.auto_prune_enabled()
                                            && (height.is_multiple_of(100) || height == prune_cfg.assumeutxo_height)
                                        {
                                            if let Err(e) = rustoshi_storage::auto_prune(&block_store, &prune_cfg, height) {
                                                tracing::warn!("auto-prune failed at height {}: {}", height, e);
                                            }
                                        }

                                        // Progress logging
                                        if height.is_multiple_of(10000) {
                                            tracing::info!(
                                                "Synced to height {} ({:.1}%) cache={} MiB",
                                                height,
                                                block_downloader.progress(),
                                                utxo_view.estimated_memory() / (1024 * 1024),
                                            );
                                        }
                                    }

                                    blocks_validated += 1;

                                    // Yield to the tokio executor between blocks so that
                                    // timers, peer messages, and other tasks can make
                                    // progress.  This is critical because the RocksDB
                                    // calls above are synchronous and block the runtime.
                                    tokio::task::yield_now().await;
                                }

                                // Request more blocks
                                let requests = block_downloader.assign_requests();
                                if !requests.is_empty() {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        for (peer, msg) in requests {
                                            pm.send_to_peer(peer, msg).await;
                                        }
                                    }
                                }
                            }

                            NetworkMessage::Inv(inv_items) => {
                                // Handle new block/transaction announcements
                                let mut tx_requests = Vec::new();
                                for item in &inv_items {
                                    match item.inv_type {
                                        InvType::MsgBlock | InvType::MsgWitnessBlock => {
                                            // New block announced -- request headers
                                            tracing::debug!(
                                                "Block announced by peer {}: {}",
                                                peer_id.0, item.hash
                                            );
                                        }
                                        InvType::MsgTx | InvType::MsgWitnessTx => {
                                            // New transaction -- request if not in mempool
                                            // and not recently rejected
                                            let rpc = rpc_state.read().await;
                                            if !rpc.mempool.contains(&item.hash)
                                                && !rpc.recently_rejected.contains(&item.hash)
                                            {
                                                tx_requests.push(item.clone());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                if !tx_requests.is_empty() {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.send_to_peer(
                                            peer_id,
                                            NetworkMessage::GetData(tx_requests),
                                        )
                                        .await;
                                    }
                                }
                            }

                            NetworkMessage::Tx(tx) => {
                                let txid = tx.txid();
                                let wtxid = tx.wtxid();
                                // Capture the wire size up front so we can
                                // bound the orphanage entry without
                                // re-serializing.  Falls back to a rough
                                // upper bound on encode failure (shouldn't
                                // happen for a tx that just decoded).
                                let tx_size = {
                                    let mut buf = Vec::new();
                                    tx.encode(&mut buf).map(|_| buf.len()).unwrap_or(usize::MAX)
                                };
                                let mut rpc = rpc_state.write().await;
                                // Refresh tip snapshot for IsFinalTx / coinbase-maturity checks.
                                {
                                    let h = rpc.best_height;
                                    let mtp = compute_mtp_via_store(&block_store, &rpc.best_hash).unwrap_or(0) as i64;
                                    rpc.mempool.notify_new_tip(h, mtp);
                                }
                                let result = rpc.mempool.add_transaction(tx.clone(), &|outpoint| {
                                    // Look up UTXO from storage
                                    block_store.get_utxo(outpoint).ok().flatten().map(|coin| {
                                        rustoshi_consensus::CoinEntry {
                                            height: coin.height,
                                            is_coinbase: coin.is_coinbase,
                                            value: coin.value,
                                            script_pubkey: coin.script_pubkey,
                                        }
                                    })
                                });
                                match result {
                                    Ok(_) => {
                                        tracing::debug!("Added tx {} to mempool", txid);

                                        // Track for fee estimation (P2P inbound path).
                                        // Mirrors the sendrawtransaction wiring in server.rs.
                                        // Called while holding the rpc write-lock, same as
                                        // the RPC path.
                                        let fee_rate = rpc
                                            .mempool
                                            .get(&txid)
                                            .map(|e| e.fee_rate)
                                            .unwrap_or(0.0);
                                        if fee_rate > 0.0 {
                                            rpc.fee_estimator.track_transaction(txid, fee_rate);
                                        }

                                        // Lookup-and-promote: any orphan
                                        // whose inputs reference this txid
                                        // may now be admittable.  Walk the
                                        // orphanage, retry, and erase
                                        // unconditionally (success ⇒ done;
                                        // failure ⇒ don't retry on every
                                        // future parent arrival).
                                        let children = rpc.orphanage.find_children(&txid);
                                        for entry in children {
                                            let child_txid = entry.tx.txid();
                                            let admit = rpc.mempool.add_transaction(
                                                (*entry.tx).clone(),
                                                &|outpoint| {
                                                    block_store
                                                        .get_utxo(outpoint)
                                                        .ok()
                                                        .flatten()
                                                        .map(|coin| {
                                                            rustoshi_consensus::CoinEntry {
                                                                height: coin.height,
                                                                is_coinbase: coin.is_coinbase,
                                                                value: coin.value,
                                                                script_pubkey: coin.script_pubkey,
                                                            }
                                                        })
                                                },
                                            );
                                            match admit {
                                                Ok(_) => {
                                                    tracing::debug!(
                                                        "Promoted orphan tx {} to mempool",
                                                        child_txid
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::debug!(
                                                        "Orphan promotion failed for {}: {}",
                                                        child_txid, e
                                                    );
                                                }
                                            }
                                            rpc.orphanage.erase(&child_txid);
                                        }

                                        drop(rpc);
                                        // Relay to all peers except the source
                                        let ps = peer_state.read().await;
                                        if let Some(ref pm) = ps.peer_manager {
                                            let inv = InvVector {
                                                inv_type: InvType::MsgWitnessTx,
                                                hash: wtxid,
                                            };
                                            let peers: Vec<_> = pm
                                                .connected_peers()
                                                .iter()
                                                .map(|(id, _)| *id)
                                                .collect();
                                            for pid in peers {
                                                if pid != peer_id {
                                                    pm.send_to_peer(
                                                        pid,
                                                        NetworkMessage::Inv(vec![inv.clone()]),
                                                    )
                                                    .await;
                                                }
                                            }
                                        }
                                    }
                                    Err(rustoshi_consensus::MempoolError::MissingInput(_, _)) => {
                                        // Orphan: parent UTXO not yet
                                        // visible.  Cache for a future
                                        // arrival, capped per Core
                                        // (MAX_ORPHAN_*).  Per-peer +
                                        // global limits are enforced by
                                        // TxOrphanage::add.
                                        if rpc.orphanage.contains(&txid) {
                                            tracing::trace!("Already in orphanage: {}", txid);
                                        } else {
                                            match rpc.orphanage.add(
                                                std::sync::Arc::new(tx),
                                                peer_id.0,
                                                tx_size,
                                            ) {
                                                Ok(()) => tracing::debug!(
                                                    "Stored orphan tx {} (size={}, peer={})",
                                                    txid, tx_size, peer_id.0
                                                ),
                                                Err(e) => tracing::debug!(
                                                    "Orphanage refused {}: {:?}",
                                                    txid, e
                                                ),
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("Rejected tx {}: {}", txid, e);
                                        // Add to recently-rejected filter to avoid re-requesting
                                        if rpc.recently_rejected.len() < 50_000 {
                                            rpc.recently_rejected.insert(txid);
                                        }
                                    }
                                }
                            }

                            NetworkMessage::GetHeaders(gh_msg) => {
                                // Rate-limit header serving during IBD to prioritize
                                // block downloads. Skip if we're far behind tip.
                                let our_height = {
                                    let rpc = rpc_state.read().await;
                                    rpc.best_height
                                };
                                let best_header = header_sync.best_header_height();

                                // During IBD, rate-limit header serving to avoid
                                // starving block downloads and bloating memory.
                                // Also rate-limit at startup before our own headers
                                // are synced (best_header == 0 means we haven't
                                // finished our own header sync yet).
                                if best_header > our_height + 1000 || best_header == 0 {
                                    // Only serve headers occasionally during IBD
                                    // Skip most getheaders to free bandwidth for blocks
                                    static IBD_HEADER_COUNTER: std::sync::atomic::AtomicU64
                                        = std::sync::atomic::AtomicU64::new(0);
                                    let count = IBD_HEADER_COUNTER.fetch_add(1,
                                        std::sync::atomic::Ordering::Relaxed);
                                    if !count.is_multiple_of(10) {
                                        // Skip 9 out of 10 getheaders during IBD
                                        continue;
                                    }
                                }

                                // Find fork point from locator (use hash index, not linear scan)
                                let start_height = {
                                    let mut found_height = 0u32;
                                    for locator_hash in &gh_msg.locator_hashes {
                                        // Try to find the height for this hash via the height index
                                        if let Ok(Some(_)) = block_store.get_header(locator_hash) {
                                            // Find height by checking the block index
                                            for h in (0..=our_height).rev() {
                                                if let Ok(Some(hh)) = block_store.get_hash_by_height(h) {
                                                    if &hh == locator_hash {
                                                        found_height = h;
                                                        break;
                                                    }
                                                }
                                                // Locator hashes use exponential backoff, so
                                                // the matching hash should be close to the tip.
                                                // Bail early if we've searched 2000+ heights.
                                                if our_height.saturating_sub(h) > 2000 && h < our_height.saturating_sub(2000) {
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                    found_height
                                };

                                // Send up to 2000 headers
                                let end_height = std::cmp::min(
                                    start_height + 2000,
                                    our_height,
                                );
                                let mut headers = Vec::new();
                                for h in (start_height + 1)..=end_height {
                                    if let Ok(Some(hash)) = block_store.get_hash_by_height(h) {
                                        if let Ok(Some(header)) = block_store.get_header(&hash) {
                                            headers.push(header);
                                        } else {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                                if !headers.is_empty() {
                                    tracing::info!(
                                        "Serving {} headers (heights {}..={}) to peer {}",
                                        headers.len(), start_height + 1,
                                        start_height + headers.len() as u32,
                                        peer_id.0
                                    );
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        // Use try_send for header serving — it's bulk
                                        // data that can be dropped without harm.
                                        pm.try_send_to_peer(
                                            peer_id,
                                            NetworkMessage::Headers(headers),
                                        );
                                    }
                                }
                            }

                            NetworkMessage::GetData(items) => {
                                tracing::info!("Received getdata with {} items from peer {}", items.len(), peer_id.0);
                                // Serve requested blocks/transactions to peers
                                for item in &items {
                                    match item.inv_type {
                                        InvType::MsgBlock | InvType::MsgWitnessBlock => {
                                            // Look up block from storage and send it
                                            match block_store.get_block(&item.hash) {
                                                Ok(Some(block)) => {
                                                    tracing::debug!(
                                                        "Serving block {} to peer {}",
                                                        item.hash, peer_id.0
                                                    );
                                                    let ps = peer_state.read().await;
                                                    if let Some(ref pm) = ps.peer_manager {
                                                        pm.try_send_to_peer(
                                                            peer_id,
                                                            NetworkMessage::Block(block),
                                                        );
                                                    }
                                                }
                                                _ => {
                                                    tracing::debug!(
                                                        "Block {} not found for peer {}",
                                                        item.hash, peer_id.0
                                                    );
                                                }
                                            }
                                        }
                                        InvType::MsgTx | InvType::MsgWitnessTx => {
                                            // Serve transaction from mempool
                                            let rpc = rpc_state.read().await;
                                            if let Some(entry) = rpc.mempool.get(&item.hash) {
                                                let tx = entry.tx.clone();
                                                drop(rpc);
                                                let ps = peer_state.read().await;
                                                if let Some(ref pm) = ps.peer_manager {
                                                    pm.try_send_to_peer(
                                                        peer_id,
                                                        NetworkMessage::Tx(tx),
                                                    );
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            // ============================================================
                            // BIP-157 P2P handlers (FIX-82 / W121 BUG-7..BUG-13 closure)
                            //
                            // Mirror Core's net_processing.cpp ProcessGetCFilters /
                            // ProcessGetCFHeaders / ProcessGetCFCheckPt + the shared
                            // PrepareBlockFilterRequest DoS gate (lines 3262-3422).
                            //
                            // Each handler:
                            //   1. Validates filter_type == BASIC + NODE_COMPACT_FILTERS
                            //      advertised; otherwise peer.disconnect (Core
                            //      fDisconnect=true).
                            //   2. Resolves stop_hash → height + walks the active chain
                            //      to confirm the hash is on our best chain (matches
                            //      Core's BlockRequestAllowed via the height-index
                            //      mirror).
                            //   3. Enforces start_height <= stop_height + per-message
                            //      range cap (MAX_GETCFILTERS_SIZE / MAX_GETCFHEADERS_SIZE
                            //      / unbounded for getcfcheckpt).
                            //   4. Reads BlockFilterIndex via lookup_filter_range /
                            //      lookup_filter_hash_range / per-checkpoint
                            //      get_filter_header. Defensive return-without-sending
                            //      if a row is missing (matches Core's bool return).
                            //   5. Pushes the response back to the peer.
                            //
                            // The handler-presence is announced via NODE_COMPACT_FILTERS
                            // gated by `should_advertise_compact_filters` (FIX-82 flips
                            // BIP157_P2P_HANDLERS_REGISTERED → true; the bit is
                            // advertised when both `-blockfilterindex` and
                            // `-peerblockfilters` are set).
                            // ============================================================
                            NetworkMessage::GetCFilters(req) => {
                                // (1) Service-bit + filter-type gate. Our local services
                                //     come straight from the PeerManager — if the operator
                                //     hasn't enabled both -blockfilterindex and
                                //     -peerblockfilters, the bit is unset and we MUST
                                //     disconnect any peer that sends getcfilters.
                                let local_services = {
                                    let ps = peer_state.read().await;
                                    ps.peer_manager
                                        .as_ref()
                                        .map(|pm| pm.local_services())
                                        .unwrap_or(0)
                                };
                                let serves_cf = local_services & NODE_COMPACT_FILTERS != 0;
                                if !serves_cf || req.filter_type != 0 {
                                    tracing::debug!(
                                        "peer {} sent getcfilters with unsupported filter \
                                         type {} (serves_cf={}) — disconnect",
                                        peer_id.0,
                                        req.filter_type,
                                        serves_cf
                                    );
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                // (2) stop_hash lookup + active-chain validation.
                                let stop_index = match block_store.get_block_index(&req.stop_hash) {
                                    Ok(Some(e)) => e,
                                    _ => {
                                        tracing::debug!(
                                            "peer {} sent getcfilters with unknown stop_hash {} — disconnect",
                                            peer_id.0, req.stop_hash
                                        );
                                        let ps = peer_state.read().await;
                                        if let Some(ref pm) = ps.peer_manager {
                                            pm.try_disconnect_peer(peer_id);
                                        }
                                        continue;
                                    }
                                };
                                // The stop_hash must be on the active chain. Mirrors
                                // Core's BlockRequestAllowed (which checks
                                // !pindexBestHeader->GetAncestor(h) failure).
                                if block_store
                                    .get_hash_by_height(stop_index.height)
                                    .ok()
                                    .flatten()
                                    != Some(req.stop_hash)
                                {
                                    tracing::debug!(
                                        "peer {} sent getcfilters for non-active-chain block — disconnect",
                                        peer_id.0
                                    );
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                let stop_height = stop_index.height;
                                // (3) Range bounds. Core uses "diff >= max" (i.e.
                                //     stop-start+1 > max) to disconnect.
                                if req.start_height > stop_height {
                                    tracing::debug!(
                                        "peer {} sent getcfilters with start>stop ({} > {}) — disconnect",
                                        peer_id.0, req.start_height, stop_height
                                    );
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                if stop_height - req.start_height >= MAX_GETCFILTERS_SIZE {
                                    tracing::debug!(
                                        "peer {} requested too many cfilters: {} > {} — disconnect",
                                        peer_id.0,
                                        stop_height - req.start_height + 1,
                                        MAX_GETCFILTERS_SIZE
                                    );
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                // (4) Read filters via the range API.
                                let idx = BlockFilterIndex::new(block_store.db());
                                let filters = match idx.lookup_filter_range(
                                    req.start_height,
                                    stop_height,
                                    |h| block_store.get_hash_by_height(h).ok().flatten(),
                                ) {
                                    Ok(Some(f)) => f,
                                    _ => {
                                        // Defensive: index lagging or missing row;
                                        // return without sending. Matches Core
                                        // ProcessGetCFilters lines 3334-3337.
                                        tracing::debug!(
                                            "BlockFilterIndex lookup_filter_range failed for peer {} (start={}, stop={})",
                                            peer_id.0, req.start_height, stop_height
                                        );
                                        continue;
                                    }
                                };
                                // (5) Push each filter as a cfilter response.
                                let ps = peer_state.read().await;
                                if let Some(ref pm) = ps.peer_manager {
                                    for f in filters {
                                        let msg = NetworkMessage::CFilter(CFilterMessage {
                                            filter_type: 0,
                                            block_hash: f.block_hash,
                                            filter_bytes: f.encoded_filter,
                                        });
                                        pm.try_send_to_peer(peer_id, msg);
                                    }
                                }
                            }

                            NetworkMessage::GetCFHeaders(req) => {
                                let local_services = {
                                    let ps = peer_state.read().await;
                                    ps.peer_manager
                                        .as_ref()
                                        .map(|pm| pm.local_services())
                                        .unwrap_or(0)
                                };
                                let serves_cf = local_services & NODE_COMPACT_FILTERS != 0;
                                if !serves_cf || req.filter_type != 0 {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                let stop_index = match block_store.get_block_index(&req.stop_hash) {
                                    Ok(Some(e)) => e,
                                    _ => {
                                        let ps = peer_state.read().await;
                                        if let Some(ref pm) = ps.peer_manager {
                                            pm.try_disconnect_peer(peer_id);
                                        }
                                        continue;
                                    }
                                };
                                if block_store
                                    .get_hash_by_height(stop_index.height)
                                    .ok()
                                    .flatten()
                                    != Some(req.stop_hash)
                                {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                let stop_height = stop_index.height;
                                if req.start_height > stop_height {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                if stop_height - req.start_height >= MAX_GETCFHEADERS_SIZE {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                // Resolve prev_filter_header (zero when start_height == 0).
                                let idx = BlockFilterIndex::new(block_store.db());
                                let prev_filter_header = if req.start_height == 0 {
                                    rustoshi_primitives::Hash256::ZERO
                                } else {
                                    match idx.lookup_filter_header_at_height(req.start_height - 1) {
                                        Ok(Some(h)) => h,
                                        _ => {
                                            // FIX-79 ouroboros pattern: defensive
                                            // return-without-sending when the previous
                                            // header row is missing. Matches Core
                                            // net_processing.cpp:3361-3370.
                                            tracing::debug!(
                                                "peer {} getcfheaders: prev_filter_header at {} missing — defensive return",
                                                peer_id.0, req.start_height - 1
                                            );
                                            continue;
                                        }
                                    }
                                };
                                // Collect per-height filter hashes.
                                let filter_hashes = match idx.lookup_filter_hash_range(
                                    req.start_height,
                                    stop_height,
                                    |h| block_store.get_hash_by_height(h).ok().flatten(),
                                ) {
                                    Ok(Some(v)) => v,
                                    _ => {
                                        tracing::debug!(
                                            "peer {} getcfheaders: lookup_filter_hash_range failed",
                                            peer_id.0
                                        );
                                        continue;
                                    }
                                };
                                let msg = NetworkMessage::CFHeaders(CFHeadersMessage {
                                    filter_type: 0,
                                    stop_hash: req.stop_hash,
                                    previous_filter_header: prev_filter_header,
                                    filter_hashes,
                                });
                                let ps = peer_state.read().await;
                                if let Some(ref pm) = ps.peer_manager {
                                    pm.try_send_to_peer(peer_id, msg);
                                }
                            }

                            NetworkMessage::GetCFCheckpt(req) => {
                                let local_services = {
                                    let ps = peer_state.read().await;
                                    ps.peer_manager
                                        .as_ref()
                                        .map(|pm| pm.local_services())
                                        .unwrap_or(0)
                                };
                                let serves_cf = local_services & NODE_COMPACT_FILTERS != 0;
                                if !serves_cf || req.filter_type != 0 {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                let stop_index = match block_store.get_block_index(&req.stop_hash) {
                                    Ok(Some(e)) => e,
                                    _ => {
                                        let ps = peer_state.read().await;
                                        if let Some(ref pm) = ps.peer_manager {
                                            pm.try_disconnect_peer(peer_id);
                                        }
                                        continue;
                                    }
                                };
                                if block_store
                                    .get_hash_by_height(stop_index.height)
                                    .ok()
                                    .flatten()
                                    != Some(req.stop_hash)
                                {
                                    let ps = peer_state.read().await;
                                    if let Some(ref pm) = ps.peer_manager {
                                        pm.try_disconnect_peer(peer_id);
                                    }
                                    continue;
                                }
                                let stop_height = stop_index.height;
                                // Walk every CFCHECKPT_INTERVAL height up to
                                // stop_height / CFCHECKPT_INTERVAL. Matches Core
                                // ProcessGetCFCheckPt (net_processing.cpp:3403-3417).
                                let idx = BlockFilterIndex::new(block_store.db());
                                let count = (stop_height / CFCHECKPT_INTERVAL) as usize;
                                let mut filter_headers: Vec<rustoshi_primitives::Hash256> =
                                    Vec::with_capacity(count);
                                let mut ok = true;
                                for i in 0..count {
                                    let height = ((i + 1) as u32) * CFCHECKPT_INTERVAL;
                                    // Active-chain walk: stop_index's ancestor at
                                    // `height` is the height-index entry only when
                                    // stop_hash is on the active chain, which we
                                    // already verified above.
                                    let _ancestor_hash = match block_store
                                        .get_hash_by_height(height)
                                        .ok()
                                        .flatten()
                                    {
                                        Some(h) => h,
                                        None => {
                                            ok = false;
                                            break;
                                        }
                                    };
                                    match idx.lookup_filter_header_at_height(height) {
                                        Ok(Some(h)) => filter_headers.push(h),
                                        _ => {
                                            ok = false;
                                            break;
                                        }
                                    }
                                }
                                if !ok {
                                    tracing::debug!(
                                        "peer {} getcfcheckpt: header walk failed at stop_height={}",
                                        peer_id.0, stop_height
                                    );
                                    continue;
                                }
                                let msg = NetworkMessage::CFCheckpt(CFCheckptMessage {
                                    filter_type: 0,
                                    stop_hash: req.stop_hash,
                                    filter_headers,
                                });
                                let ps = peer_state.read().await;
                                if let Some(ref pm) = ps.peer_manager {
                                    pm.try_send_to_peer(peer_id, msg);
                                }
                            }

                            // BIP 35: Respond to a peer's `mempool` request with the full
                            // set of in-mempool txids (or wtxids when the peer negotiated
                            // BIP 339 wtxid relay), chunked into inv messages of
                            // MAX_INV_SIZE entries.  Mirrors Bitcoin Core's handler in
                            // `net_processing.cpp` (search for `NetMsgType::MEMPOOL`).
                            NetworkMessage::MemPool => {
                                use rustoshi_network::message::MAX_INV_SIZE;

                                // Gate: drop + disconnect if we did not advertise NODE_BLOOM.
                                // Core: `if (!(peer.m_our_services & NODE_BLOOM) && !pfrom.HasPermission(...))
                                //       { ... pfrom.fDisconnect = true; }`
                                let (bloom_enabled, peer_supports_wtxid, has_pm) = {
                                    let ps = peer_state.read().await;
                                    match ps.peer_manager.as_ref() {
                                        Some(pm) => (
                                            pm.peer_bloom_filters_enabled(),
                                            pm.get_peer_info(peer_id)
                                                .map(|i| i.supports_wtxid_relay)
                                                .unwrap_or(false),
                                            true,
                                        ),
                                        None => (false, false, false),
                                    }
                                };

                                if !has_pm {
                                    // Peer manager unavailable — nothing to do.
                                } else if !bloom_enabled {
                                    tracing::debug!(
                                        "mempool request from peer {} with bloom filters disabled, disconnecting",
                                        peer_id.0
                                    );
                                    let mut ps = peer_state.write().await;
                                    if let Some(ref mut pm) = ps.peer_manager {
                                        pm.disconnect_peer(peer_id).await;
                                    }
                                } else {
                                    // Walk the mempool and build inv vectors.
                                    let entries: Vec<(Hash256, Hash256)> = {
                                        let rpc = rpc_state.read().await;
                                        rpc.mempool.collect_txid_wtxid()
                                    };

                                    if entries.is_empty() {
                                        tracing::debug!(
                                            "mempool request from peer {}: empty mempool, no inv to send",
                                            peer_id.0
                                        );
                                    } else {
                                        let inv_type = if peer_supports_wtxid {
                                            InvType::MsgWitnessTx
                                        } else {
                                            InvType::MsgTx
                                        };
                                        let mut invs: Vec<InvVector> = entries
                                            .into_iter()
                                            .map(|(txid, wtxid)| InvVector {
                                                inv_type,
                                                hash: if peer_supports_wtxid { wtxid } else { txid },
                                            })
                                            .collect();

                                        tracing::debug!(
                                            "mempool request from peer {}: sending {} inv entries (wtxid={})",
                                            peer_id.0, invs.len(), peer_supports_wtxid
                                        );

                                        // Chunk into MAX_INV_SIZE-sized inv messages.
                                        let ps = peer_state.read().await;
                                        if let Some(ref pm) = ps.peer_manager {
                                            while !invs.is_empty() {
                                                let take = invs.len().min(MAX_INV_SIZE);
                                                let chunk: Vec<InvVector> = invs.drain(..take).collect();
                                                pm.try_send_to_peer(
                                                    peer_id,
                                                    NetworkMessage::Inv(chunk),
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            // BIP 152: Handle compact block relay messages
                            NetworkMessage::SendCmpct(sc) => {
                                tracing::debug!(
                                    "Peer {} supports compact blocks: version={}, announce={}",
                                    peer_id.0, sc.version, sc.announce
                                );
                                // Record peer's compact block preferences (forwarded to peer manager)
                                let mut ps = peer_state.write().await;
                                if let Some(ref mut pm) = ps.peer_manager {
                                    pm.handle_event(PeerEvent::Message(peer_id, NetworkMessage::SendCmpct(sc))).await;
                                }
                            }

                            NetworkMessage::CmpctBlock(data) => {
                                // BIP 152: Reconstruct block from compact block + mempool
                                use rustoshi_network::{CmpctBlock, PartiallyDownloadedBlock, BlockTxnRequest};
                                use rustoshi_primitives::{Hash256, Transaction};
                                match CmpctBlock::decode(&mut std::io::Cursor::new(&data)) {
                                    Ok(cmpct) => {
                                        let block_hash = cmpct.block_hash();
                                        let (mempool_txns, segwit_active) = {
                                            let rpc = rpc_state.read().await;
                                            let seg = rpc.params.is_segwit_active(rpc.best_height);
                                            (rpc.mempool.collect_for_compact_block(), seg)
                                        };
                                        let mempool_refs: Vec<(&Hash256, &Arc<Transaction>)> =
                                            mempool_txns.iter().map(|(h, t)| (h, t)).collect();
                                        match PartiallyDownloadedBlock::init_data(
                                            &cmpct, mempool_refs.into_iter(), &[],
                                        ) {
                                            Ok(mut partial) => {
                                                let missing = partial.get_missing_indices();
                                                let (prefilled, from_mempool, _extra) = partial.stats();
                                                if missing.is_empty() {
                                                    match partial.fill_block(vec![], segwit_active) {
                                                        Ok(block) => {
                                                            tracing::info!(
                                                                "Compact block {} reconstructed (prefilled={}, mempool={})",
                                                                block_hash, prefilled, from_mempool
                                                            );
                                                            block_downloader.block_received(peer_id, block);
                                                        }
                                                        Err(_) => {
                                                            tracing::warn!("Compact block {} merkle mismatch, requesting full block", block_hash);
                                                            let inv = InvVector { inv_type: InvType::MsgWitnessBlock, hash: block_hash };
                                                            let ps = peer_state.read().await;
                                                            if let Some(ref pm) = ps.peer_manager {
                                                                pm.send_to_peer(peer_id, NetworkMessage::GetData(vec![inv])).await;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    let miss_pct = missing.len() as f64 / cmpct.block_tx_count() as f64 * 100.0;
                                                    if miss_pct > 50.0 {
                                                        tracing::info!("Compact block {} missing {:.0}% txns, requesting full block", block_hash, miss_pct);
                                                        let inv = InvVector { inv_type: InvType::MsgWitnessBlock, hash: block_hash };
                                                        let ps = peer_state.read().await;
                                                        if let Some(ref pm) = ps.peer_manager {
                                                            pm.send_to_peer(peer_id, NetworkMessage::GetData(vec![inv])).await;
                                                        }
                                                    } else {
                                                        tracing::info!("Compact block {} missing {} txns (mempool_hits={}), sending getblocktxn", block_hash, missing.len(), from_mempool);
                                                        let req = BlockTxnRequest::new(block_hash, missing);
                                                        // Store the PartiallyDownloadedBlock so the
                                                        // blocktxn handler can complete reconstruction.
                                                        // Key: (peer_id, block_hash) — one in-flight
                                                        // block per peer (Core net_processing.cpp:5028).
                                                        inflight_partial_blocks
                                                            .insert((peer_id.0, block_hash), partial);
                                                        let ps = peer_state.read().await;
                                                        if let Some(ref pm) = ps.peer_manager {
                                                            pm.send_to_peer(peer_id, NetworkMessage::GetBlockTxn(req.serialize())).await;
                                                        }
                                                    }
                                                }
                                            }
                                            Err(status) => {
                                                tracing::warn!("Compact block init failed ({:?}), requesting full block", status);
                                                let block_hash = rustoshi_crypto::sha256d(&data[..80]);
                                                let inv = InvVector { inv_type: InvType::MsgWitnessBlock, hash: block_hash };
                                                let ps = peer_state.read().await;
                                                if let Some(ref pm) = ps.peer_manager {
                                                    pm.send_to_peer(peer_id, NetworkMessage::GetData(vec![inv])).await;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("Failed to decode cmpctblock from peer {} ({} bytes): {}", peer_id.0, data.len(), e);
                                        // DoS: malformed compact block. 100-pt
                                        // instant ban (Bitcoin Core: bad-cmpctblk).
                                        let mut ps = peer_state.write().await;
                                        if let Some(ref mut pm) = ps.peer_manager {
                                            pm.misbehaving(
                                                peer_id,
                                                MisbehaviorReason::InvalidCompactBlock,
                                            )
                                            .await;
                                        }
                                    }
                                }
                            }

                            NetworkMessage::GetBlockTxn(data) => {
                                use rustoshi_network::{BlockTxnRequest, BlockTxn};
                                match BlockTxnRequest::deserialize(&data) {
                                    Ok(req) => {
                                        if let Ok(Some(block)) = block_store.get_block(&req.block_hash) {
                                            let txns: Vec<Arc<rustoshi_primitives::Transaction>> = req.indices.iter()
                                                .filter_map(|&idx| block.transactions.get(idx as usize).map(|tx| Arc::new(tx.clone())))
                                                .collect();
                                            let resp = BlockTxn::from_arcs(req.block_hash, txns);
                                            let ps = peer_state.read().await;
                                            if let Some(ref pm) = ps.peer_manager {
                                                pm.send_to_peer(peer_id, NetworkMessage::BlockTxn(resp.serialize())).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to decode getblocktxn from peer {}: {}", peer_id.0, e);
                                    }
                                }
                            }

                            NetworkMessage::BlockTxn(data) => {
                                // BIP-152: Complete compact block reconstruction.
                                //
                                // Core flow (net_processing.cpp:4276-4326):
                                //   1. Look up the in-flight PartiallyDownloadedBlock for
                                //      this (peer, block_hash) pair.
                                //   2. Call FillBlock(block, resp.txn).
                                //   3a. READ_STATUS_OK  → ProcessNewBlock (validate + connect).
                                //   3b. READ_STATUS_FAILED (merkle mismatch / wrong tx count)
                                //       → Misbehaving(peer, 100) + fall back to full block via
                                //         getdata MSG_WITNESS_BLOCK.
                                use rustoshi_network::BlockTxn;
                                match BlockTxn::deserialize(&data) {
                                    Ok(blocktxn) => {
                                        tracing::debug!(
                                            "Received blocktxn for {} from peer {} ({} txns)",
                                            blocktxn.block_hash, peer_id.0, blocktxn.transactions.len()
                                        );

                                        let key = (peer_id.0, blocktxn.block_hash);
                                        match inflight_partial_blocks.remove(&key) {
                                            None => {
                                                // No in-flight partial block for this hash + peer.
                                                // Could be a duplicate response or arrived after a
                                                // fallback getdata — ignore silently (Core does the
                                                // same at net_processing.cpp:4280-4282).
                                                tracing::debug!(
                                                    "blocktxn from peer {} for unknown in-flight block {} — ignoring",
                                                    peer_id.0, blocktxn.block_hash
                                                );
                                            }
                                            Some(mut partial) => {
                                                let segwit_active = {
                                                    let rpc = rpc_state.read().await;
                                                    rpc.params.is_segwit_active(rpc.best_height)
                                                };

                                                match partial.fill_block(
                                                    blocktxn.transactions,
                                                    segwit_active,
                                                ) {
                                                    Ok(block) => {
                                                        tracing::info!(
                                                            "Compact block {} reconstructed via blocktxn from peer {}",
                                                            blocktxn.block_hash, peer_id.0
                                                        );
                                                        block_downloader
                                                            .block_received(peer_id, block);
                                                    }
                                                    Err(rustoshi_network::compact_blocks::ReadStatus::Failed) => {
                                                        // Merkle mismatch or wrong tx count —
                                                        // likely a short-ID collision survivor.
                                                        // 100-pt Misbehaving (Core net_processing.cpp:4310)
                                                        // + fall back to requesting the full block.
                                                        tracing::warn!(
                                                            "blocktxn from peer {} for {} caused merkle mismatch — misbehaving + requesting full block",
                                                            peer_id.0, blocktxn.block_hash
                                                        );
                                                        {
                                                            let mut ps = peer_state.write().await;
                                                            if let Some(ref mut pm) = ps.peer_manager {
                                                                pm.misbehaving(
                                                                    peer_id,
                                                                    MisbehaviorReason::InvalidCompactBlock,
                                                                )
                                                                .await;
                                                            }
                                                        }
                                                        let inv = InvVector {
                                                            inv_type: InvType::MsgWitnessBlock,
                                                            hash: blocktxn.block_hash,
                                                        };
                                                        let ps = peer_state.read().await;
                                                        if let Some(ref pm) = ps.peer_manager {
                                                            pm.send_to_peer(
                                                                peer_id,
                                                                NetworkMessage::GetData(vec![inv]),
                                                            )
                                                            .await;
                                                        }
                                                    }
                                                    Err(_) => {
                                                        // ReadStatus::Invalid — wrong tx count
                                                        // supplied (our own bug or DoS).  Log and
                                                        // fall back to full block without misbehaving.
                                                        tracing::warn!(
                                                            "fill_block returned Invalid for {} from peer {} — requesting full block",
                                                            blocktxn.block_hash, peer_id.0
                                                        );
                                                        let inv = InvVector {
                                                            inv_type: InvType::MsgWitnessBlock,
                                                            hash: blocktxn.block_hash,
                                                        };
                                                        let ps = peer_state.read().await;
                                                        if let Some(ref pm) = ps.peer_manager {
                                                            pm.send_to_peer(
                                                                peer_id,
                                                                NetworkMessage::GetData(vec![inv]),
                                                            )
                                                            .await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to decode blocktxn from peer {}: {}", peer_id.0, e);
                                        // Malformed compact-block follow-up.
                                        // 100-pt ban — Core treats this the
                                        // same as a bad cmpctblock.
                                        let mut ps = peer_state.write().await;
                                        if let Some(ref mut pm) = ps.peer_manager {
                                            pm.misbehaving(
                                                peer_id,
                                                MisbehaviorReason::InvalidCompactBlock,
                                            )
                                            .await;
                                        }
                                    }
                                }
                            }

                            // Forward other messages to peer manager for internal handling
                            _ => {
                                let mut ps = peer_state.write().await;
                                if let Some(ref mut pm) = ps.peer_manager {
                                    pm.handle_event(PeerEvent::Message(peer_id, msg)).await;
                                }
                            }
                        }
                    }

                    Some(PeerEvent::Disconnected(peer_id, reason)) => {
                        tracing::info!("Peer {} disconnected: {:?}", peer_id.0, reason);
                        header_sync.remove_peer(peer_id);
                        block_downloader.remove_peer(peer_id);
                        // Discard any in-flight partial block for this peer —
                        // the blocktxn response will never arrive.
                        inflight_partial_blocks.retain(|(pid, _), _| *pid != peer_id.0);
                        // Drop any orphans this peer announced — they're
                        // unverifiable now that the source is gone, so
                        // freeing the slot benefits other peers.
                        {
                            let mut rpc = rpc_state.write().await;
                            let n = rpc.orphanage.erase_for_peer(peer_id.0);
                            if n > 0 {
                                tracing::debug!(
                                    "Cleared {} orphan(s) from disconnected peer {}",
                                    n, peer_id.0
                                );
                            }
                        }
                        let mut ps = peer_state.write().await;
                        if let Some(ref mut pm) = ps.peer_manager {
                            pm.handle_event(PeerEvent::Disconnected(peer_id, reason)).await;
                        }
                    }

                    // Forward misbehavior signals from spawned read/write tasks
                    // (run_inbound_peer / run_outbound_peer / run_message_loop)
                    // into the peer manager's MisbehaviorTracker + BanManager.
                    Some(PeerEvent::Misbehaving(peer_id, reason)) => {
                        let mut ps = peer_state.write().await;
                        if let Some(ref mut pm) = ps.peer_manager {
                            pm.handle_event(PeerEvent::Misbehaving(peer_id, reason)).await;
                        }
                    }

                    None => {
                        tracing::warn!("Peer event channel closed");
                        break;
                    }
                }
            }

            // Periodic block download retry — picks up enqueued blocks that
            // couldn't be assigned on the first try (e.g. no peers available yet).
            _ = block_retry_interval.tick() => {
                // Check for timed-out block requests FIRST — this frees
                // blocks_in_flight slots so assign_requests can use them.
                let timed_out = block_downloader.check_timeouts();

                // Score misbehavior for peers with stalled block downloads
                if !timed_out.is_empty() {
                    let mut ps = peer_state.write().await;
                    if let Some(ref mut pm) = ps.peer_manager {
                        for stalled_peer in &timed_out {
                            pm.misbehaving(*stalled_peer, MisbehaviorReason::BlockDownloadStall).await;
                        }
                    }
                }

                let queue_len = block_downloader.download_queue_len();
                let in_flight = block_downloader.in_flight_count();
                let peer_count = block_downloader.peer_count();
                let tip = block_downloader.validated_tip_height();

                if queue_len > 0 || in_flight > 0 || !timed_out.is_empty() {
                    tracing::info!(
                        "Retry tick: queue={}, in_flight={}, peers={}, tip={}, timed_out={}, received={}, pending={}",
                        queue_len, in_flight, peer_count, tip, timed_out.len(),
                        block_downloader.received_blocks_count(),
                        block_downloader.pending_hashes_count()
                    );
                }

                if !block_downloader.download_queue_empty() {
                    let requests = block_downloader.assign_requests();
                    if !requests.is_empty() {
                        tracing::info!("Periodic retry: {} getdata requests", requests.len());
                        let ps = peer_state.read().await;
                        if let Some(ref pm) = ps.peer_manager {
                            for (peer, msg) in requests {
                                pm.send_to_peer(peer, msg).await;
                            }
                        }
                    }
                }
            }

            // P2P maintenance tick: drive stalled-peer eviction, outbound
            // fill, and header-sync recovery.  Mirrors Bitcoin Core's
            // PeerManagerImpl::CheckForStaleTipAndEvictPeers + the
            // ThreadOpenConnections fill-outbound loop, except condensed
            // into one 45s tick because rustoshi has a single main loop
            // rather than Core's per-thread structure.
            //
            // Without this tick the StalePeerDetector and
            // fill_outbound_connections never run outside of startup +
            // reactive disconnects, so a peer that goes silent post-
            // handshake (TCP alive but no application messages) wedges
            // sync indefinitely (observed 2026-05-07: rustoshi froze
            // for 6+ hours at h=948271 with one zombie peer).
            _ = maintenance_interval.tick() => {
                let validated_tip = block_downloader.validated_tip_height();
                let in_flight = block_downloader.in_flight_count();

                // 1. Run the stale-peer / chain-sync-timeout detector,
                //    refresh fill-outbound to the configured target,
                //    and snapshot peer count for sync-recovery logic.
                let (stale_result, peer_count) = {
                    let mut ps = peer_state.write().await;
                    if let Some(ref mut pm) = ps.peer_manager {
                        pm.update_tip_height(validated_tip);
                        let stale = pm.check_for_stale_peers(in_flight).await;
                        pm.fill_outbound_connections().await;
                        (stale, pm.peer_count())
                    } else {
                        (Default::default(), 0)
                    }
                };

                let _: rustoshi_network::StalePeerCheckResult = stale_result;

                // 2. Disconnect notifications for peers the stale
                //    detector evicted are delivered via the normal
                //    PeerEvent::Disconnected path; header_sync /
                //    block_downloader peer state is cleaned up there.
                //    Here we only need to recover header sync if the
                //    chosen sync peer was the one that just got
                //    evicted, OR if we were never syncing because
                //    the prior peer was a zombie.
                let header_sync_idle = matches!(
                    header_sync.state(),
                    rustoshi_network::SyncState::Idle
                );
                if peer_count > 0 && header_sync_idle {
                    if let Some((target, msg)) = header_sync.start_sync(|h| {
                        block_store.get_hash_by_height(h).ok().flatten()
                    }) {
                        tracing::info!(
                            "Maintenance: re-issuing getheaders to peer {} (idle sync)",
                            target.0
                        );
                        let ps = peer_state.read().await;
                        if let Some(ref pm) = ps.peer_manager {
                            pm.send_to_peer(target, msg).await;
                        }
                    }
                }
            }

            // ASMap health-check tick — fires every 3600 s (1 hour).
            // Logs ASN diversity stats over all known AddrMan entries so operators
            // can detect stale or low-coverage asmap files.  No-ops (skips the
            // log entirely) when no asmap is loaded.
            _ = asmap_health_interval.tick() => {
                let ps = peer_state.read().await;
                if let Some(ref pm) = ps.peer_manager {
                    if let Some(stats) = pm.asmap_health_check(5) {
                        tracing::info!("{}", stats.summary_line());
                        if !stats.top_asns.is_empty() {
                            let top_str: Vec<String> = stats
                                .top_asns
                                .iter()
                                .map(|(asn, cnt)| format!("AS{}:{}", asn, cnt))
                                .collect();
                            tracing::info!("ASMap top ASNs: {}", top_str.join(", "));
                        }
                    }
                }
            }

            // Handle shutdown signal (Ctrl+C in foreground; SIGTERM under
            // daemon mode / supervisor).  Both produce a graceful shutdown.
            _ = signal::ctrl_c() => {
                tracing::info!("Received shutdown signal (Ctrl+C)");
                break;
            }
            _ = async {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut s) = signal(SignalKind::terminate()) {
                    s.recv().await;
                }
            } => {
                tracing::info!("Received shutdown signal (SIGTERM)");
                break;
            }
        }
    }

    // ============================================================
    // GRACEFUL SHUTDOWN
    // ============================================================
    tracing::info!("Shutting down...");

    // Stop RPC server
    rpc_handle.stop()?;
    tracing::debug!("RPC server stopped");

    // Delete the cookie file so stale credentials don't linger after shutdown.
    delete_cookie_file(&base_datadir);

    // Save fee estimates to disk
    {
        let state = rpc_state.read().await;
        match state.fee_estimator.save(&fee_estimates_path) {
            Ok(()) => tracing::info!("Fee estimates saved to {}", fee_estimates_path.display()),
            Err(e) => tracing::error!("Failed to save fee estimates: {}", e),
        }
    }

    // Dump mempool to `mempool.dat` (Core-format, byte-compatible). Same
    // best-effort posture as fee-estimate persistence: log and continue
    // on any I/O failure.
    {
        let state = rpc_state.read().await;
        match dump_mempool(&state.mempool, &mempool_dat_path) {
            Ok(stats) => tracing::info!(
                "Mempool dumped to {} ({} txs, {} bytes)",
                mempool_dat_path.display(),
                stats.txs,
                stats.bytes,
            ),
            Err(e) => tracing::error!("Failed to dump mempool: {}", e),
        }
    }

    // Flush the UTXO cache AND advance the persisted tip pointer in a
    // single atomic batch.  This is the same `flush_with_tip` invariant
    // the connect loop uses: the durable tip must never point past the
    // durable UTXO set.  Doing the flush and the `set_best_block` as two
    // separate writes here (the old behaviour) reintroduced the wedge
    // window if the process died between them.
    //
    // NB: a graceful shutdown reaches this code, but a SIGKILL / OOM /
    // crash does NOT — that is exactly why the connect loop now also
    // flushes atomically every UTXO_FLUSH_INTERVAL_BLOCKS blocks. This
    // shutdown flush is the best-effort fast path for clean exits.
    {
        let cs = chain_state.read().await;
        let tip_hash = cs.tip_hash();
        let tip_height = cs.tip_height();
        drop(cs);
        let entries = utxo_view.cache_len();
        let mem_mb = utxo_view.estimated_memory() / (1024 * 1024);
        match utxo_view.flush_with_tip(&tip_hash, tip_height) {
            Ok(()) => tracing::info!(
                "UTXO+tip flushed atomically on shutdown: {} entries, ~{} MiB, tip {} at height {}",
                entries, mem_mb, tip_hash, tip_height
            ),
            Err(e) => tracing::error!("Failed to flush UTXO+tip on shutdown: {}", e),
        }
    }

    // Remove PID file so a subsequent supervisor restart sees a clean state.
    remove_pid_file(&pid_path);

    tracing::info!("Shutdown complete");

    Ok(())
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_datadir_mainnet_no_subdirectory() {
        let params = ChainParams::mainnet();
        let path = resolve_datadir("/data/bitcoin", &params);
        assert_eq!(path, PathBuf::from("/data/bitcoin"));
    }

    #[test]
    fn test_resolve_datadir_testnet3_subdirectory() {
        let params = ChainParams::testnet3();
        let path = resolve_datadir("/data/bitcoin", &params);
        assert_eq!(path, PathBuf::from("/data/bitcoin/testnet3"));
    }

    #[test]
    fn test_resolve_datadir_testnet4_subdirectory() {
        let params = ChainParams::testnet4();
        let path = resolve_datadir("/data/bitcoin", &params);
        assert_eq!(path, PathBuf::from("/data/bitcoin/testnet4"));
    }

    #[test]
    fn test_resolve_datadir_signet_subdirectory() {
        let params = ChainParams::signet();
        let path = resolve_datadir("/data/bitcoin", &params);
        assert_eq!(path, PathBuf::from("/data/bitcoin/signet"));
    }

    #[test]
    fn test_resolve_datadir_regtest_subdirectory() {
        let params = ChainParams::regtest();
        let path = resolve_datadir("/data/bitcoin", &params);
        assert_eq!(path, PathBuf::from("/data/bitcoin/regtest"));
    }

    #[test]
    fn test_resolve_datadir_tilde_expansion() {
        // Set HOME for the test
        std::env::set_var("HOME", "/home/testuser");
        let params = ChainParams::mainnet();
        let path = resolve_datadir("~/.rustoshi", &params);
        assert_eq!(path, PathBuf::from("/home/testuser/.rustoshi"));
    }

    #[test]
    fn test_resolve_datadir_tilde_expansion_with_network() {
        std::env::set_var("HOME", "/home/testuser");
        let params = ChainParams::testnet4();
        let path = resolve_datadir("~/.rustoshi", &params);
        assert_eq!(path, PathBuf::from("/home/testuser/.rustoshi/testnet4"));
    }

    #[test]
    fn test_default_rpc_port_mainnet() {
        assert_eq!(default_rpc_port(NetworkId::Mainnet), 8332);
    }

    #[test]
    fn test_default_rpc_port_testnet3() {
        assert_eq!(default_rpc_port(NetworkId::Testnet3), 18332);
    }

    #[test]
    fn test_default_rpc_port_testnet4() {
        assert_eq!(default_rpc_port(NetworkId::Testnet4), 48332);
    }

    #[test]
    fn test_default_rpc_port_signet() {
        assert_eq!(default_rpc_port(NetworkId::Signet), 38332);
    }

    #[test]
    fn test_default_rpc_port_regtest() {
        assert_eq!(default_rpc_port(NetworkId::Regtest), 18443);
    }

    #[test]
    fn test_cli_default_values() {
        // Parse with no arguments
        let cli = Cli::try_parse_from(["rustoshi"]).unwrap();
        assert_eq!(cli.network, "testnet4");
        assert_eq!(cli.datadir, "~/.rustoshi");
        assert_eq!(cli.rpcbind, "127.0.0.1:8332");
        assert!(cli.rpcuser.is_none());
        assert!(cli.rpcpassword.is_none());
        assert!(cli.listen);
        assert!(cli.port.is_none());
        assert_eq!(cli.maxconnections, 8);
        assert!(cli.connect.is_none());
        assert!(!cli.txindex);
        assert_eq!(cli.loglevel, "info");
        assert!(cli.prune.is_none());
        assert!(cli.command.is_none());
        // New ops-parity defaults
        assert!(!cli.daemon);
        assert!(cli.pidfile.is_none());
        assert!(cli.debug_categories.is_none());
        assert!(cli.conf.is_none());
        assert!(cli.printtoconsole);
        assert!(cli.debuglogfile.is_none());
        assert!(cli.ready_fd.is_none());
    }

    #[test]
    fn test_cli_override_network() {
        let cli = Cli::try_parse_from(["rustoshi", "--network", "mainnet"]).unwrap();
        assert_eq!(cli.network, "mainnet");
    }

    #[test]
    fn test_cli_override_datadir() {
        let cli = Cli::try_parse_from(["rustoshi", "--datadir", "/custom/path"]).unwrap();
        assert_eq!(cli.datadir, "/custom/path");
    }

    #[test]
    fn test_cli_override_rpcbind() {
        let cli = Cli::try_parse_from(["rustoshi", "--rpcbind", "0.0.0.0:9999"]).unwrap();
        assert_eq!(cli.rpcbind, "0.0.0.0:9999");
    }

    #[test]
    fn test_cli_rpc_auth() {
        let cli = Cli::try_parse_from([
            "rustoshi",
            "--rpcuser",
            "alice",
            "--rpcpassword",
            "secret123",
        ])
        .unwrap();
        assert_eq!(cli.rpcuser, Some("alice".to_string()));
        assert_eq!(cli.rpcpassword, Some("secret123".to_string()));
    }

    #[test]
    fn test_cli_connection_options() {
        let cli = Cli::try_parse_from([
            "rustoshi",
            "--port",
            "12345",
            "--maxconnections",
            "16",
            "--connect",
            "192.168.1.100:8333",
        ])
        .unwrap();
        assert_eq!(cli.port, Some(12345));
        assert_eq!(cli.maxconnections, 16);
        assert_eq!(cli.connect, Some("192.168.1.100:8333".to_string()));
    }

    /// FIX-88 W121 G29: `--blockfilterindex` parses + defaults off.
    /// Mirrors Bitcoin Core `init.cpp` default `DEFAULT_BLOCKFILTERINDEX=false`.
    #[test]
    fn test_cli_blockfilterindex_flag_fix88() {
        // Default: off.
        let cli = Cli::try_parse_from(["rustoshi"]).unwrap();
        assert_eq!(cli.blockfilterindex, "false");
        // Explicit on (Core-style).
        let cli = Cli::try_parse_from(["rustoshi", "--blockfilterindex", "1"]).unwrap();
        assert_eq!(cli.blockfilterindex, "1");
        // Core also accepts `basic`.
        let cli = Cli::try_parse_from(["rustoshi", "--blockfilterindex", "basic"]).unwrap();
        assert_eq!(cli.blockfilterindex, "basic");
    }

    /// FIX-88 W121 G30: `--peerblockfilters` parses + defaults off.
    /// Mirrors Bitcoin Core `init.cpp:993 DEFAULT_PEERBLOCKFILTERS=false`.
    #[test]
    fn test_cli_peerblockfilters_flag_fix88() {
        let cli = Cli::try_parse_from(["rustoshi"]).unwrap();
        assert!(!cli.peerblockfilters);
        // Bare presence enables (matches `--peerbloomfilters` shape).
        let cli = Cli::try_parse_from(["rustoshi", "--peerblockfilters"]).unwrap();
        assert!(cli.peerblockfilters);
    }

    #[test]
    fn test_cli_txindex_flag() {
        let cli = Cli::try_parse_from(["rustoshi", "--txindex"]).unwrap();
        assert!(cli.txindex);
    }

    #[test]
    fn test_cli_prune_option() {
        let cli = Cli::try_parse_from(["rustoshi", "--prune", "550"]).unwrap();
        assert_eq!(cli.prune, Some(550));
    }

    #[test]
    fn test_cli_loglevel() {
        let cli = Cli::try_parse_from(["rustoshi", "--loglevel", "debug"]).unwrap();
        assert_eq!(cli.loglevel, "debug");
    }

    #[test]
    fn test_cli_subcommand_reindex() {
        let cli = Cli::try_parse_from(["rustoshi", "reindex"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Reindex)));
    }

    #[test]
    fn test_cli_subcommand_resync() {
        let cli = Cli::try_parse_from(["rustoshi", "resync"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Resync)));
    }

    // ----- New ops-parity flag tests -----

    #[test]
    fn test_cli_daemon_flag() {
        // Presence of `--daemon` enables daemon mode; default is false.
        let cli = Cli::try_parse_from(["rustoshi", "--daemon"]).unwrap();
        assert!(cli.daemon);
        // Absence keeps default false.
        let cli = Cli::try_parse_from(["rustoshi"]).unwrap();
        assert!(!cli.daemon);
    }

    #[test]
    fn test_cli_pidfile_flag() {
        let cli = Cli::try_parse_from(["rustoshi", "--pidfile", "/run/rustoshi.pid"]).unwrap();
        assert_eq!(cli.pidfile.as_deref(), Some("/run/rustoshi.pid"));
    }

    #[test]
    fn test_cli_debug_categories_flag() {
        let cli = Cli::try_parse_from(["rustoshi", "--debug", "net,mempool,rpc"]).unwrap();
        assert_eq!(cli.debug_categories.as_deref(), Some("net,mempool,rpc"));
    }

    #[test]
    fn test_cli_conf_flag() {
        let cli = Cli::try_parse_from(["rustoshi", "--conf", "/etc/rustoshi/rustoshi.conf"]).unwrap();
        assert_eq!(cli.conf.as_deref(), Some("/etc/rustoshi/rustoshi.conf"));
    }

    #[test]
    fn test_cli_printtoconsole_flag() {
        // `--printtoconsole=false` explicitly disables (Core-compat syntax).
        let cli = Cli::try_parse_from(["rustoshi", "--printtoconsole=false"]).unwrap();
        assert!(!cli.printtoconsole);
        // Default is true.
        let cli = Cli::try_parse_from(["rustoshi"]).unwrap();
        assert!(cli.printtoconsole);
        // Bare flag re-asserts true.
        let cli = Cli::try_parse_from(["rustoshi", "--printtoconsole"]).unwrap();
        assert!(cli.printtoconsole);
    }

    #[test]
    fn test_cli_debuglogfile_flag() {
        let cli = Cli::try_parse_from(["rustoshi", "--debuglogfile", "/var/log/rustoshi.log"]).unwrap();
        assert_eq!(cli.debuglogfile.as_deref(), Some("/var/log/rustoshi.log"));
    }

    #[test]
    fn test_cli_ready_fd_flag() {
        let cli = Cli::try_parse_from(["rustoshi", "--ready-fd", "3"]).unwrap();
        assert_eq!(cli.ready_fd, Some(3));
    }

    #[test]
    fn test_apply_conf_to_cli_respects_cli_precedence() {
        // CLI flag should win over conf file value.
        let mut cli = Cli::try_parse_from(["rustoshi", "--network", "regtest"]).unwrap();
        let conf = ConfFile::parse("network=mainnet\nlisten=false\n");
        let raw_argv: Vec<String> =
            ["rustoshi", "--network", "regtest"].iter().map(|s| s.to_string()).collect();
        apply_conf_to_cli(&mut cli, &conf, &raw_argv);
        // CLI wins for network
        assert_eq!(cli.network, "regtest");
        // listen wasn't on CLI, so conf wins
        assert!(!cli.listen);
    }

    #[test]
    fn test_apply_conf_to_cli_fills_unset_values() {
        let mut cli = Cli::try_parse_from(["rustoshi"]).unwrap();
        let conf = ConfFile::parse("rpcuser=carol\nrpcpassword=hunter2\n");
        let raw_argv: Vec<String> = vec!["rustoshi".to_string()];
        apply_conf_to_cli(&mut cli, &conf, &raw_argv);
        assert_eq!(cli.rpcuser.as_deref(), Some("carol"));
        assert_eq!(cli.rpcpassword.as_deref(), Some("hunter2"));
    }

    // =================================================================
    // Post-assumeUTXO-snapshot connect path: median-time-past (MTP)
    //
    // Regression coverage for the mainnet 2026-05-20 wedge: a freshly
    // loaded assumeUTXO snapshot at height 944,183 froze the chain at the
    // snapshot base because the first post-snapshot block (944,184) was
    // rejected `bad-txns-nonfinal`. Root cause: header sync starts *at*
    // the snapshot base, so neither the base block nor its 10 ancestors
    // have stored headers; `compute_mtp_via_store` returned `None`, the
    // connect loop's `.unwrap_or(0)` collapsed the `IsFinalTx`
    // `nLockTimeCutoff` to 0, and every time-locked tx in 944,184 looked
    // non-final. The fix: `mtp_for_connect` falls back to the trusted
    // `AssumeutxoData::base_mtp` chainparams constant.
    // =================================================================

    use rustoshi_primitives::{BlockHeader, Hash256};

    /// Build a temporary on-disk block store for MTP tests.
    fn mtp_test_store() -> (tempfile::TempDir, ChainDb) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let db = ChainDb::open(dir.path()).expect("open db");
        (dir, db)
    }

    fn hdr(prev: Hash256, timestamp: u32) -> BlockHeader {
        BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp,
            bits: 0x1702_0684,
            nonce: 0,
        }
    }

    #[test]
    fn median_time_past_empty_is_none() {
        assert_eq!(median_time_past(&mut []), None);
    }

    #[test]
    fn median_time_past_single_element() {
        assert_eq!(median_time_past(&mut [1_775_650_208]), Some(1_775_650_208));
    }

    #[test]
    fn median_time_past_partial_window_unsorted() {
        // Core medians whatever it has; input order must not matter.
        let mut ts = [30u32, 10, 20];
        assert_eq!(median_time_past(&mut ts), Some(20));
    }

    #[test]
    fn median_time_past_full_window_matches_core_944183() {
        // The 11 block timestamps for heights 944,173..=944,183 (mainnet),
        // verified against Bitcoin Core `getblockheader`. The median (6th
        // when sorted) is the MTP of block 944,183 and must equal Core's
        // reported `mediantime`.
        let mut ts = [
            1_775_645_057, // 944173
            1_775_646_085, // 944174
            1_775_646_357, // 944175
            1_775_647_293, // 944176
            1_775_647_738, // 944177
            1_775_650_208, // 944178
            1_775_650_485, // 944179
            1_775_651_075, // 944180
            1_775_651_104, // 944181
            1_775_651_886, // 944182
            1_775_651_930, // 944183
        ];
        assert_eq!(median_time_past(&mut ts), Some(1_775_650_208));
    }

    #[test]
    fn compute_mtp_via_store_stops_at_missing_header() {
        // Two linked headers; the parent of the older one is absent. The
        // walk must NOT bail out to `None` — it medians the partial window
        // it could reach, mirroring Core stopping at a null `pprev`.
        let (_dir, db) = mtp_test_store();
        let store = BlockStore::new(&db);

        let base_hash = Hash256([7u8; 32]); // header deliberately NOT stored
        let h1 = hdr(base_hash, 1_775_651_930);
        let h1_hash = h1.block_hash();
        let h2 = hdr(h1_hash, 1_775_653_126);
        let h2_hash = h2.block_hash();
        store.put_header(&h1_hash, &h1).unwrap();
        store.put_header(&h2_hash, &h2).unwrap();

        // Walk from h2: reaches h2 + h1, then h1.prev (base) is missing.
        // Partial median of {1_775_651_930, 1_775_653_126}.
        assert_eq!(
            compute_mtp_via_store(&store, &h2_hash),
            Some(1_775_653_126)
        );
    }

    #[test]
    fn compute_mtp_via_store_zero_headers_is_none() {
        // The true assumeUTXO boundary: the parent hash has no stored
        // header at all. `compute_mtp_via_store` must return `None` so
        // `mtp_for_connect` can fall back to `base_mtp`.
        let (_dir, db) = mtp_test_store();
        let store = BlockStore::new(&db);
        assert_eq!(compute_mtp_via_store(&store, &Hash256([9u8; 32])), None);
    }

    #[test]
    fn mtp_for_connect_uses_base_mtp_at_snapshot_boundary() {
        // THE regression test. Parent = the mainnet assumeUTXO snapshot
        // base (944,183) whose header was never downloaded. The store has
        // no ancestor headers, so `mtp_for_connect` MUST return the
        // trusted `base_mtp` chainparams constant instead of `None`.
        let (_dir, db) = mtp_test_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();

        let snapshot_base = params
            .assumeutxo_for_height(944_183)
            .expect("mainnet has a 944183 assumeutxo entry");
        let base_hash = snapshot_base.blockhash;

        // Pre-fix behaviour: bare `compute_mtp_via_store` -> None -> 0.
        assert_eq!(compute_mtp_via_store(&store, &base_hash), None);

        // Post-fix behaviour: `mtp_for_connect` recovers the real MTP.
        let mtp = mtp_for_connect(&store, &base_hash, &params)
            .expect("snapshot-base MTP must resolve via base_mtp");
        assert_eq!(mtp, 1_775_650_208);
        assert_eq!(Some(mtp), snapshot_base.base_mtp);
    }

    #[test]
    fn mtp_for_connect_first_post_snapshot_block_is_final_tx() {
        // End-to-end of the fix: the cutoff that the connect loop hands to
        // `is_final_tx` for block 944,184. With the bug it was 0 and any
        // time-locked tx (lock_time >= LOCKTIME_THRESHOLD) was rejected
        // `bad-txns-nonfinal`; with the fix it is the real MTP and the
        // same tx is final.
        use rustoshi_consensus::validation::is_final_tx;
        use rustoshi_primitives::{OutPoint, Transaction, TxIn, TxOut};

        let (_dir, db) = mtp_test_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        let base_hash = params.assumeutxo_for_height(944_183).unwrap().blockhash;

        // A tx with a time-based nLockTime ~30 min before the base block
        // and a non-final input sequence (so finality hinges on locktime).
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: vec![],
                sequence: 0xFFFF_FFFE, // not SEQUENCE_FINAL
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1, script_pubkey: vec![] }],
            lock_time: 1_775_650_000,
        };

        // Buggy cutoff (compute_mtp_via_store alone -> unwrap_or(0)).
        let buggy_cutoff = compute_mtp_via_store(&store, &base_hash).unwrap_or(0);
        assert_eq!(buggy_cutoff, 0);
        assert!(
            !is_final_tx(&tx, 944_184, buggy_cutoff),
            "with the bug, the cutoff is 0 so a real time-locked tx is wrongly non-final"
        );

        // Fixed cutoff (mtp_for_connect -> base_mtp).
        let fixed_cutoff = mtp_for_connect(&store, &base_hash, &params).unwrap_or(0);
        assert_eq!(fixed_cutoff, 1_775_650_208);
        assert!(
            is_final_tx(&tx, 944_184, fixed_cutoff),
            "with the fix, the cutoff is the real MTP so the tx is final \
             and block 944,184 can connect"
        );
    }

    #[test]
    fn mtp_for_connect_non_snapshot_parent_without_headers_is_none() {
        // A header-less parent that is NOT a snapshot base must still
        // yield `None` (no spurious base_mtp). Connect callers then
        // `.unwrap_or(0)`, which is correct genesis-adjacent behaviour.
        let (_dir, db) = mtp_test_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        assert_eq!(
            mtp_for_connect(&store, &Hash256([0x5a; 32]), &params),
            None
        );
    }

    #[test]
    fn mainnet_944183_assumeutxo_entry_has_base_mtp() {
        // Guards the chainparams constant the fix depends on.
        let params = ChainParams::mainnet();
        let d = params
            .assumeutxo_for_height(944_183)
            .expect("mainnet 944183 assumeutxo entry");
        assert_eq!(d.base_mtp, Some(1_775_650_208));
    }
}
