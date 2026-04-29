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
use tokio::io::AsyncWriteExt;

use rustoshi_consensus::{get_block_proof, ChainParams, ChainState, ChainWork, FeeEstimator, NetworkId};
use rustoshi_network::{
    BlockDownloader, HeaderSync, InvType, InvVector, MisbehaviorReason, NetworkMessage, PeerEvent,
    PeerManager, PeerManagerConfig,
};
use rustoshi_primitives::{Hash256, OutPoint};
use rustoshi_rpc::{start_rpc_server, PeerState, RpcConfig, RpcState};
use rustoshi_storage::{block_store::{BlockIndexEntry, BlockStatus}, BlockStore, ChainDb};

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

    /// Listen for incoming P2P connections
    #[arg(long, default_value = "true")]
    listen: bool,

    /// Advertise NODE_BLOOM (BIP 37) and serve BIP 35 mempool requests.
    /// Mirrors Bitcoin Core's `-peerbloomfilters` (default: enabled).
    #[arg(long, default_value = "true")]
    peerbloomfilters: bool,

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
            // Read the HTTP request (we don't need to parse it, just consume it)
            let mut buf = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

            // Gather metrics from state
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

        // Validate and process
        match chain_state.process_block(&block, utxo_view) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Block validation failed at height {}: {}", height, e);
                break;
            }
        }

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

        // Validate and process
        match chain_state.process_block(&block, utxo_view) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Block validation failed at height {}: {}", frame_height, e);
                break;
            }
        }

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.loglevel));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    tracing::info!("Rustoshi v{}", env!("CARGO_PKG_VERSION"));

    // Resolve network
    let params = match cli.network.as_str() {
        "mainnet" | "main" => ChainParams::mainnet(),
        "testnet3" | "testnet" => ChainParams::testnet3(),
        "testnet4" => ChainParams::testnet4(),
        "signet" => ChainParams::signet(),
        "regtest" => ChainParams::regtest(),
        _ => anyhow::bail!("Unknown network: {}", cli.network),
    };

    tracing::info!("Network: {:?}", params.network_id);
    tracing::info!("Genesis: {}", params.genesis_hash);

    // Handle subcommands
    if let Some(cmd) = &cli.command {
        match cmd {
            Commands::Reindex => {
                tracing::info!("Reindex requested - not yet implemented");
                return Ok(());
            }
            Commands::Resync => {
                tracing::info!("Resync requested - not yet implemented");
                return Ok(());
            }
        }
    }

    // Resolve data directories — base (for cookie file) and network-specific
    // (for chainstate, blocks, etc.)
    let base_datadir = resolve_base_datadir(&cli.datadir);
    std::fs::create_dir_all(&base_datadir)?;
    let datadir = resolve_datadir(&cli.datadir, &params);
    std::fs::create_dir_all(&datadir)?;
    tracing::info!("Data directory: {}", datadir.display());

    // Open database
    let db_path = datadir.join("chainstate");
    let db = Arc::new(ChainDb::open(&db_path)?);
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
    let best_hash = block_store.get_best_block_hash()?.unwrap();
    let stored_height = block_store.get_best_height()?.unwrap();

    // Try to find the actual height by looking up the best hash in the height index
    let best_height = {
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

        return Ok(());
    }

    // Initialize chain state for local block processing
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        best_hash,
        best_height,
        params.clone(),
    )));

    // Determine RPC bind address with appropriate port
    let rpc_bind = if cli.rpcbind == "127.0.0.1:8332" {
        // Use default, adjust port based on network
        format!("127.0.0.1:{}", default_rpc_port(params.network_id))
    } else {
        cli.rpcbind.clone()
    };

    // Initialize RPC state
    let mut rpc_state_inner = RpcState::new(db.clone(), params.clone());
    rpc_state_inner.init_from_db().map_err(|e| anyhow::anyhow!(e))?;

    // Load persisted fee estimates if available
    let fee_estimates_path = datadir.join("fee_estimates.json");
    let loaded_estimator = FeeEstimator::load(&fee_estimates_path);
    if loaded_estimator.current_height() > 0 {
        tracing::info!("Loaded fee estimates from disk (height {})", loaded_estimator.current_height());
    }
    rpc_state_inner.fee_estimator = loaded_estimator;

    let rpc_state = Arc::new(RwLock::new(rpc_state_inner));

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
    };
    let rpc_handle = start_rpc_server(rpc_config, rpc_state.clone(), peer_state.clone()).await?;
    tracing::info!("RPC server listening on {}", rpc_bind);

    // Start Prometheus metrics server
    tokio::spawn(start_metrics_server(
        cli.metrics_port,
        rpc_state.clone(),
        peer_state.clone(),
    ));

    // Configure peer manager
    let peer_config = PeerManagerConfig {
        max_outbound_full_relay: cli.maxconnections.saturating_sub(2),
        max_outbound_block_relay: 2, // Block-relay-only anchors for eclipse resistance
        listen_port: cli.port.unwrap_or(params.default_port),
        listen: cli.listen,
        peer_bloom_filters: cli.peerbloomfilters,
        data_dir: datadir.clone(),
        ..Default::default()
    };
    let mut peer_manager = PeerManager::new(peer_config, params.clone());
    peer_manager.set_start_height(best_height as i32);

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

    // Initialize header sync and block download
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

    // UTXO cache for block validation, bounded to 2 GiB
    let mut utxo_view = block_store.utxo_view();

    // ============================================================
    // MAIN EVENT LOOP
    // ============================================================
    //
    // The event_rx was taken from PeerManager before it was moved into PeerState.
    // We poll event_rx directly here without holding any locks. When we need to
    // interact with the peer manager (send_to_peer, handle_event), we briefly
    // acquire the peer_state lock.
    let mut block_retry_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    block_retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Fast validation timer — fires every 100ms to process buffered blocks.
    // This ensures block validation is never starved by a stream of peer
    // messages in the select loop.  The 10s retry timer handles download
    // retries and timeouts; this timer handles validation throughput.
    let mut validation_interval = tokio::time::interval(std::time::Duration::from_millis(100));
    validation_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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

                    {
                        let mut cs = chain_state.write().await;
                        if let Err(e) = cs.process_block(&block, &mut utxo_view) {
                            tracing::warn!(
                                "Block validation failed at height {}: {}",
                                height, e
                            );
                        }
                    }

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

                    if let Err(e) = block_store.set_best_block(&block_hash, height) {
                        tracing::error!("Failed to update best block: {}", e);
                    }

                    {
                        let mut rpc = rpc_state.write().await;
                        if height > rpc.best_height {
                            rpc.best_height = height;
                            rpc.best_hash = block_hash;
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
                    Some(PeerEvent::Connected(peer_id, info)) => {
                        // Register inbound peer handle in PeerManager
                        {
                            let mut ps = peer_state.write().await;
                            if let Some(ref mut pm) = ps.peer_manager {
                                pm.handle_event(PeerEvent::Connected(peer_id, info.clone())).await;
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
                                let need_more = header_sync.process_headers(
                                    peer_id,
                                    headers,
                                    &mut |header, height| {
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
                                        // Begin block download (only for blocks above our tip)
                                        // Use best_header_height to avoid re-enqueuing already-queued blocks
                                        let old_best = std::cmp::max(
                                            block_downloader.best_header_height(),
                                            block_downloader.validated_tip_height(),
                                        );
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

                                        // Score misbehavior based on the error type
                                        {
                                            let mut ps = peer_state.write().await;
                                            if let Some(ref mut pm) = ps.peer_manager {
                                                if e.contains("not connected") || e.contains("not in our chain") {
                                                    pm.misbehaving(peer_id, MisbehaviorReason::HeadersDontConnect).await;
                                                } else if e.contains("proof of work") {
                                                    pm.misbehaving(peer_id, MisbehaviorReason::InvalidBlockHeader).await;
                                                }
                                            }
                                        }

                                        // When the first header doesn't connect to our tip,
                                        // the peer may have reorged or we're on a stale fork.
                                        // Re-request headers with a full block locator so the
                                        // peer can find our fork point (like Bitcoin Core's
                                        // FindForkInGlobalIndex behavior).
                                        if e.contains("not in our chain") {
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

                                    // Validate block and update UTXO set
                                    {
                                        let mut cs = chain_state.write().await;
                                        if let Err(e) = cs.process_block(&block, &mut utxo_view) {
                                            tracing::warn!(
                                                "Block validation failed at height {}: {}",
                                                height, e
                                            );
                                        }
                                    }

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

                                    // Flush UTXO cache if it exceeds the 2 GiB limit
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
                                    if let Err(e) = block_store.set_best_block(&block_hash, height) {
                                        tracing::error!("Failed to update best block: {}", e);
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

                                        // Clear recently-rejected filter -- rejection reasons
                                        // may no longer apply after a new block
                                        rpc.recently_rejected.clear();
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
                                let mut rpc = rpc_state.write().await;
                                match rpc.mempool.add_transaction(tx, &|outpoint| {
                                    // Look up UTXO from storage
                                    block_store.get_utxo(outpoint).ok().flatten().map(|coin| {
                                        rustoshi_consensus::CoinEntry {
                                            height: coin.height,
                                            is_coinbase: coin.is_coinbase,
                                            value: coin.value,
                                            script_pubkey: coin.script_pubkey,
                                        }
                                    })
                                }) {
                                    Ok(_) => {
                                        tracing::debug!("Added tx {} to mempool", txid);
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
                                        let mempool_txns = {
                                            let rpc = rpc_state.read().await;
                                            rpc.mempool.collect_for_compact_block()
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
                                                    match partial.fill_block(vec![]) {
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
                                use rustoshi_network::BlockTxn;
                                match BlockTxn::deserialize(&data) {
                                    Ok(blocktxn) => {
                                        tracing::debug!(
                                            "Received blocktxn for {} from peer {} ({} txns)",
                                            blocktxn.block_hash, peer_id.0, blocktxn.transactions.len()
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to decode blocktxn from peer {}: {}", peer_id.0, e);
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
                        let mut ps = peer_state.write().await;
                        if let Some(ref mut pm) = ps.peer_manager {
                            pm.handle_event(PeerEvent::Disconnected(peer_id, reason)).await;
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

            // Handle shutdown signal (Ctrl+C)
            _ = signal::ctrl_c() => {
                tracing::info!("Received shutdown signal (Ctrl+C)");
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

    // Flush UTXO cache to disk
    if utxo_view.cache_len() > 0 {
        let entries = utxo_view.cache_len();
        let mem_mb = utxo_view.estimated_memory() / (1024 * 1024);
        match utxo_view.flush() {
            Ok(()) => tracing::info!("UTXO cache flushed on shutdown: {} entries, ~{} MiB", entries, mem_mb),
            Err(e) => tracing::error!("Failed to flush UTXO cache on shutdown: {}", e),
        }
    }

    // Flush chain state
    {
        let cs = chain_state.read().await;
        let _ = block_store.set_best_block(&cs.tip_hash(), cs.tip_height());
        tracing::debug!(
            "Chain state flushed: {} at height {}",
            cs.tip_hash(),
            cs.tip_height()
        );
    }

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
}
