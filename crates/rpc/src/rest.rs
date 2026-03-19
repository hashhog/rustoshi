//! REST API for read-only blockchain queries.
//!
//! This module provides a REST API serving blockchain data in JSON, binary, and hex
//! formats without requiring authentication. The API is designed to be compatible
//! with Bitcoin Core's REST interface.
//!
//! # Endpoints
//!
//! - `GET /rest/block/<hash>.<format>` - Get block data
//! - `GET /rest/block/notxdetails/<hash>.<format>` - Get block without transaction details
//! - `GET /rest/headers/<count>/<hash>.<format>` - Get headers starting from hash
//! - `GET /rest/blockhashbyheight/<height>.<format>` - Get block hash at height
//! - `GET /rest/tx/<txid>.<format>` - Get transaction (requires txindex)
//! - `GET /rest/getutxos/<checkmempool>/<outpoint>...<format>` - Check UTXO status
//! - `GET /rest/mempool/info.json` - Mempool info
//! - `GET /rest/mempool/contents.json` - Mempool contents
//!
//! # Formats
//!
//! - `.json` - JSON format
//! - `.bin` - Binary format
//! - `.hex` - Hex-encoded binary

use crate::server::RpcState;
use crate::types::*;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use rustoshi_consensus::COIN;
use rustoshi_primitives::{BlockHeader, Encodable, Hash256, OutPoint, Transaction};
use rustoshi_storage::block_store::BlockStore;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum number of headers to return in a single request.
const MAX_REST_HEADERS_RESULTS: usize = 2000;

/// Maximum number of outpoints to query in getutxos.
const MAX_GETUTXOS_OUTPOINTS: usize = 15;

// ============================================================
// RESPONSE FORMAT
// ============================================================

/// REST response format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestFormat {
    /// JSON format.
    Json,
    /// Binary format.
    Binary,
    /// Hex-encoded binary.
    Hex,
}

impl RestFormat {
    /// Parse format from file extension.
    fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "json" => Some(Self::Json),
            "bin" => Some(Self::Binary),
            "hex" => Some(Self::Hex),
            _ => None,
        }
    }

    /// Get the content type for this format.
    fn content_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Binary => "application/octet-stream",
            Self::Hex => "text/plain",
        }
    }
}

/// Parse hash and format from a path like "hash.format".
fn parse_hash_and_format(param: &str) -> Result<(Hash256, RestFormat), RestError> {
    let (hash_str, format) = parse_param_and_format(param)?;
    let hash = Hash256::from_hex(hash_str).map_err(|_| RestError::InvalidHash)?;
    Ok((hash, format))
}

/// Parse parameter and format from a string like "param.format".
fn parse_param_and_format(param: &str) -> Result<(&str, RestFormat), RestError> {
    // Find the last dot for format extension
    let pos = param.rfind('.').ok_or(RestError::MissingFormat)?;
    let (value, ext) = param.split_at(pos);
    let ext = &ext[1..]; // Skip the dot
    let format = RestFormat::from_extension(ext).ok_or(RestError::InvalidFormat)?;
    Ok((value, format))
}

// ============================================================
// ERROR HANDLING
// ============================================================

/// REST API errors.
#[derive(Debug)]
pub enum RestError {
    /// Invalid hash format.
    InvalidHash,
    /// Missing format extension.
    MissingFormat,
    /// Invalid format extension.
    InvalidFormat,
    /// Block not found.
    BlockNotFound,
    /// Transaction not found.
    TxNotFound,
    /// Header not found.
    HeaderNotFound,
    /// Height out of range.
    HeightOutOfRange,
    /// Invalid height.
    InvalidHeight,
    /// Invalid count.
    InvalidCount,
    /// Too many outpoints.
    TooManyOutpoints,
    /// Invalid outpoint format.
    InvalidOutpoint,
    /// Database error.
    DatabaseError(String),
    /// JSON only endpoint.
    JsonOnly,
    /// Invalid URI.
    InvalidUri,
    /// Empty request.
    EmptyRequest,
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            RestError::InvalidHash => (StatusCode::BAD_REQUEST, "Invalid hash"),
            RestError::MissingFormat => (StatusCode::BAD_REQUEST, "Missing format extension"),
            RestError::InvalidFormat => {
                (StatusCode::NOT_FOUND, "Invalid format (available: .json, .bin, .hex)")
            }
            RestError::BlockNotFound => (StatusCode::NOT_FOUND, "Block not found"),
            RestError::TxNotFound => (StatusCode::NOT_FOUND, "Transaction not found"),
            RestError::HeaderNotFound => (StatusCode::NOT_FOUND, "Header not found"),
            RestError::HeightOutOfRange => (StatusCode::NOT_FOUND, "Block height out of range"),
            RestError::InvalidHeight => (StatusCode::BAD_REQUEST, "Invalid height"),
            RestError::InvalidCount => (StatusCode::BAD_REQUEST, "Invalid count"),
            RestError::TooManyOutpoints => (StatusCode::BAD_REQUEST, "Too many outpoints"),
            RestError::InvalidOutpoint => (StatusCode::BAD_REQUEST, "Invalid outpoint format"),
            RestError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            RestError::JsonOnly => (StatusCode::NOT_FOUND, "Only JSON format available"),
            RestError::InvalidUri => (StatusCode::BAD_REQUEST, "Invalid URI format"),
            RestError::EmptyRequest => (StatusCode::BAD_REQUEST, "Empty request"),
        };

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(format!("{}\r\n", message)))
            .unwrap()
    }
}

// ============================================================
// REST STATE
// ============================================================

/// Shared state for REST handlers.
pub struct RestState {
    /// Chain state (shared with RPC).
    pub rpc_state: Arc<RwLock<RpcState>>,
}

// ============================================================
// RESPONSE HELPERS
// ============================================================

/// Build a response with the given format.
fn build_response(data: &[u8], format: RestFormat) -> Response {
    let body = match format {
        RestFormat::Json => data.to_vec(),
        RestFormat::Binary => data.to_vec(),
        RestFormat::Hex => {
            let mut hex = hex::encode(data);
            hex.push('\n');
            hex.into_bytes()
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, format.content_type())
        .body(Body::from(body))
        .unwrap()
}

/// Build a JSON response.
fn json_response<T: Serialize>(value: &T) -> Response {
    let json = serde_json::to_string(value).unwrap() + "\n";
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap()
}

// ============================================================
// BLOCK ENDPOINTS
// ============================================================

/// GET /rest/block/<hash>.<format>
///
/// Returns the full block with transaction details.
async fn rest_block(
    State(state): State<Arc<RestState>>,
    Path(hash_with_format): Path<String>,
) -> Result<Response, RestError> {
    let (hash, format) = parse_hash_and_format(&hash_with_format)?;
    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    let block = store
        .get_block(&hash)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?
        .ok_or(RestError::BlockNotFound)?;

    match format {
        RestFormat::Binary => {
            let data = block.serialize();
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let data = block.serialize();
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            // Get block index entry for height and metadata
            let entry = store
                .get_block_index(&hash)
                .map_err(|e| RestError::DatabaseError(e.to_string()))?
                .ok_or(RestError::BlockNotFound)?;

            // Calculate confirmations
            let confirmations = if rpc_state.best_height >= entry.height {
                (rpc_state.best_height - entry.height + 1) as i32
            } else {
                0
            };

            // Get next block hash if available
            let next_hash = store
                .get_hash_by_height(entry.height + 1)
                .ok()
                .flatten()
                .map(|h| h.to_hex());

            let block_info = build_block_info(&block, &entry, confirmations, next_hash);
            Ok(json_response(&block_info))
        }
    }
}

/// GET /rest/block/notxdetails/<hash>.<format>
///
/// Returns the block without full transaction data (only txids).
async fn rest_block_notxdetails(
    State(state): State<Arc<RestState>>,
    Path(hash_with_format): Path<String>,
) -> Result<Response, RestError> {
    let (hash, format) = parse_hash_and_format(&hash_with_format)?;
    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    let block = store
        .get_block(&hash)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?
        .ok_or(RestError::BlockNotFound)?;

    match format {
        RestFormat::Binary => {
            let data = block.serialize();
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let data = block.serialize();
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            let entry = store
                .get_block_index(&hash)
                .map_err(|e| RestError::DatabaseError(e.to_string()))?
                .ok_or(RestError::BlockNotFound)?;

            let confirmations = if rpc_state.best_height >= entry.height {
                (rpc_state.best_height - entry.height + 1) as i32
            } else {
                0
            };

            let next_hash = store
                .get_hash_by_height(entry.height + 1)
                .ok()
                .flatten()
                .map(|h| h.to_hex());

            // For notxdetails, we only include txids, not full transaction info
            let block_info = build_block_info_simple(&block, &entry, confirmations, next_hash);
            Ok(json_response(&block_info))
        }
    }
}

// ============================================================
// HEADERS ENDPOINT
// ============================================================

/// GET /rest/headers/<count>/<hash>.<format>
///
/// Returns `count` headers starting from the given hash.
async fn rest_headers(
    State(state): State<Arc<RestState>>,
    Path(path): Path<String>,
) -> Result<Response, RestError> {
    // Parse path: <count>/<hash>.<format>
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(RestError::InvalidUri);
    }

    let count: usize = parts[0].parse().map_err(|_| RestError::InvalidCount)?;
    if count < 1 || count > MAX_REST_HEADERS_RESULTS {
        return Err(RestError::InvalidCount);
    }

    let (hash, format) = parse_hash_and_format(parts[1])?;
    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    // Collect headers starting from hash
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(count);
    let mut current_hash = hash;

    // Get the starting block's height
    let start_entry = store
        .get_block_index(&hash)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?
        .ok_or(RestError::HeaderNotFound)?;

    let mut height = start_entry.height;

    while headers.len() < count {
        if let Ok(Some(header)) = store.get_header(&current_hash) {
            headers.push(header);
            height += 1;
            // Get next block hash
            match store.get_hash_by_height(height) {
                Ok(Some(next_hash)) => current_hash = next_hash,
                _ => break,
            }
        } else {
            break;
        }
    }

    match format {
        RestFormat::Binary => {
            let mut data = Vec::new();
            for header in &headers {
                header.encode(&mut data).unwrap();
            }
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let mut data = Vec::new();
            for header in &headers {
                header.encode(&mut data).unwrap();
            }
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            let header_infos: Vec<RestHeaderInfo> = headers
                .iter()
                .enumerate()
                .map(|(i, header)| {
                    let h = start_entry.height + i as u32;
                    let confirmations = rpc_state.best_height.saturating_sub(h) + 1;
                    build_header_info(header, h, confirmations as i32)
                })
                .collect();
            Ok(json_response(&header_infos))
        }
    }
}

// ============================================================
// BLOCKHASHBYHEIGHT ENDPOINT
// ============================================================

/// GET /rest/blockhashbyheight/<height>.<format>
///
/// Returns the block hash at the given height.
async fn rest_blockhashbyheight(
    State(state): State<Arc<RestState>>,
    Path(height_with_format): Path<String>,
) -> Result<Response, RestError> {
    let (height_str, format) = parse_param_and_format(&height_with_format)?;
    let height: u32 = height_str.parse().map_err(|_| RestError::InvalidHeight)?;

    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    if height > rpc_state.best_height {
        return Err(RestError::HeightOutOfRange);
    }

    let hash = store
        .get_hash_by_height(height)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?
        .ok_or(RestError::HeightOutOfRange)?;

    match format {
        RestFormat::Binary => {
            Ok(build_response(hash.as_bytes(), format))
        }
        RestFormat::Hex => {
            // For hex format, return the display hex (reversed) + newline
            let hex = hash.to_hex() + "\n";
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(hex))
                .map_err(|_| RestError::DatabaseError("response build error".into()))
        }
        RestFormat::Json => {
            #[derive(Serialize)]
            struct BlockHashResponse {
                blockhash: String,
            }
            let resp = BlockHashResponse {
                blockhash: hash.to_hex(),
            };
            Ok(json_response(&resp))
        }
    }
}

// ============================================================
// TRANSACTION ENDPOINT
// ============================================================

/// GET /rest/tx/<txid>.<format>
///
/// Returns a transaction by txid.
async fn rest_tx(
    State(state): State<Arc<RestState>>,
    Path(txid_with_format): Path<String>,
) -> Result<Response, RestError> {
    let (txid, format) = parse_hash_and_format(&txid_with_format)?;
    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    // Check mempool first
    if let Some(entry) = rpc_state.mempool.get(&txid) {
        return format_transaction(&entry.tx, format, None, None);
    }

    // Check transaction index
    if let Ok(Some(tx_entry)) = store.get_tx_index(&txid) {
        // Load the block and find the transaction
        if let Ok(Some(block)) = store.get_block(&tx_entry.block_hash) {
            for tx in &block.transactions {
                if tx.txid() == txid {
                    let entry = store
                        .get_block_index(&tx_entry.block_hash)
                        .ok()
                        .flatten();
                    let height = entry.as_ref().map(|e| e.height);
                    return format_transaction(tx, format, Some(tx_entry.block_hash), height);
                }
            }
        }
    }

    Err(RestError::TxNotFound)
}

fn format_transaction(
    tx: &Transaction,
    format: RestFormat,
    block_hash: Option<Hash256>,
    height: Option<u32>,
) -> Result<Response, RestError> {
    match format {
        RestFormat::Binary => {
            let data = tx.serialize();
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let data = tx.serialize();
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            let tx_info = build_tx_info(tx, block_hash, height);
            Ok(json_response(&tx_info))
        }
    }
}

// ============================================================
// GETUTXOS ENDPOINT
// ============================================================

/// GET /rest/getutxos/<checkmempool>/<txid>-<n>/...<format>
///
/// Checks UTXO status for one or more outpoints.
async fn rest_getutxos(
    State(state): State<Arc<RestState>>,
    Path(path): Path<String>,
) -> Result<Response, RestError> {
    // Parse path parts
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() {
        return Err(RestError::EmptyRequest);
    }

    // Check if first part is "checkmempool"
    let (check_mempool, outpoint_parts) = if parts[0] == "checkmempool" {
        (true, &parts[1..])
    } else {
        (false, &parts[..])
    };

    if outpoint_parts.is_empty() {
        return Err(RestError::EmptyRequest);
    }

    // Last part contains format extension
    let last_idx = outpoint_parts.len() - 1;
    let (last_outpoint, format) = parse_param_and_format(outpoint_parts[last_idx])?;

    // Parse all outpoints
    let mut outpoints: Vec<OutPoint> = Vec::new();
    for (i, part) in outpoint_parts.iter().enumerate() {
        let outpoint_str = if i == last_idx { last_outpoint } else { *part };
        let outpoint = parse_outpoint(outpoint_str)?;
        outpoints.push(outpoint);
    }

    if outpoints.len() > MAX_GETUTXOS_OUTPOINTS {
        return Err(RestError::TooManyOutpoints);
    }

    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    // Check each outpoint
    let mut hits: Vec<bool> = Vec::with_capacity(outpoints.len());
    let mut utxos: Vec<UtxoInfo> = Vec::new();

    for outpoint in &outpoints {
        // Check if spent in mempool
        if check_mempool && rpc_state.mempool.is_spent(outpoint) {
            hits.push(false);
            continue;
        }

        // Check UTXO set
        match store.get_utxo(outpoint) {
            Ok(Some(coin)) => {
                hits.push(true);
                utxos.push(UtxoInfo {
                    height: coin.height,
                    value: coin.value as f64 / COIN as f64,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: disassemble_script(&coin.script_pubkey),
                        hex: hex::encode(&coin.script_pubkey),
                        script_type: detect_script_type(&coin.script_pubkey),
                        address: None, // Would need address encoding
                    },
                });
            }
            Ok(None) => {
                // Check mempool for unconfirmed outputs
                if check_mempool {
                    if let Some(tx_output) = rpc_state.mempool.get_utxo(outpoint) {
                        hits.push(true);
                        utxos.push(UtxoInfo {
                            height: 0, // Mempool
                            value: tx_output.value as f64 / COIN as f64,
                            script_pubkey: ScriptPubKeyInfo {
                                asm: disassemble_script(&tx_output.script_pubkey),
                                hex: hex::encode(&tx_output.script_pubkey),
                                script_type: detect_script_type(&tx_output.script_pubkey),
                                address: None,
                            },
                        });
                        continue;
                    }
                }
                hits.push(false);
            }
            Err(_) => {
                hits.push(false);
            }
        }
    }

    // Build bitmap string
    let bitmap_str: String = hits.iter().map(|&h| if h { '1' } else { '0' }).collect();

    // Build bitmap bytes
    let mut bitmap: Vec<u8> = vec![0u8; (hits.len() + 7) / 8];
    for (i, &hit) in hits.iter().enumerate() {
        if hit {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }

    match format {
        RestFormat::Binary => {
            let mut data = Vec::new();
            // Height (4 bytes LE)
            data.extend_from_slice(&rpc_state.best_height.to_le_bytes());
            // Chain tip hash (32 bytes)
            data.extend_from_slice(rpc_state.best_hash.as_bytes());
            // Bitmap
            data.extend_from_slice(&bitmap);
            // UTXOs (simplified binary format)
            for utxo in &utxos {
                data.extend_from_slice(&(utxo.height).to_le_bytes());
                let value_sats = (utxo.value * COIN as f64) as u64;
                data.extend_from_slice(&value_sats.to_le_bytes());
                let script_bytes = hex::decode(&utxo.script_pubkey.hex).unwrap_or_default();
                data.extend_from_slice(&(script_bytes.len() as u32).to_le_bytes());
                data.extend_from_slice(&script_bytes);
            }
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let mut data = Vec::new();
            data.extend_from_slice(&rpc_state.best_height.to_le_bytes());
            data.extend_from_slice(rpc_state.best_hash.as_bytes());
            data.extend_from_slice(&bitmap);
            for utxo in &utxos {
                data.extend_from_slice(&(utxo.height).to_le_bytes());
                let value_sats = (utxo.value * COIN as f64) as u64;
                data.extend_from_slice(&value_sats.to_le_bytes());
                let script_bytes = hex::decode(&utxo.script_pubkey.hex).unwrap_or_default();
                data.extend_from_slice(&(script_bytes.len() as u32).to_le_bytes());
                data.extend_from_slice(&script_bytes);
            }
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            #[derive(Serialize)]
            struct GetUtxosResponse {
                #[serde(rename = "chainHeight")]
                chain_height: u32,
                #[serde(rename = "chaintipHash")]
                chaintip_hash: String,
                bitmap: String,
                utxos: Vec<UtxoInfo>,
            }
            let resp = GetUtxosResponse {
                chain_height: rpc_state.best_height,
                chaintip_hash: rpc_state.best_hash.to_hex(),
                bitmap: bitmap_str,
                utxos,
            };
            Ok(json_response(&resp))
        }
    }
}

fn parse_outpoint(s: &str) -> Result<OutPoint, RestError> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(RestError::InvalidOutpoint);
    }
    let txid = Hash256::from_hex(parts[0]).map_err(|_| RestError::InvalidOutpoint)?;
    let vout: u32 = parts[1].parse().map_err(|_| RestError::InvalidOutpoint)?;
    Ok(OutPoint { txid, vout })
}

// ============================================================
// MEMPOOL ENDPOINTS
// ============================================================

/// GET /rest/mempool/info.json
///
/// Returns mempool information.
async fn rest_mempool_info(
    State(state): State<Arc<RestState>>,
) -> Result<Response, RestError> {
    let rpc_state = state.rpc_state.read().await;

    let info = RestMempoolInfo {
        loaded: true,
        size: rpc_state.mempool.size(),
        bytes: rpc_state.mempool.total_bytes(),
        usage: rpc_state.mempool.total_bytes(), // Simplified
        total_fee: rpc_state.mempool.total_fees() as f64 / COIN as f64,
        maxmempool: 300_000_000, // 300 MB default
        mempoolminfee: 0.00001,
        minrelaytxfee: 0.00001,
        unbroadcastcount: 0,
    };

    Ok(json_response(&info))
}

/// GET /rest/mempool/contents.json
///
/// Returns mempool contents.
async fn rest_mempool_contents(
    State(state): State<Arc<RestState>>,
) -> Result<Response, RestError> {
    let rpc_state = state.rpc_state.read().await;

    let sorted = rpc_state.mempool.get_sorted_for_mining();
    let mut result: HashMap<String, RestMempoolEntry> = HashMap::new();

    for txid in sorted {
        if let Some(entry) = rpc_state.mempool.get(&txid) {
            result.insert(
                txid.to_hex(),
                RestMempoolEntry {
                    vsize: entry.vsize as u32,
                    weight: entry.weight as u32,
                    fee: entry.fee as f64 / COIN as f64,
                    modifiedfee: entry.fee as f64 / COIN as f64,
                    time: entry.time_added.elapsed().as_secs(),
                    height: rpc_state.best_height,
                    descendantcount: entry.descendant_count as u32,
                    descendantsize: entry.descendant_size as u32,
                    descendantfees: entry.descendant_fees,
                    ancestorcount: entry.ancestor_count as u32,
                    ancestorsize: entry.ancestor_size as u32,
                    ancestorfees: entry.ancestor_fees,
                    wtxid: entry.tx.wtxid().to_hex(),
                    depends: vec![],
                    spentby: vec![],
                },
            );
        }
    }

    Ok(json_response(&result))
}

// ============================================================
// HELPER TYPES
// ============================================================

/// UTXO information for getutxos response.
#[derive(Debug, Serialize)]
struct UtxoInfo {
    height: u32,
    value: f64,
    #[serde(rename = "scriptPubKey")]
    script_pubkey: ScriptPubKeyInfo,
}

/// Header information for REST response.
#[derive(Debug, Serialize)]
struct RestHeaderInfo {
    hash: String,
    confirmations: i32,
    height: u32,
    version: i32,
    #[serde(rename = "versionHex")]
    version_hex: String,
    merkleroot: String,
    time: u32,
    nonce: u32,
    bits: String,
    difficulty: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previousblockhash: Option<String>,
}

/// Mempool info for REST response.
#[derive(Debug, Serialize)]
struct RestMempoolInfo {
    loaded: bool,
    size: usize,
    bytes: usize,
    usage: usize,
    total_fee: f64,
    maxmempool: usize,
    mempoolminfee: f64,
    minrelaytxfee: f64,
    unbroadcastcount: usize,
}

/// Mempool entry for REST response.
#[derive(Debug, Serialize)]
struct RestMempoolEntry {
    vsize: u32,
    weight: u32,
    fee: f64,
    modifiedfee: f64,
    time: u64,
    height: u32,
    descendantcount: u32,
    descendantsize: u32,
    descendantfees: u64,
    ancestorcount: u32,
    ancestorsize: u32,
    ancestorfees: u64,
    wtxid: String,
    depends: Vec<String>,
    spentby: Vec<String>,
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Calculate block weight and stripped size from transactions.
/// Returns (weight, stripped_size).
fn calculate_block_weight(block: &rustoshi_primitives::Block) -> (u32, u32) {
    // Block header is 80 bytes, tx count is varint
    let header_size = 80;
    let tx_count_size = compact_size_len(block.transactions.len() as u64);

    // Calculate total weight and stripped size from all transactions
    let mut total_weight: usize = 0;
    let mut total_stripped_size: usize = 0;

    for tx in &block.transactions {
        total_weight += tx.weight();
        total_stripped_size += tx.base_size();
    }

    // Block weight = header_weight + tx_count_weight + tx_weights
    // Header and tx count are non-witness data, so they get weight of 4 per byte
    let header_weight = (header_size + tx_count_size) * 4;
    let weight = header_weight + total_weight;

    // Stripped size = header + tx_count + sum of tx base sizes (no witness)
    let stripped_size = header_size + tx_count_size + total_stripped_size;

    (weight as u32, stripped_size as u32)
}

/// Get the length of a varint-encoded compact size.
fn compact_size_len(n: u64) -> usize {
    if n < 0xFD {
        1
    } else if n <= 0xFFFF {
        3
    } else if n <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

fn build_block_info(
    block: &rustoshi_primitives::Block,
    entry: &rustoshi_storage::block_store::BlockIndexEntry,
    confirmations: i32,
    next_hash: Option<String>,
) -> BlockInfo {
    let header = &block.header;
    let hash = header.block_hash();

    // Calculate sizes
    let serialized = block.serialize();
    let size = serialized.len() as u32;
    // Calculate block weight and stripped size from transactions
    let (weight, stripped_size) = calculate_block_weight(block);

    BlockInfo {
        hash: hash.to_hex(),
        confirmations,
        size,
        strippedsize: stripped_size,
        weight,
        height: entry.height,
        version: header.version,
        version_hex: format!("{:08x}", header.version),
        merkleroot: header.merkle_root.to_hex(),
        tx: block.transactions.iter().map(|tx| tx.txid().to_hex()).collect(),
        time: header.timestamp,
        mediantime: header.timestamp as u64, // Simplified
        nonce: header.nonce,
        bits: format!("{:08x}", header.bits),
        difficulty: bits_to_difficulty(header.bits),
        chainwork: hex::encode(&entry.chain_work),
        n_tx: block.transactions.len() as u32,
        previousblockhash: if entry.height > 0 {
            Some(header.prev_block_hash.to_hex())
        } else {
            None
        },
        nextblockhash: next_hash,
    }
}

fn build_block_info_simple(
    block: &rustoshi_primitives::Block,
    entry: &rustoshi_storage::block_store::BlockIndexEntry,
    confirmations: i32,
    next_hash: Option<String>,
) -> BlockInfo {
    // Same as build_block_info but only txids (no transaction details)
    // For REST notxdetails endpoint, this is the same since we already only return txids
    build_block_info(block, entry, confirmations, next_hash)
}

fn build_header_info(header: &BlockHeader, height: u32, confirmations: i32) -> RestHeaderInfo {
    let hash = header.block_hash();
    RestHeaderInfo {
        hash: hash.to_hex(),
        confirmations,
        height,
        version: header.version,
        version_hex: format!("{:08x}", header.version),
        merkleroot: header.merkle_root.to_hex(),
        time: header.timestamp,
        nonce: header.nonce,
        bits: format!("{:08x}", header.bits),
        difficulty: bits_to_difficulty(header.bits),
        previousblockhash: if height > 0 {
            Some(header.prev_block_hash.to_hex())
        } else {
            None
        },
    }
}

fn build_tx_info(tx: &Transaction, block_hash: Option<Hash256>, height: Option<u32>) -> RestTxInfo {
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    let serialized = tx.serialize();

    RestTxInfo {
        txid: txid.to_hex(),
        hash: wtxid.to_hex(),
        version: tx.version,
        size: serialized.len() as u32,
        vsize: tx.vsize() as u32,
        weight: tx.weight() as u32,
        locktime: tx.lock_time,
        vin: tx
            .inputs
            .iter()
            .map(|input| {
                if input.previous_output.txid == Hash256::ZERO {
                    // Coinbase
                    RestTxInput {
                        coinbase: Some(hex::encode(&input.script_sig)),
                        txid: None,
                        vout: None,
                        script_sig: None,
                        txinwitness: if !input.witness.is_empty() {
                            Some(input.witness.iter().map(|w| hex::encode(w)).collect())
                        } else {
                            None
                        },
                        sequence: input.sequence,
                    }
                } else {
                    RestTxInput {
                        coinbase: None,
                        txid: Some(input.previous_output.txid.to_hex()),
                        vout: Some(input.previous_output.vout),
                        script_sig: Some(RestScriptSig {
                            asm: disassemble_script(&input.script_sig),
                            hex: hex::encode(&input.script_sig),
                        }),
                        txinwitness: if !input.witness.is_empty() {
                            Some(input.witness.iter().map(|w| hex::encode(w)).collect())
                        } else {
                            None
                        },
                        sequence: input.sequence,
                    }
                }
            })
            .collect(),
        vout: tx
            .outputs
            .iter()
            .enumerate()
            .map(|(n, output)| RestTxOutput {
                value: output.value as f64 / COIN as f64,
                n: n as u32,
                script_pubkey: ScriptPubKeyInfo {
                    asm: disassemble_script(&output.script_pubkey),
                    hex: hex::encode(&output.script_pubkey),
                    script_type: detect_script_type(&output.script_pubkey),
                    address: None,
                },
            })
            .collect(),
        hex: hex::encode(&serialized),
        blockhash: block_hash.map(|h| h.to_hex()),
        confirmations: height.map(|_| 1), // Simplified
        blocktime: None,
        time: None,
    }
}

/// REST transaction info response.
#[derive(Debug, Serialize)]
struct RestTxInfo {
    txid: String,
    hash: String,
    version: i32,
    size: u32,
    vsize: u32,
    weight: u32,
    locktime: u32,
    vin: Vec<RestTxInput>,
    vout: Vec<RestTxOutput>,
    hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocktime: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<u32>,
}

#[derive(Debug, Serialize)]
struct RestTxInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    coinbase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vout: Option<u32>,
    #[serde(rename = "scriptSig", skip_serializing_if = "Option::is_none")]
    script_sig: Option<RestScriptSig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txinwitness: Option<Vec<String>>,
    sequence: u32,
}

#[derive(Debug, Serialize)]
struct RestScriptSig {
    asm: String,
    hex: String,
}

#[derive(Debug, Serialize)]
struct RestTxOutput {
    value: f64,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pubkey: ScriptPubKeyInfo,
}

/// Calculate difficulty from compact target (bits).
fn bits_to_difficulty(bits: u32) -> f64 {
    let genesis_bits = 0x1d00ffffu32;
    let current_target = compact_to_target_f64(bits);
    let genesis_target = compact_to_target_f64(genesis_bits);
    if current_target == 0.0 {
        return 0.0;
    }
    genesis_target / current_target
}

fn compact_to_target_f64(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x007FFFFF) as f64;
    if exponent <= 3 {
        mantissa / (1u64 << (8 * (3 - exponent))) as f64
    } else {
        mantissa * 2f64.powi(8 * (exponent - 3))
    }
}

/// Detect script type from scriptPubKey.
fn detect_script_type(script: &[u8]) -> String {
    match script.len() {
        22 if script.starts_with(&[0x00, 0x14]) => "witness_v0_keyhash".to_string(),
        34 if script.starts_with(&[0x00, 0x20]) => "witness_v0_scripthash".to_string(),
        34 if script.starts_with(&[0x51, 0x20]) => "witness_v1_taproot".to_string(),
        25 if script.starts_with(&[0x76, 0xa9, 0x14]) && script.ends_with(&[0x88, 0xac]) => {
            "pubkeyhash".to_string()
        }
        23 if script.starts_with(&[0xa9, 0x14]) && script.ends_with(&[0x87]) => {
            "scripthash".to_string()
        }
        _ if !script.is_empty() && script[0] == 0x6a => "nulldata".to_string(),
        _ => "nonstandard".to_string(),
    }
}

/// Disassemble script to human-readable form.
fn disassemble_script(script: &[u8]) -> String {
    // Simplified disassembly
    if script.is_empty() {
        return String::new();
    }

    let mut result = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];
        i += 1;

        match opcode {
            0x00 => result.push("0".to_string()),
            0x4c => {
                // OP_PUSHDATA1
                if i < script.len() {
                    let len = script[i] as usize;
                    i += 1;
                    if i + len <= script.len() {
                        result.push(hex::encode(&script[i..i + len]));
                        i += len;
                    }
                }
            }
            0x4d => {
                // OP_PUSHDATA2
                if i + 2 <= script.len() {
                    let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                    i += 2;
                    if i + len <= script.len() {
                        result.push(hex::encode(&script[i..i + len]));
                        i += len;
                    }
                }
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 4 <= script.len() {
                    let len = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                        as usize;
                    i += 4;
                    if i + len <= script.len() {
                        result.push(hex::encode(&script[i..i + len]));
                        i += len;
                    }
                }
            }
            0x51..=0x60 => result.push(format!("OP_{}", opcode - 0x50)),
            0x76 => result.push("OP_DUP".to_string()),
            0x87 => result.push("OP_EQUAL".to_string()),
            0x88 => result.push("OP_EQUALVERIFY".to_string()),
            0xa9 => result.push("OP_HASH160".to_string()),
            0xac => result.push("OP_CHECKSIG".to_string()),
            0x6a => result.push("OP_RETURN".to_string()),
            0x01..=0x4b => {
                // Direct push
                let len = opcode as usize;
                if i + len <= script.len() {
                    result.push(hex::encode(&script[i..i + len]));
                    i += len;
                }
            }
            _ => result.push(format!("OP_UNKNOWN_{:02x}", opcode)),
        }
    }

    result.join(" ")
}

// ============================================================
// ROUTER
// ============================================================

/// Create the REST API router.
pub fn rest_router(rpc_state: Arc<RwLock<RpcState>>) -> Router {
    let state = Arc::new(RestState { rpc_state });

    Router::new()
        .route("/rest/block/{hash_format}", get(rest_block))
        .route("/rest/block/notxdetails/{hash_format}", get(rest_block_notxdetails))
        .route("/rest/headers/{path:.*}", get(rest_headers))
        .route("/rest/blockhashbyheight/{height_format}", get(rest_blockhashbyheight))
        .route("/rest/tx/{txid_format}", get(rest_tx))
        .route("/rest/getutxos/{path:.*}", get(rest_getutxos))
        .route("/rest/mempool/info.json", get(rest_mempool_info))
        .route("/rest/mempool/contents.json", get(rest_mempool_contents))
        .with_state(state)
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_and_format() {
        let hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

        // JSON format
        let input = format!("{}.json", hash);
        let (parsed_hash, format) = parse_hash_and_format(&input).unwrap();
        assert_eq!(parsed_hash.to_hex(), hash);
        assert_eq!(format, RestFormat::Json);

        // Binary format
        let input = format!("{}.bin", hash);
        let (parsed_hash, format) = parse_hash_and_format(&input).unwrap();
        assert_eq!(parsed_hash.to_hex(), hash);
        assert_eq!(format, RestFormat::Binary);

        // Hex format
        let input = format!("{}.hex", hash);
        let (parsed_hash, format) = parse_hash_and_format(&input).unwrap();
        assert_eq!(parsed_hash.to_hex(), hash);
        assert_eq!(format, RestFormat::Hex);
    }

    #[test]
    fn test_parse_param_and_format() {
        let (param, format) = parse_param_and_format("12345.json").unwrap();
        assert_eq!(param, "12345");
        assert_eq!(format, RestFormat::Json);

        let (param, format) = parse_param_and_format("0.bin").unwrap();
        assert_eq!(param, "0");
        assert_eq!(format, RestFormat::Binary);
    }

    #[test]
    fn test_parse_outpoint() {
        let txid = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let outpoint = parse_outpoint(&format!("{}-0", txid)).unwrap();
        assert_eq!(outpoint.txid.to_hex(), txid);
        assert_eq!(outpoint.vout, 0);

        let outpoint = parse_outpoint(&format!("{}-42", txid)).unwrap();
        assert_eq!(outpoint.vout, 42);
    }

    #[test]
    fn test_detect_script_type() {
        // P2WPKH: OP_0 <20 bytes>
        let p2wpkh = hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(detect_script_type(&p2wpkh), "witness_v0_keyhash");

        // P2WSH: OP_0 <32 bytes>
        let p2wsh = hex::decode("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d").unwrap();
        assert_eq!(detect_script_type(&p2wsh), "witness_v0_scripthash");

        // P2TR: OP_1 <32 bytes>
        let p2tr = hex::decode("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c").unwrap();
        assert_eq!(detect_script_type(&p2tr), "witness_v1_taproot");

        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let p2pkh = hex::decode("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac").unwrap();
        assert_eq!(detect_script_type(&p2pkh), "pubkeyhash");

        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        let p2sh = hex::decode("a914751e76e8199196d454941c45d1b3a323f1433bd687").unwrap();
        assert_eq!(detect_script_type(&p2sh), "scripthash");

        // OP_RETURN
        let op_return = hex::decode("6a0568656c6c6f").unwrap();
        assert_eq!(detect_script_type(&op_return), "nulldata");
    }

    #[test]
    fn test_bits_to_difficulty() {
        // Genesis difficulty
        let diff = bits_to_difficulty(0x1d00ffff);
        assert!((diff - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_rest_format_content_type() {
        assert_eq!(RestFormat::Json.content_type(), "application/json");
        assert_eq!(RestFormat::Binary.content_type(), "application/octet-stream");
        assert_eq!(RestFormat::Hex.content_type(), "text/plain");
    }

    #[test]
    fn test_disassemble_script() {
        // P2PKH script
        let script = hex::decode("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac").unwrap();
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_DUP"));
        assert!(asm.contains("OP_HASH160"));
        assert!(asm.contains("OP_EQUALVERIFY"));
        assert!(asm.contains("OP_CHECKSIG"));
    }
}
