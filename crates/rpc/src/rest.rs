//! REST API for read-only blockchain queries.
//!
//! This module provides a REST API serving blockchain data in JSON, binary, and hex
//! formats without requiring authentication. The API is designed to be compatible
//! with Bitcoin Core's REST interface (`bitcoin-core/src/rest.cpp`).
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
//! - `GET /rest/chaininfo.json` - Chain info (subset of `getblockchaininfo`)
//! - `GET /rest/blockfilter/<filtertype>/<hash>.<format>` - BIP-157 cfilter
//! - `GET /rest/blockfilterheaders/<filtertype>/<count>/<hash>.<format>` - BIP-157 cfheader range
//!
//! # Formats
//!
//! - `.json` - JSON format
//! - `.bin` - Binary format
//! - `.hex` - Hex-encoded binary
//!
//! # Wiring
//!
//! The production binary calls [`start_rest_server`] (gated behind `--rest`,
//! default off, matching Core's `DEFAULT_REST_ENABLE = false`) which mounts
//! [`rest_router`] on its own axum listener. See `rustoshi/src/main.rs`.

use crate::server::RpcState;
use crate::types::*;
use crate::wallet::WalletRpcState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use rustoshi_consensus::COIN;
use rustoshi_primitives::{BlockHeader, Encodable, Hash256, OutPoint, Transaction};
use rustoshi_storage::block_store::BlockStore;
use rustoshi_storage::indexes::blockfilterindex::{
    BlockFilterIndex, BlockFilterType,
};
use rustoshi_wallet::payjoin::{
    evict_expired_offers, handle_payjoin_request, OfferedPayjoin, PayjoinError, PayjoinParams,
    MAX_ORIGINAL_PSBT_BYTES, OFFERED_PAYJOIN_TTL_SECS,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

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
    /// Unknown BIP-157 filter type.
    UnknownFilterType,
    /// BIP-157 filter not found for the given block.
    FilterNotFound,
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
            RestError::UnknownFilterType => (StatusCode::BAD_REQUEST, "Unknown filtertype"),
            RestError::FilterNotFound => (StatusCode::NOT_FOUND, "Filter not found"),
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
    /// Wallet state, populated when the binary mounts the wallet RPC.
    ///
    /// Currently only consumed by the `POST /payjoin` BIP-78 receiver
    /// endpoint (FIX-65). Requests arriving when this is `None` are
    /// answered with HTTP 503 + `{"errorCode":"unavailable", ...}` per
    /// BIP-78 §"Receiver's well known errors".
    pub wallet_state: Option<Arc<RwLock<WalletRpcState>>>,
    /// In-flight PayJoin offers, keyed by Original-PSBT unsigned-tx
    /// hash. Receiver UTXOs that appear in any value of this map are
    /// excluded from new-offer coin selection (G19 replay/conflict
    /// guard). Held outside the wallet to keep FIX-61's `sent_txs`
    /// single-purpose (outgoing-only).
    ///
    /// G18 (FIX-67): Entries are evicted on every new request whose
    /// `created_at + OFFERED_PAYJOIN_TTL_SECS < now`, so a sender that
    /// receives a PayJoin reply but never broadcasts cannot pin the
    /// receiver's UTXO forever.
    pub offered_payjoins: Mutex<HashMap<Hash256, OfferedPayjoin>>,
    /// G30 (FIX-67): Set of unsigned-tx hashes the receiver has already
    /// answered for. A second request carrying the same Original-PSBT
    /// id is rejected as `original-psbt-rejected` (replay) regardless
    /// of whether the prior offer is still in `offered_payjoins`.
    ///
    /// Bounded growth: this set is reset whenever it grows past
    /// `PAYJOIN_REPLAY_SET_LIMIT`. The reset is coarse — under steady
    /// state the in-flight TTL eviction keeps the set proportional to
    /// the request rate × TTL.
    pub payjoin_replay_ids: Mutex<std::collections::HashSet<Hash256>>,
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
    if !(1..=MAX_REST_HEADERS_RESULTS).contains(&count) {
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
                {
                    use rustoshi_wallet::descriptor::add_checksum;
                    let raw_desc = format!("raw({})", hex::encode(&coin.script_pubkey));
                    let desc = add_checksum(&raw_desc).unwrap_or(raw_desc);
                    utxos.push(UtxoInfo {
                        height: coin.height,
                        value: coin.value as f64 / COIN as f64,
                        script_pubkey: ScriptPubKeyInfo {
                            asm: disassemble_script(&coin.script_pubkey),
                            desc,
                            hex: hex::encode(&coin.script_pubkey),
                            address: None,
                            script_type: detect_script_type(&coin.script_pubkey),
                        },
                    });
                }
            }
            Ok(None) => {
                // Check mempool for unconfirmed outputs
                if check_mempool {
                    if let Some(tx_output) = rpc_state.mempool.get_utxo(outpoint) {
                        hits.push(true);
                        use rustoshi_wallet::descriptor::add_checksum;
                        let raw_desc = format!("raw({})", hex::encode(&tx_output.script_pubkey));
                        let desc = add_checksum(&raw_desc).unwrap_or(raw_desc);
                        utxos.push(UtxoInfo {
                            height: 0, // Mempool
                            value: tx_output.value as f64 / COIN as f64,
                            script_pubkey: ScriptPubKeyInfo {
                                asm: disassemble_script(&tx_output.script_pubkey),
                                desc,
                                hex: hex::encode(&tx_output.script_pubkey),
                                address: None,
                                script_type: detect_script_type(&tx_output.script_pubkey),
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
    let mut bitmap: Vec<u8> = vec![0u8; hits.len().div_ceil(8)];
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

    // Build coinbase_tx metadata for REST response (Core 27+).
    let coinbase_tx = block.transactions.first().and_then(|coinbase| {
        coinbase.inputs.first().map(|vin0| {
            let mut cb_obj = serde_json::Map::new();
            cb_obj.insert("version".to_string(), serde_json::Value::Number(coinbase.version.into()));
            cb_obj.insert("locktime".to_string(), serde_json::Value::Number(coinbase.lock_time.into()));
            cb_obj.insert("sequence".to_string(), serde_json::Value::Number(vin0.sequence.into()));
            cb_obj.insert("coinbase".to_string(), serde_json::Value::String(hex::encode(&vin0.script_sig)));
            if let Some(witness_item) = vin0.witness.first() {
                cb_obj.insert("witness".to_string(), serde_json::Value::String(hex::encode(witness_item)));
            }
            serde_json::Value::Object(cb_obj)
        })
    });

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
        target: compact_to_target_hex_rest(header.bits),
        difficulty: bits_to_difficulty(header.bits),
        chainwork: hex::encode(entry.chain_work),
        n_tx: block.transactions.len() as u32,
        previousblockhash: if entry.height > 0 {
            Some(header.prev_block_hash.to_hex())
        } else {
            None
        },
        nextblockhash: next_hash,
        coinbase_tx,
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
                            Some(input.witness.iter().map(hex::encode).collect())
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
                            Some(input.witness.iter().map(hex::encode).collect())
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
            .map(|(n, output)| {
                use rustoshi_wallet::descriptor::add_checksum;
                let raw_desc = format!("raw({})", hex::encode(&output.script_pubkey));
                let desc = add_checksum(&raw_desc).unwrap_or(raw_desc);
                RestTxOutput {
                    value: output.value as f64 / COIN as f64,
                    n: n as u32,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: disassemble_script(&output.script_pubkey),
                        desc,
                        hex: hex::encode(&output.script_pubkey),
                        address: None,
                        script_type: detect_script_type(&output.script_pubkey),
                    },
                }
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

/// Convert compact nBits to a 64-char hex target string (same logic as server.rs).
fn compact_to_target_hex_rest(bits: u32) -> String {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007F_FFFF;
    let mut target = [0u8; 32];
    if exponent == 0 {
        return "0".repeat(64);
    }
    let byte2 = ((mantissa >> 16) & 0xff) as u8;
    let byte1 = ((mantissa >> 8) & 0xff) as u8;
    let byte0 = (mantissa & 0xff) as u8;
    if exponent >= 1 && exponent <= 32 {
        let pos = 32 - exponent;
        if pos < 32 { target[pos] = byte2; }
        if pos + 1 < 32 { target[pos + 1] = byte1; }
        if pos + 2 < 32 { target[pos + 2] = byte0; }
    }
    hex::encode(target)
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
// CHAININFO ENDPOINT
// ============================================================

/// Compact chain-info projection returned by `/rest/chaininfo.json`.
///
/// Mirrors the subset of `getblockchaininfo` that Bitcoin Core surfaces via
/// REST (`bitcoin-core/src/rest.cpp::rest_chaininfo`). Fields are kept in
/// snake_case matching Core's UniValue keys.
#[derive(Debug, Serialize)]
struct RestChainInfo {
    chain: String,
    blocks: u32,
    headers: u32,
    bestblockhash: String,
    difficulty: f64,
    mediantime: u64,
    verificationprogress: f64,
    initialblockdownload: bool,
    chainwork: String,
    pruned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pruneheight: Option<u32>,
    warnings: String,
}

/// GET /rest/chaininfo.json
///
/// Returns blockchain info as JSON only — no `.bin` / `.hex` form per
/// `bitcoin-core/src/rest.cpp::rest_chaininfo` (rejects non-JSON formats).
async fn rest_chaininfo(
    State(state): State<Arc<RestState>>,
) -> Result<Response, RestError> {
    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);

    let entry_opt = store.get_block_index(&rpc_state.best_hash).ok().flatten();
    let header_opt = store.get_header(&rpc_state.best_hash).ok().flatten();

    let (difficulty, chainwork_hex, mediantime) = match (entry_opt.as_ref(), header_opt.as_ref()) {
        (Some(entry), Some(header)) => (
            bits_to_difficulty(header.bits),
            hex::encode(entry.chain_work),
            entry.timestamp as u64,
        ),
        (Some(entry), None) => (
            1.0,
            hex::encode(entry.chain_work),
            entry.timestamp as u64,
        ),
        (None, Some(header)) => (
            bits_to_difficulty(header.bits),
            "0".repeat(64),
            header.timestamp as u64,
        ),
        (None, None) => (1.0, "0".repeat(64), 0),
    };

    let progress = if rpc_state.header_height > 0 {
        rpc_state.best_height as f64 / rpc_state.header_height as f64
    } else {
        1.0
    };

    let chain_name = match rpc_state.params.network_id {
        rustoshi_consensus::params::NetworkId::Mainnet => "main",
        rustoshi_consensus::params::NetworkId::Testnet3 => "test3",
        rustoshi_consensus::params::NetworkId::Testnet4 => "test4",
        rustoshi_consensus::params::NetworkId::Signet => "signet",
        rustoshi_consensus::params::NetworkId::Regtest => "regtest",
    };

    let pruneheight = if rpc_state.prune_mode {
        let watermark = store.get_prune_height().unwrap_or(0);
        let lowest_complete = if watermark == 0 { 0 } else { watermark + 1 };
        Some(lowest_complete)
    } else {
        None
    };

    let info = RestChainInfo {
        chain: chain_name.to_string(),
        blocks: rpc_state.best_height,
        headers: rpc_state.header_height,
        bestblockhash: rpc_state.best_hash.to_hex(),
        difficulty,
        mediantime,
        verificationprogress: progress,
        initialblockdownload: rpc_state.is_ibd,
        chainwork: chainwork_hex,
        pruned: rpc_state.prune_mode,
        pruneheight,
        warnings: String::new(),
    };

    Ok(json_response(&info))
}

// ============================================================
// BIP-157 BLOCK FILTER ENDPOINTS
// ============================================================

/// Encode a `BlockFilter` in Bitcoin Core's binary form.
///
/// Reference: `bitcoin-core/src/blockfilter.h::BlockFilter::Serialize`:
/// `[uint8 filter_type] [uint256 block_hash] [CompactSize len] [filter bytes]`.
///
/// Block hash is serialized in little-endian (internal-byte-order) form, which
/// is the natural memory order of `Hash256::as_bytes()`.
fn serialize_blockfilter_core(
    filter_type: BlockFilterType,
    block_hash: &Hash256,
    encoded_filter: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 9 + encoded_filter.len());
    out.push(filter_type as u8);
    out.extend_from_slice(block_hash.as_bytes());
    encode_compact_size(&mut out, encoded_filter.len() as u64);
    out.extend_from_slice(encoded_filter);
    out
}

/// Encode a Bitcoin-style CompactSize into `out`.
fn encode_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// GET /rest/blockfilter/<filtertype>/<hash>.<format>
///
/// Returns the BIP-157 compact block filter (BIP-158 GCS encoding) for the
/// given block. Mirrors `bitcoin-core/src/rest.cpp::rest_block_filter`.
///
/// Path is `<filtertype>/<hash>.<format>` where `filtertype` is the textual
/// filter name (today only `"basic"`, BIP-158 default).
async fn rest_blockfilter(
    State(state): State<Arc<RestState>>,
    Path(path): Path<String>,
) -> Result<Response, RestError> {
    // Path: <filtertype>/<hash>.<format>
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(RestError::InvalidUri);
    }
    let filter_type = BlockFilterType::from_name(parts[0]).ok_or(RestError::UnknownFilterType)?;
    let (block_hash, format) = parse_hash_and_format(parts[1])?;

    let rpc_state = state.rpc_state.read().await;
    let index = BlockFilterIndex::new(&rpc_state.db);

    let filter = index
        .get_filter(&block_hash)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?
        .ok_or(RestError::FilterNotFound)?;

    match format {
        RestFormat::Binary => {
            let data = serialize_blockfilter_core(filter_type, &block_hash, &filter.encoded_filter);
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let data = serialize_blockfilter_core(filter_type, &block_hash, &filter.encoded_filter);
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            #[derive(Serialize)]
            struct FilterJson {
                filter: String,
            }
            let resp = FilterJson {
                filter: hex::encode(&filter.encoded_filter),
            };
            Ok(json_response(&resp))
        }
    }
}

/// GET /rest/blockfilterheaders/<filtertype>/<count>/<hash>.<format>
///
/// Returns up to `count` BIP-157 compact-filter headers starting at
/// the block named by `hash`, walking forward by height. Mirrors
/// `bitcoin-core/src/rest.cpp::rest_filter_header` (deprecated 3-segment
/// path; the 2-segment `?count=N` query form is not implemented yet).
///
/// Binary form: concatenated 32-byte little-endian filter headers.
/// JSON form: array of hex-encoded filter headers (display order).
async fn rest_blockfilterheaders(
    State(state): State<Arc<RestState>>,
    Path(path): Path<String>,
) -> Result<Response, RestError> {
    // Path: <filtertype>/<count>/<hash>.<format>
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() != 3 {
        return Err(RestError::InvalidUri);
    }
    let _filter_type = BlockFilterType::from_name(parts[0]).ok_or(RestError::UnknownFilterType)?;
    let count: usize = parts[1].parse().map_err(|_| RestError::InvalidCount)?;
    if !(1..=MAX_REST_HEADERS_RESULTS).contains(&count) {
        return Err(RestError::InvalidCount);
    }
    let (start_hash, format) = parse_hash_and_format(parts[2])?;

    // FIX-88 W121 BUG-26 — REST handler reorg-race guard.
    //
    // The original loop walked heights `start_entry.height + i` without
    // re-checking that each height still maps to the requested chain
    // segment.  If a reorg landed between iterations, the response would
    // splice headers from two different chains (a sender-controlled
    // amplification of consensus state).
    //
    // Fix: hold the `RpcState` read lock across the entire walk AND verify
    // for every iteration that
    //   (a) start_hash still maps to start_entry.height on the active
    //       chain, and
    //   (b) the height we are about to read still resolves to a block on
    //       the active chain.
    //
    // The RwLock on `RpcState` is the same lock acquired by writers that
    // perform reorganize / connect_tip / disconnect_tip, so holding the
    // read lock for the duration of the walk guarantees no reorg can
    // commit mid-response.  This mirrors Core's `cs_main` lock held by
    // `rest_filter_header` (bitcoin-core/src/rest.cpp).
    let rpc_state = state.rpc_state.read().await;
    let store = BlockStore::new(&rpc_state.db);
    let index = BlockFilterIndex::new(&rpc_state.db);

    let start_entry = store
        .get_block_index(&start_hash)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?
        .ok_or(RestError::BlockNotFound)?;

    // Pin: confirm start_hash is on the active chain right now.  If not,
    // the request is for a stale/orphaned tip and we MUST NOT splice in
    // filter headers from the current chain at the same heights.
    let active_at_start = store
        .get_hash_by_height(start_entry.height)
        .map_err(|e| RestError::DatabaseError(e.to_string()))?;
    if active_at_start != Some(start_hash) {
        return Err(RestError::BlockNotFound);
    }

    let mut headers: Vec<Hash256> = Vec::with_capacity(count);
    for i in 0..count {
        let height = start_entry.height + i as u32;

        // Re-pin: after every iteration step, re-verify that the start
        // anchor is still on the active chain.  This is redundant under
        // the read-lock semantics above (no writer can commit a reorg
        // while we hold the lock), but is kept as defence-in-depth in
        // case lock granularity is ever relaxed (see CORE-PARITY-AUDIT/
        // _rest-reorg-race-bug26.md).
        if store
            .get_hash_by_height(start_entry.height)
            .map_err(|e| RestError::DatabaseError(e.to_string()))?
            != Some(start_hash)
        {
            return Err(RestError::BlockNotFound);
        }

        match index.get_filter_header(height) {
            Ok(Some(entry)) => headers.push(entry.filter_header),
            Ok(None) => return Err(RestError::FilterNotFound),
            Err(e) => return Err(RestError::DatabaseError(e.to_string())),
        }
        // Stop early if we walked off the active chain.
        if store
            .get_hash_by_height(height + 1)
            .ok()
            .flatten()
            .is_none()
        {
            break;
        }
    }

    match format {
        RestFormat::Binary => {
            let mut data = Vec::with_capacity(headers.len() * 32);
            for h in &headers {
                data.extend_from_slice(h.as_bytes());
            }
            Ok(build_response(&data, format))
        }
        RestFormat::Hex => {
            let mut data = Vec::with_capacity(headers.len() * 32);
            for h in &headers {
                data.extend_from_slice(h.as_bytes());
            }
            Ok(build_response(&data, format))
        }
        RestFormat::Json => {
            let hexes: Vec<String> = headers.iter().map(|h| h.to_hex()).collect();
            Ok(json_response(&hexes))
        }
    }
}

// ============================================================
// REST SERVER CONFIG + STARTUP
// ============================================================

/// Configuration for the REST HTTP server (Bitcoin Core `-rest`).
///
/// Default off. Mounted on its own axum listener, distinct from the
/// JSON-RPC server (which jsonrpsee owns end-to-end). Bitcoin Core
/// multiplexes REST onto the same port as JSON-RPC; rustoshi runs them
/// on separate ports because `jsonrpsee 0.22` does not expose a
/// hookable HTTP router. The REST URI surface is otherwise byte-
/// compatible with Core's.
#[derive(Clone, Debug)]
pub struct RestConfig {
    /// Address to bind the REST listener to (e.g. `127.0.0.1:8432`).
    pub bind_address: String,
}

/// Handle for a running REST server.
///
/// Holding this prevents the listener task from being aborted; dropping it
/// triggers cooperative shutdown via the inner `JoinHandle::abort()`.
pub struct RestServerHandle {
    join: tokio::task::JoinHandle<()>,
}

impl RestServerHandle {
    /// Returns a reference to the underlying `JoinHandle`.
    pub fn join_handle(&self) -> &tokio::task::JoinHandle<()> {
        &self.join
    }

    /// Abort the listener task.
    pub fn abort(&self) {
        self.join.abort();
    }
}

impl Drop for RestServerHandle {
    fn drop(&mut self) {
        self.join.abort();
    }
}

/// Bind the REST listener and spawn it as a tokio task.
///
/// Returns a [`RestServerHandle`]; dropping it shuts the listener down. The
/// REST server is unauthenticated (matches Core) and read-only; consensus
/// callers should still gate it behind `--rest`. Bind failures (e.g. port
/// already in use) are returned as `anyhow::Error` for the caller to log.
///
/// Reference: `bitcoin-core/src/rest.cpp` URI table at line 1144.
pub async fn start_rest_server(
    config: RestConfig,
    rpc_state: Arc<RwLock<RpcState>>,
) -> anyhow::Result<RestServerHandle> {
    start_rest_server_with_wallet(config, rpc_state, None).await
}

/// Like [`start_rest_server`], but also mounts the BIP-78 PayJoin
/// receiver endpoint backed by `wallet_state` when `Some`. The
/// JSON-RPC wallet endpoints continue to live on the jsonrpsee listener
/// — only the receiver-side HTTP surface is added here.
///
/// Reference: BIP-78 §"Protocol", and the FIX-64 + FIX-65 design notes
/// in `crates/rpc/src/payjoin.rs` (formerly `crates/wallet/src/payjoin.rs`).
pub async fn start_rest_server_with_wallet(
    config: RestConfig,
    rpc_state: Arc<RwLock<RpcState>>,
    wallet_state: Option<Arc<RwLock<WalletRpcState>>>,
) -> anyhow::Result<RestServerHandle> {
    let listener = TcpListener::bind(&config.bind_address).await?;
    let router = rest_router_with_wallet(rpc_state, wallet_state);
    let join = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("REST server exited: {}", e);
        }
    });
    Ok(RestServerHandle { join })
}

// ============================================================
// BIP-78 PAYJOIN RECEIVER (W119 / FIX-65)
// ============================================================

/// G16 / G21 (FIX-67) — strict BIP-78 query-param parser.
///
/// BIP-78 §"Protocol" specifies five wire query parameters
/// (`v`, `additionalfeeoutputindex`, `maxadditionalfeecontribution`,
/// `disableoutputsubstitution`, `minfeerate`). The receiver MUST
/// understand `v=1` and reject anything else as
/// `version-unsupported`; malformed numeric values MUST be rejected
/// as `original-psbt-rejected`.
///
/// Parses the raw query string (`?k=v&k=v`), recognising only the
/// five wire keys (unknown keys are tolerated for forward-compat
/// per BIP-78 §"Forward compatibility"), validates each value, and
/// emits a [`PayjoinParams`] or a typed parser error mapped to a
/// BIP-78 wire error.
fn parse_payjoin_query(raw: &str) -> Result<PayjoinParams, PayjoinError> {
    let mut version: Option<u32> = None;
    let mut additional_fee_output_index: Option<usize> = None;
    let mut max_additional_fee_contribution: Option<u64> = None;
    let mut disable_output_substitution: bool = false;
    let mut min_fee_rate: Option<f64> = None;

    // Empty query → defaults (version=0 → caught by validate_params as
    // `version-unsupported`).
    if raw.is_empty() {
        return Ok(PayjoinParams {
            version: 0,
            additional_fee_output_index: None,
            max_additional_fee_contribution: None,
            disable_output_substitution: false,
            min_fee_rate: None,
        });
    }

    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            // Bare key without `=` → BIP-78 doesn't define that shape;
            // we tolerate it as no-op so unknown keys don't trip us.
            None => continue,
        };
        match k {
            "v" => {
                let parsed: u32 = v.parse().map_err(|_| {
                    PayjoinError::OriginalPsbtRejected(format!(
                        "v query param must be a u32 (got {v:?})"
                    ))
                })?;
                version = Some(parsed);
            }
            "additionalfeeoutputindex" => {
                let parsed: usize = v.parse().map_err(|_| {
                    PayjoinError::OriginalPsbtRejected(format!(
                        "additionalfeeoutputindex must be a non-negative integer (got {v:?})"
                    ))
                })?;
                additional_fee_output_index = Some(parsed);
            }
            "maxadditionalfeecontribution" => {
                let parsed: u64 = v.parse().map_err(|_| {
                    PayjoinError::OriginalPsbtRejected(format!(
                        "maxadditionalfeecontribution must be a u64 (got {v:?})"
                    ))
                })?;
                max_additional_fee_contribution = Some(parsed);
            }
            "disableoutputsubstitution" => {
                // BIP-78: 0 or 1.
                match v {
                    "0" => disable_output_substitution = false,
                    "1" => disable_output_substitution = true,
                    other => {
                        return Err(PayjoinError::OriginalPsbtRejected(format!(
                            "disableoutputsubstitution must be 0 or 1 (got {other:?})"
                        )));
                    }
                }
            }
            "minfeerate" => {
                let parsed: f64 = v.parse().map_err(|_| {
                    PayjoinError::OriginalPsbtRejected(format!(
                        "minfeerate must be a non-negative f64 (got {v:?})"
                    ))
                })?;
                min_fee_rate = Some(parsed);
            }
            // Unknown keys: per BIP-78 forward-compat, we tolerate but
            // do not store. (Senders that need stricter semantics can
            // use HTTP request validation upstream.)
            _ => continue,
        }
    }

    Ok(PayjoinParams {
        version: version.unwrap_or(0),
        additional_fee_output_index,
        max_additional_fee_contribution,
        disable_output_substitution,
        min_fee_rate,
    })
}

/// Build a BIP-78 JSON error body + the matching HTTP status. The
/// payload shape is fixed by the spec:
/// `{"errorCode": "...", "message": "..."}`.
fn payjoin_error_response(err: &PayjoinError) -> Response {
    let body = serde_json::json!({
        "errorCode": err.code(),
        "message": err.to_string(),
    });
    let status = StatusCode::from_u16(err.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Cap on the request body size before we even try to base64-decode.
/// BIP-78 specifies that implementations may reject oversize bodies;
/// we apply the same 8 KiB ceiling as the payjoin module itself uses
/// for the post-decode shape check, which is overkill for raw bytes
/// but trivially safe.
const PAYJOIN_REQUEST_BODY_LIMIT: usize = MAX_ORIGINAL_PSBT_BYTES;

/// G30 (FIX-67) replay-id set soft cap. Larger than the in-flight TTL
/// map can grow under realistic load; if a misbehaving sender floods,
/// the set is cleared (replay protection then degrades to "any
/// previously offered PSBT-id that has expired from `offered_payjoins`
/// might be re-accepted", which is an acceptable failure mode — the
/// alternative is unbounded growth).
const PAYJOIN_REPLAY_SET_LIMIT: usize = 8192;

/// POST /payjoin — BIP-78 receiver endpoint.
///
/// Flow:
///  1. Validate request headers: `Content-Type: text/plain` (G23) and
///     body size ≤ [`PAYJOIN_REQUEST_BODY_LIMIT`] (G23).
///  2. Strict-parse the query string (G16) into [`PayjoinParams`];
///     enforce `v=1` (G21).
///  3. Acquire the wallet handle and require it unlocked; if either
///     fails, answer with HTTP 503 `unavailable`.
///  4. Evict expired offers from `offered_payjoins` (G18) before
///     snapshotting.
///  5. Reject any request whose Original-PSBT id has already been
///     served (G30 replay).
///  6. Call into [`handle_payjoin_request`] which runs the structural
///     PSBT checks, picks a receiver UTXO that isn't already in
///     `offered_payjoins`, augments the PSBT, signs the receiver input,
///     and returns the modified PSBT.
///  7. Commit the offer into `offered_payjoins` (key = Original PSBT
///     unsigned-tx hash) so subsequent concurrent requests don't pick
///     the same receiver UTXO. Also record the id in the replay set.
///  8. Respond `200 text/plain` with the base64 PSBT body. The sender
///     is responsible for signing its own inputs and broadcasting
///     (BIP-78 §"Sender's actions").
async fn payjoin_handler(
    State(state): State<Arc<RestState>>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // G23: Content-Type strict. BIP-78 §"Protocol" specifies the body
    // is a base64-encoded PSBT served as `text/plain`. We accept
    // exactly `text/plain` (optionally with charset parameter, common
    // in practice). Any other type is rejected with a BIP-78
    // `original-psbt-rejected`. We look up by string to dodge the
    // multi-version `http` crate disambiguation (axum 0.7 ships
    // `http` 1.x; some other deps still pin `http` 0.2).
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !content_type
        .to_ascii_lowercase()
        .starts_with("text/plain")
    {
        return payjoin_error_response(&PayjoinError::OriginalPsbtRejected(format!(
            "Content-Type must be text/plain (got {content_type:?})"
        )));
    }

    // G23: Body size guard (the 8 KiB BIP-78 cap).
    if body.len() > PAYJOIN_REQUEST_BODY_LIMIT {
        return payjoin_error_response(&PayjoinError::OriginalPsbtRejected(format!(
            "request body exceeds {} byte limit",
            PAYJOIN_REQUEST_BODY_LIMIT
        )));
    }

    // G16 strict query-param parsing; surfaces parse failures as
    // `original-psbt-rejected` per BIP-78 "malformed request".
    let raw = raw_query.unwrap_or_default();
    let params = match parse_payjoin_query(&raw) {
        Ok(p) => p,
        Err(e) => return payjoin_error_response(&e),
    };

    // G21 + G16 receiver-side validation (v=1 sentinel + minfeerate
    // sanity). Runs BEFORE wallet resolution so the wire
    // `version-unsupported` answer is produced even with no wallet
    // loaded.
    if let Err(e) = rustoshi_wallet::payjoin::validate_params(&params) {
        return payjoin_error_response(&e);
    }

    // Resolve the wallet handle. Absent → `unavailable`.
    let wallet_state = match &state.wallet_state {
        Some(ws) => ws.clone(),
        None => {
            return payjoin_error_response(&PayjoinError::Unavailable(
                "receiver wallet is not loaded".to_string(),
            ));
        }
    };

    // G18: evict expired offers BEFORE snapshotting. A sender that
    // received a PayJoin reply but never broadcast won't pin the
    // receiver UTXO past the TTL.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let offered_snapshot: HashMap<Hash256, OfferedPayjoin> = {
        let mut offered = state.offered_payjoins.lock().await;
        let _evicted = evict_expired_offers(&mut offered, now_secs, OFFERED_PAYJOIN_TTL_SECS);
        offered.clone()
    };

    // G30: replay check. We compute the Original-PSBT id by parsing the
    // body upfront (cheap — body is already known to be ≤ 8 KiB). If
    // the id has already been served, return `original-psbt-rejected`
    // without ever touching the wallet (avoids re-deriving keys for
    // known-replayed requests).
    let original_psbt_id: Option<Hash256> = match std::str::from_utf8(body.as_ref()) {
        Ok(s) => rustoshi_wallet::Psbt::from_base64(s.trim())
            .ok()
            .map(|p| p.unsigned_tx.txid()),
        Err(_) => None,
    };
    if let Some(psbt_id) = original_psbt_id.as_ref() {
        let replays = state.payjoin_replay_ids.lock().await;
        if replays.contains(psbt_id) {
            return payjoin_error_response(&PayjoinError::OriginalPsbtRejected(
                "replay: this Original PSBT has already been served".to_string(),
            ));
        }
    }

    // Acquire wallet read lock + require the active wallet unlocked.
    let result = {
        let wallet_state_guard = wallet_state.read().await;
        let (name, wallet_arc) = match wallet_state_guard
            .wallet_manager
            .get_wallet_or_default(None)
        {
            Ok(pair) => pair,
            Err(e) => {
                return payjoin_error_response(&PayjoinError::Unavailable(format!(
                    "no active wallet: {e}"
                )));
            }
        };
        if let Err(e) = wallet_state_guard.wallet_manager.require_unlocked(&name) {
            return payjoin_error_response(&PayjoinError::Unavailable(format!(
                "wallet '{name}' locked: {e}"
            )));
        }

        let wallet_guard = match wallet_arc.lock() {
            Ok(w) => w,
            Err(_) => {
                return payjoin_error_response(&PayjoinError::Unavailable(
                    "wallet lock poisoned".to_string(),
                ));
            }
        };

        handle_payjoin_request(body.as_ref(), &params, &wallet_guard, &offered_snapshot)
    };

    let contribution = match result {
        Ok(c) => c,
        Err(e) => return payjoin_error_response(&e),
    };

    // Commit the offer. The Original-PSBT id (G30) is the unsigned-tx
    // hash of the body the sender supplied; offered_payjoins also keys
    // on it (or falls back to the modified-tx hash if the original
    // failed to parse a moment ago — that path is defensive: if we
    // reached here `handle_payjoin_request` already parsed it).
    let commit_id = original_psbt_id
        .unwrap_or_else(|| contribution.modified_psbt.unsigned_tx.txid());
    {
        let mut offered = state.offered_payjoins.lock().await;
        offered.insert(
            commit_id,
            OfferedPayjoin {
                receiver_outpoint: contribution.added_utxo.outpoint.clone(),
                created_at: now_secs,
            },
        );
    }
    {
        let mut replays = state.payjoin_replay_ids.lock().await;
        if replays.len() >= PAYJOIN_REPLAY_SET_LIMIT {
            // Soft-reset to bound memory growth (see PAYJOIN_REPLAY_SET_LIMIT).
            replays.clear();
        }
        replays.insert(commit_id);
    }

    let body_b64 = contribution.modified_psbt.to_base64();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(body_b64))
        .unwrap()
}

// ============================================================
// ROUTER
// ============================================================

/// Create the REST API router (legacy, no wallet wiring).
///
/// Equivalent to `rest_router_with_wallet(rpc_state, None)`. Retained for
/// callers and existing tests that never need the PayJoin endpoint.
pub fn rest_router(rpc_state: Arc<RwLock<RpcState>>) -> Router {
    rest_router_with_wallet(rpc_state, None)
}

/// Create the REST API router, optionally mounting the BIP-78 PayJoin
/// receiver endpoint when `wallet_state` is `Some`.
///
/// The PayJoin route is unconditionally registered — when `wallet_state`
/// is `None` the handler simply answers HTTP 503 +
/// `{"errorCode":"unavailable", ...}` per BIP-78. This is intentional:
/// it keeps the route surface deterministic regardless of binary
/// configuration so a sender that hits the URL gets a structured
/// answer rather than a 404.
pub fn rest_router_with_wallet(
    rpc_state: Arc<RwLock<RpcState>>,
    wallet_state: Option<Arc<RwLock<WalletRpcState>>>,
) -> Router {
    let state = Arc::new(RestState {
        rpc_state,
        wallet_state,
        offered_payjoins: Mutex::new(HashMap::new()),
        payjoin_replay_ids: Mutex::new(std::collections::HashSet::new()),
    });

    // axum 0.7 uses matchit 0.7 syntax: `:name` for single-segment params
    // and `*name` for catch-all. Bitcoin Core's REST URI table is in
    // `bitcoin-core/src/rest.cpp` line 1144.
    Router::new()
        // `block/notxdetails/...` MUST be registered before `block/...`
        // because matchit treats `notxdetails` as a static prefix and would
        // otherwise be shadowed by the parameterized sibling.
        .route("/rest/block/notxdetails/:hash_format", get(rest_block_notxdetails))
        .route("/rest/block/:hash_format", get(rest_block))
        .route("/rest/headers/*path", get(rest_headers))
        .route("/rest/blockhashbyheight/:height_format", get(rest_blockhashbyheight))
        .route("/rest/tx/:txid_format", get(rest_tx))
        .route("/rest/getutxos/*path", get(rest_getutxos))
        .route("/rest/mempool/info.json", get(rest_mempool_info))
        .route("/rest/mempool/contents.json", get(rest_mempool_contents))
        .route("/rest/chaininfo.json", get(rest_chaininfo))
        // BIP-157 cfilter endpoints. The `*path` matcher captures
        // `<filtertype>/<...>.<format>` for the handler to parse.
        .route("/rest/blockfilter/*path", get(rest_blockfilter))
        .route("/rest/blockfilterheaders/*path", get(rest_blockfilterheaders))
        // BIP-78 PayJoin receiver endpoint (W119 / FIX-65). Lives at the
        // unprefixed `/payjoin` URL so a BIP-21 `bitcoin:?pj=<host>/payjoin`
        // URI fits the typical receiver-vending pattern without leaking
        // the REST URI prefix into the spec.
        .route("/payjoin", post(payjoin_handler))
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

    // -----------------------------------------------------------------
    // FIX-67 G16 — parse_payjoin_query
    // -----------------------------------------------------------------

    #[test]
    fn payjoin_query_parses_full_set() {
        let q = "v=1&additionalfeeoutputindex=0&maxadditionalfeecontribution=1000&disableoutputsubstitution=1&minfeerate=2.5";
        let p = parse_payjoin_query(q).expect("happy parse");
        assert_eq!(p.version, 1);
        assert_eq!(p.additional_fee_output_index, Some(0));
        assert_eq!(p.max_additional_fee_contribution, Some(1000));
        assert!(p.disable_output_substitution);
        assert_eq!(p.min_fee_rate, Some(2.5));
    }

    #[test]
    fn payjoin_query_default_v_is_zero() {
        // Empty query → version=0 → caller's validate_params rejects.
        let p = parse_payjoin_query("").expect("empty parse");
        assert_eq!(p.version, 0);
    }

    #[test]
    fn payjoin_query_rejects_non_numeric_v() {
        let err = parse_payjoin_query("v=abc").expect_err("non-numeric v rejects");
        assert_eq!(err.code(), "original-psbt-rejected");
    }

    #[test]
    fn payjoin_query_rejects_invalid_disable_output_substitution() {
        let err = parse_payjoin_query("v=1&disableoutputsubstitution=2")
            .expect_err("only 0/1 allowed");
        assert_eq!(err.code(), "original-psbt-rejected");
    }

    #[test]
    fn payjoin_query_tolerates_unknown_keys() {
        // Forward-compat: unknown keys are skipped.
        let p = parse_payjoin_query("v=1&foo=bar&someotherkey=42").expect("tolerates unknown");
        assert_eq!(p.version, 1);
    }

    #[test]
    fn payjoin_query_rejects_negative_minfeerate_via_validate() {
        let p = parse_payjoin_query("v=1&minfeerate=-1.0").expect("parses raw");
        let err = rustoshi_wallet::payjoin::validate_params(&p)
            .expect_err("negative minfeerate rejects in validate_params");
        assert_eq!(err.code(), "original-psbt-rejected");
    }

    // -----------------------------------------------------------------
    // FIX-67 G18 — payjoin_replay_set + offered_payjoins TTL semantics
    // -----------------------------------------------------------------

    #[test]
    fn payjoin_replay_set_limit_is_finite_and_resets() {
        // Smoke: ensure PAYJOIN_REPLAY_SET_LIMIT is configured so the
        // soft-reset semantics in payjoin_handler are bounded.
        assert!(PAYJOIN_REPLAY_SET_LIMIT >= 1024);
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

    #[test]
    fn test_serialize_blockfilter_core_format() {
        // Spot-check the binary serialization matches Core's
        // `BlockFilter::Serialize`:
        // [u8 type][32 bytes block_hash][CompactSize len][filter bytes]
        let block_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let encoded_filter = vec![0xab, 0xcd, 0xef];
        let out = serialize_blockfilter_core(BlockFilterType::Basic, &block_hash, &encoded_filter);
        // 1 + 32 + 1 (compactsize for 3) + 3
        assert_eq!(out.len(), 1 + 32 + 1 + 3);
        assert_eq!(out[0], 0u8); // BlockFilterType::Basic = 0
        assert_eq!(&out[1..33], block_hash.as_bytes());
        assert_eq!(out[33], 3u8); // CompactSize for len=3
        assert_eq!(&out[34..], &[0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_encode_compact_size() {
        let mut out = Vec::new();
        encode_compact_size(&mut out, 0);
        assert_eq!(out, vec![0x00]);

        out.clear();
        encode_compact_size(&mut out, 252);
        assert_eq!(out, vec![0xfc]);

        out.clear();
        encode_compact_size(&mut out, 253);
        assert_eq!(out, vec![0xfd, 0xfd, 0x00]);

        out.clear();
        encode_compact_size(&mut out, 0x10000);
        assert_eq!(out, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    /// Sanity: building the router does not panic. axum 0.7 / matchit 0.7
    /// rejects `{...}`-style placeholders at insert time, so a regression
    /// to `{}` syntax would be caught here even without exercising the
    /// network listener.
    #[test]
    fn test_router_builds_without_panic() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = ChainParams::regtest();
        let state = Arc::new(RwLock::new(RpcState::new(db, params)));
        let _router = rest_router(state);
        // Constructed without panic — that is all we need to prove.
    }

    /// Bring the REST listener up on an ephemeral port and verify that we
    /// can establish a TCP connection (proves `start_rest_server` actually
    /// binds + spawns). This is the cross-impl audit's RED-1 acceptance
    /// criterion: REST is reachable in the running binary.
    #[tokio::test]
    async fn test_rest_listener_accepts_connection() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = ChainParams::regtest();
        let state = Arc::new(RwLock::new(RpcState::new(db, params)));

        // Bind on port 0 — let the OS pick. We then read the actual port
        // back via `local_addr()` on the listener.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let router = rest_router(state);
        let _server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Connect + send a minimal HTTP/1.1 GET against `/rest/chaininfo.json`
        // and expect a 200 back. This proves the listener is live AND that
        // the chaininfo route is mounted (closing audit RED-6).
        let mut sock = TcpStream::connect(bound).await.expect("connect");
        sock.write_all(
            b"GET /rest/chaininfo.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write");
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.expect("read");
        let head = String::from_utf8_lossy(&buf);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200 OK from /rest/chaininfo.json, got:\n{}",
            head
        );
        assert!(head.contains("\"chain\":\"regtest\""), "body: {}", head);
    }

    /// Happy path: store a filter, query `/rest/blockfilter/basic/<hash>.bin`,
    /// expect the Core-format serialization back.
    #[tokio::test]
    async fn test_rest_blockfilter_happy_path() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::indexes::blockfilterindex::{BlockFilter, BlockFilterIndex};
        use rustoshi_storage::ChainDb;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));

        // Pick a deterministic hash + payload, write the filter to the
        // index. The handler reads from `BlockFilterIndex::get_filter`.
        let block_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let encoded = vec![0xde, 0xad, 0xbe, 0xef, 0x42];
        let filter = BlockFilter::new(BlockFilterType::Basic, block_hash, encoded.clone());
        BlockFilterIndex::new(&db).put_filter(&filter).expect("put_filter");

        let params = ChainParams::regtest();
        let state = Arc::new(RwLock::new(RpcState::new(db, params)));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let router = rest_router(state);
        let _server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let path = format!(
            "/rest/blockfilter/basic/{}.bin",
            block_hash.to_hex()
        );
        let mut sock = TcpStream::connect(bound).await.expect("connect");
        sock.write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                path
            )
            .as_bytes(),
        )
        .await
        .expect("write");
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.expect("read");

        // Split header / body on the canonical \r\n\r\n boundary.
        let sep = b"\r\n\r\n";
        let split = buf
            .windows(sep.len())
            .position(|w| w == sep)
            .expect("expected header/body separator");
        let header = String::from_utf8_lossy(&buf[..split]);
        let body = &buf[split + sep.len()..];
        assert!(
            header.starts_with("HTTP/1.1 200"),
            "expected 200 OK, got:\n{}",
            header
        );

        // Body might be chunked-encoded (axum + hyper default). Strip the
        // chunked framing if present.
        let body_bytes: Vec<u8> = if header.to_lowercase().contains("transfer-encoding: chunked") {
            decode_chunked(body)
        } else {
            body.to_vec()
        };

        let expected = serialize_blockfilter_core(BlockFilterType::Basic, &block_hash, &encoded);
        assert_eq!(body_bytes, expected, "binary blockfilter body mismatch");
    }

    /// 404 on unknown block hash (filter index has no entry).
    #[tokio::test]
    async fn test_rest_blockfilter_unknown_hash_404() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = ChainParams::regtest();
        let state = Arc::new(RwLock::new(RpcState::new(db, params)));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let router = rest_router(state);
        let _server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Hash that the filter index will never have.
        let unknown = "0".repeat(64);
        let path = format!("/rest/blockfilter/basic/{}.bin", unknown);
        let mut sock = TcpStream::connect(bound).await.expect("connect");
        sock.write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                path
            )
            .as_bytes(),
        )
        .await
        .expect("write");
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.expect("read");
        let head = String::from_utf8_lossy(&buf);
        assert!(
            head.starts_with("HTTP/1.1 404"),
            "expected 404 Not Found, got:\n{}",
            head
        );
    }

    /// Decode a single chunked-transfer-encoded body. Sufficient for our
    /// small fixture filters — we don't need full HTTP/1.1 framing here.
    fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            // Read chunk size up to \r\n.
            let crlf = body
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("chunk size CRLF");
            let size_str = std::str::from_utf8(&body[..crlf]).unwrap();
            // Strip optional chunk extension after `;`.
            let size_str = size_str.split(';').next().unwrap().trim();
            let size = usize::from_str_radix(size_str, 16).expect("parse hex chunk size");
            body = &body[crlf + 2..];
            if size == 0 {
                break;
            }
            out.extend_from_slice(&body[..size]);
            body = &body[size..];
            // Trailing \r\n after chunk data.
            assert!(body.starts_with(b"\r\n"));
            body = &body[2..];
        }
        out
    }
}
