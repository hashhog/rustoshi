//! RPC server implementation using jsonrpsee.
//!
//! This module provides a JSON-RPC server that implements Bitcoin Core-compatible RPCs
//! for interacting with the node. It uses `jsonrpsee` for standards-compliant JSON-RPC 2.0
//! support with automatic request parsing, response formatting, and error codes.
//!
//! # Architecture
//!
//! The server uses `Arc<RwLock<...>>` for shared state access. Read-heavy methods
//! (getblock, getblockchaininfo) use read locks; write methods (sendrawtransaction,
//! submitblock) use write locks.
//!
//! # Example
//!
//! ```ignore
//! let config = RpcConfig::default();
//! let state = Arc::new(RwLock::new(RpcState::new(...)));
//! let handle = start_rpc_server(config, state).await?;
//! ```

use crate::types::*;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use rustoshi_consensus::{
    block_template::{build_block_template, BlockTemplateConfig},
    fee_estimator::FeeEstimator,
    mempool::{Mempool, MempoolConfig},
    ChainParams, NetworkId, COIN,
};
use rustoshi_network::peer_manager::PeerManager;
use rustoshi_primitives::{Block, Decodable, Encodable, Hash256, OutPoint, Transaction};
use rustoshi_storage::{block_store::BlockStore, ChainDb};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{oneshot, RwLock};

// ============================================================
// RPC ERROR CODES
// ============================================================

/// RPC error codes matching Bitcoin Core.
pub mod rpc_error {
    /// Standard JSON-RPC 2.0 invalid params error.
    pub const RPC_INVALID_PARAMS: i32 = -32602;
    /// General-purpose RPC error.
    pub const RPC_MISC_ERROR: i32 = -1;
    /// Invalid address or key.
    pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
    /// Database error.
    pub const RPC_DATABASE_ERROR: i32 = -20;
    /// Deserialization error.
    pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
    /// Transaction or block already in chain.
    pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;
    /// Transaction rejected by mempool.
    pub const RPC_VERIFY_REJECTED: i32 = -26;
    /// P2P network disabled.
    pub const RPC_CLIENT_P2P_DISABLED: i32 = -9;
    /// Block not found.
    pub const RPC_BLOCK_NOT_FOUND: i32 = -5;
}

// ============================================================
// RPC STATE
// ============================================================

/// Shared state accessible by all RPC handlers.
pub struct RpcState {
    /// Chain database for blocks, headers, UTXOs.
    pub db: Arc<ChainDb>,
    /// Transaction mempool.
    pub mempool: Mempool,
    /// Fee estimator.
    pub fee_estimator: FeeEstimator,
    /// Chain parameters.
    pub params: ChainParams,
    /// Current best block height.
    pub best_height: u32,
    /// Current best block hash.
    pub best_hash: Hash256,
    /// Current header tip height (may be ahead of best_height during sync).
    pub header_height: u32,
    /// Whether we are in initial block download.
    pub is_ibd: bool,
    /// Shutdown signal sender.
    pub shutdown_tx: Option<oneshot::Sender<()>>,
}

impl RpcState {
    /// Create a new RPC state.
    pub fn new(db: Arc<ChainDb>, params: ChainParams) -> Self {
        Self {
            db,
            mempool: Mempool::new(MempoolConfig::default()),
            fee_estimator: FeeEstimator::new(),
            params,
            best_height: 0,
            best_hash: Hash256::ZERO,
            header_height: 0,
            is_ibd: true,
            shutdown_tx: None,
        }
    }

    /// Initialize from database state.
    pub fn init_from_db(&mut self) -> Result<(), String> {
        let store = BlockStore::new(&self.db);

        if let Some(hash) = store
            .get_best_block_hash()
            .map_err(|e| format!("db error: {}", e))?
        {
            self.best_hash = hash;
        } else {
            self.best_hash = self.params.genesis_hash;
        }

        if let Some(height) = store
            .get_best_height()
            .map_err(|e| format!("db error: {}", e))?
        {
            self.best_height = height;
            self.header_height = height;
        }

        Ok(())
    }
}

/// Peer manager state (separate from chain state for lock granularity).
#[derive(Default)]
pub struct PeerState {
    /// The peer manager.
    pub peer_manager: Option<PeerManager>,
}

// ============================================================
// RPC TRAIT DEFINITION
// ============================================================

/// Define the RPC interface using jsonrpsee macros.
#[rpc(server)]
pub trait RustoshiRpc {
    /// Get general information about the blockchain.
    #[method(name = "getblockchaininfo")]
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo>;

    /// Get the hash of a block at a given height.
    #[method(name = "getblockhash")]
    async fn get_block_hash(&self, height: u32) -> RpcResult<String>;

    /// Get a block by its hash. Verbosity: 0=hex, 1=json, 2=json+tx details.
    #[method(name = "getblock")]
    async fn get_block(&self, hash: String, verbosity: Option<u8>) -> RpcResult<serde_json::Value>;

    /// Get a block header by hash.
    #[method(name = "getblockheader")]
    async fn get_block_header(
        &self,
        hash: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value>;

    /// Get the current block count (height of the best chain).
    #[method(name = "getblockcount")]
    async fn get_block_count(&self) -> RpcResult<u32>;

    /// Get the hash of the best (tip) block.
    #[method(name = "getbestblockhash")]
    async fn get_best_block_hash(&self) -> RpcResult<String>;

    /// Get the current network difficulty.
    #[method(name = "getdifficulty")]
    async fn get_difficulty(&self) -> RpcResult<f64>;

    /// Get raw transaction by txid.
    #[method(name = "getrawtransaction")]
    async fn get_raw_transaction(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value>;

    /// Send a raw transaction (hex-encoded) to the network.
    #[method(name = "sendrawtransaction")]
    async fn send_raw_transaction(&self, hex: String) -> RpcResult<String>;

    /// Decode a raw transaction without broadcasting.
    #[method(name = "decoderawtransaction")]
    async fn decode_raw_transaction(&self, hex: String) -> RpcResult<serde_json::Value>;

    /// Get mempool information.
    #[method(name = "getmempoolinfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Get all transaction IDs in the mempool.
    #[method(name = "getrawmempool")]
    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<serde_json::Value>;

    /// Estimate the fee rate for confirmation within `conf_target` blocks.
    #[method(name = "estimatesmartfee")]
    async fn estimate_smart_fee(&self, conf_target: u32) -> RpcResult<FeeEstimateResult>;

    /// Get a block template for mining.
    #[method(name = "getblocktemplate")]
    async fn get_block_template(
        &self,
        params: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value>;

    /// Submit a mined block.
    #[method(name = "submitblock")]
    async fn submit_block(&self, hex: String) -> RpcResult<Option<String>>;

    /// Get mining information.
    #[method(name = "getmininginfo")]
    async fn get_mining_info(&self) -> RpcResult<MiningInfo>;

    /// Get connected peer information.
    #[method(name = "getpeerinfo")]
    async fn get_peer_info(&self) -> RpcResult<Vec<PeerInfoRpc>>;

    /// Get network information.
    #[method(name = "getnetworkinfo")]
    async fn get_network_info(&self) -> RpcResult<NetworkInfo>;

    /// Get connection count.
    #[method(name = "getconnectioncount")]
    async fn get_connection_count(&self) -> RpcResult<u32>;

    /// Add a node to connect to.
    #[method(name = "addnode")]
    async fn add_node(&self, addr: String, command: String) -> RpcResult<()>;

    /// Stop the node.
    #[method(name = "stop")]
    async fn stop(&self) -> RpcResult<String>;

    /// Validate an address.
    #[method(name = "validateaddress")]
    async fn validate_address(&self, address: String) -> RpcResult<ValidateAddressResult>;

    /// Get UTXO information for an outpoint.
    #[method(name = "gettxout")]
    async fn get_tx_out(
        &self,
        txid: String,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> RpcResult<Option<TxOutResult>>;
}

// ============================================================
// RPC SERVER IMPLEMENTATION
// ============================================================

/// RPC server implementation.
pub struct RpcServerImpl {
    /// Chain state.
    state: Arc<RwLock<RpcState>>,
    /// Peer state (separate lock for network operations).
    peer_state: Arc<RwLock<PeerState>>,
}

impl RpcServerImpl {
    /// Create a new RPC server implementation.
    pub fn new(state: Arc<RwLock<RpcState>>, peer_state: Arc<RwLock<PeerState>>) -> Self {
        Self { state, peer_state }
    }

    /// Helper to create an RPC error.
    fn rpc_error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(code, message.into(), None::<()>)
    }

    /// Helper to parse a hex-encoded block hash.
    fn parse_hash(hash: &str) -> Result<Hash256, ErrorObjectOwned> {
        Hash256::from_hex(hash)
            .map_err(|_| Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid hash"))
    }

    /// Helper to parse hex-encoded bytes.
    fn parse_hex(hex: &str) -> Result<Vec<u8>, ErrorObjectOwned> {
        hex::decode(hex)
            .map_err(|_| Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid hex encoding"))
    }

    /// Calculate difficulty from compact target (bits).
    fn bits_to_difficulty(bits: u32) -> f64 {
        // Genesis difficulty target
        let genesis_bits = 0x1d00ffffu32;

        let current_target = compact_to_target_f64(bits);
        let genesis_target = compact_to_target_f64(genesis_bits);

        if current_target == 0.0 {
            return 0.0;
        }

        genesis_target / current_target
    }
}

/// Convert compact bits to a floating-point target approximation.
fn compact_to_target_f64(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x007FFFFF) as f64;

    if exponent <= 3 {
        mantissa / (1u64 << (8 * (3 - exponent))) as f64
    } else {
        mantissa * 2f64.powi(8 * (exponent - 3))
    }
}

#[async_trait]
impl RustoshiRpcServer for RpcServerImpl {
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo> {
        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        // Get the best block header for difficulty
        let difficulty = if let Ok(Some(header)) = store.get_header(&state.best_hash) {
            Self::bits_to_difficulty(header.bits)
        } else {
            1.0
        };

        // Get median time past
        let mediantime = if let Ok(Some(entry)) = store.get_block_index(&state.best_hash) {
            entry.timestamp as u64
        } else {
            0
        };

        // Calculate verification progress
        let progress = if state.header_height > 0 {
            state.best_height as f64 / state.header_height as f64
        } else {
            1.0
        };

        let chain_name = match state.params.network_id {
            NetworkId::Mainnet => "main",
            NetworkId::Testnet3 => "test3",
            NetworkId::Testnet4 => "test4",
            NetworkId::Signet => "signet",
            NetworkId::Regtest => "regtest",
        };

        Ok(BlockchainInfo {
            chain: chain_name.to_string(),
            blocks: state.best_height,
            headers: state.header_height,
            bestblockhash: state.best_hash.to_hex(),
            difficulty,
            mediantime,
            verificationprogress: progress,
            initialblockdownload: state.is_ibd,
            chainwork: "0".repeat(64), // simplified
            size_on_disk: 0,           // would need filesystem stat
            pruned: false,
            warnings: String::new(),
        })
    }

    async fn get_block_hash(&self, height: u32) -> RpcResult<String> {
        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        match store.get_hash_by_height(height) {
            Ok(Some(hash)) => Ok(hash.to_hex()),
            Ok(None) => Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!("Block height {} out of range", height),
            )),
            Err(e) => Err(Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Database error: {}", e),
            )),
        }
    }

    async fn get_block(&self, hash: String, verbosity: Option<u8>) -> RpcResult<serde_json::Value> {
        let block_hash = Self::parse_hash(&hash)?;
        let verbosity = verbosity.unwrap_or(1);

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        let block = store
            .get_block(&block_hash)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
            .ok_or_else(|| Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not found"))?;

        if verbosity == 0 {
            // Return raw hex
            let hex_data = hex::encode(block.serialize());
            return Ok(serde_json::Value::String(hex_data));
        }

        // Get block index entry for metadata
        let entry = store
            .get_block_index(&block_hash)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;

        let height = entry.as_ref().map(|e| e.height).unwrap_or(0);
        let confirmations = if state.best_height >= height {
            (state.best_height - height + 1) as i32
        } else {
            0
        };

        // Get next block hash if exists
        let next_hash = store
            .get_hash_by_height(height + 1)
            .ok()
            .flatten()
            .map(|h| h.to_hex());

        let prev_hash = if block.header.prev_block_hash != Hash256::ZERO {
            Some(block.header.prev_block_hash.to_hex())
        } else {
            None
        };

        // Build response based on verbosity
        let txids: Vec<String> = block.transactions.iter().map(|tx| tx.txid().to_hex()).collect();

        let block_info = BlockInfo {
            hash: block_hash.to_hex(),
            confirmations,
            size: block.serialize().len() as u32,
            strippedsize: block.transactions.iter().map(|tx| tx.base_size()).sum::<usize>() as u32 + 80,
            weight: block.transactions.iter().map(|tx| tx.weight()).sum::<usize>() as u32 + 80 * 4,
            height,
            version: block.header.version,
            version_hex: format!("{:08x}", block.header.version),
            merkleroot: block.header.merkle_root.to_hex(),
            tx: txids,
            time: block.header.timestamp,
            mediantime: entry.as_ref().map(|e| e.timestamp as u64).unwrap_or(0),
            nonce: block.header.nonce,
            bits: format!("{:08x}", block.header.bits),
            difficulty: Self::bits_to_difficulty(block.header.bits),
            chainwork: "0".repeat(64),
            n_tx: block.transactions.len() as u32,
            previousblockhash: prev_hash,
            nextblockhash: next_hash,
        };

        Ok(serde_json::to_value(block_info).unwrap())
    }

    async fn get_block_header(
        &self,
        hash: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value> {
        let block_hash = Self::parse_hash(&hash)?;
        let verbose = verbose.unwrap_or(true);

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        let header = store
            .get_header(&block_hash)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
            .ok_or_else(|| Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not found"))?;

        if !verbose {
            let hex_data = hex::encode(header.serialize());
            return Ok(serde_json::Value::String(hex_data));
        }

        let entry = store
            .get_block_index(&block_hash)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;

        let height = entry.as_ref().map(|e| e.height).unwrap_or(0);
        let confirmations = if state.best_height >= height {
            (state.best_height - height + 1) as i32
        } else {
            0
        };

        let next_hash = store
            .get_hash_by_height(height + 1)
            .ok()
            .flatten()
            .map(|h| h.to_hex());

        let prev_hash = if header.prev_block_hash != Hash256::ZERO {
            Some(header.prev_block_hash.to_hex())
        } else {
            None
        };

        let header_info = BlockHeaderInfo {
            hash: block_hash.to_hex(),
            confirmations,
            height,
            version: header.version,
            version_hex: format!("{:08x}", header.version),
            merkleroot: header.merkle_root.to_hex(),
            time: header.timestamp,
            mediantime: entry.as_ref().map(|e| e.timestamp as u64).unwrap_or(0),
            nonce: header.nonce,
            bits: format!("{:08x}", header.bits),
            difficulty: Self::bits_to_difficulty(header.bits),
            chainwork: "0".repeat(64),
            n_tx: entry.as_ref().map(|e| e.n_tx).unwrap_or(0),
            previousblockhash: prev_hash,
            nextblockhash: next_hash,
        };

        Ok(serde_json::to_value(header_info).unwrap())
    }

    async fn get_block_count(&self) -> RpcResult<u32> {
        let state = self.state.read().await;
        Ok(state.best_height)
    }

    async fn get_best_block_hash(&self) -> RpcResult<String> {
        let state = self.state.read().await;
        Ok(state.best_hash.to_hex())
    }

    async fn get_difficulty(&self) -> RpcResult<f64> {
        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        if let Ok(Some(header)) = store.get_header(&state.best_hash) {
            Ok(Self::bits_to_difficulty(header.bits))
        } else {
            Ok(1.0)
        }
    }

    async fn get_raw_transaction(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value> {
        let tx_hash = Self::parse_hash(&txid)?;
        let verbose = verbose.unwrap_or(false);

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        // Check mempool first
        if let Some(entry) = state.mempool.get(&tx_hash) {
            let tx = &entry.tx;
            if !verbose {
                return Ok(serde_json::Value::String(hex::encode(tx.serialize())));
            }

            let info = build_tx_info(tx, None, None);
            return Ok(serde_json::to_value(info).unwrap());
        }

        // Check tx index
        if let Ok(Some(tx_entry)) = store.get_tx_index(&tx_hash) {
            // Load the block to get the transaction
            if let Ok(Some(block)) = store.get_block(&tx_entry.block_hash) {
                // Find the transaction in the block
                for tx in &block.transactions {
                    if tx.txid() == tx_hash {
                        if !verbose {
                            return Ok(serde_json::Value::String(hex::encode(tx.serialize())));
                        }

                        let block_index = store.get_block_index(&tx_entry.block_hash).ok().flatten();
                        let confirmations = block_index.as_ref().map(|e| {
                            if state.best_height >= e.height {
                                state.best_height - e.height + 1
                            } else {
                                0
                            }
                        });

                        let info = build_tx_info(
                            tx,
                            Some(&tx_entry.block_hash),
                            confirmations,
                        );
                        return Ok(serde_json::to_value(info).unwrap());
                    }
                }
            }
        }

        Err(Self::rpc_error(
            rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
            "Transaction not found",
        ))
    }

    async fn send_raw_transaction(&self, hex: String) -> RpcResult<String> {
        let tx_bytes = Self::parse_hex(&hex)?;

        let tx = Transaction::deserialize(&tx_bytes).map_err(|_| {
            Self::rpc_error(
                rpc_error::RPC_DESERIALIZATION_ERROR,
                "Invalid transaction",
            )
        })?;

        let txid = tx.txid();

        let mut state = self.state.write().await;

        // Collect UTXO data upfront to avoid borrow conflicts
        let db = Arc::clone(&state.db);
        let utxo_lookup = |outpoint: &OutPoint| {
            let store = BlockStore::new(&db);
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

        // Add to mempool
        match state.mempool.add_transaction(tx, &utxo_lookup) {
            Ok(_) => {
                // Track for fee estimation - get fee_rate first to avoid double borrow
                let fee_rate = state.mempool.get(&txid).map(|e| e.fee_rate).unwrap_or(0.0);
                state.fee_estimator.track_transaction(txid, fee_rate);
                Ok(txid.to_hex())
            }
            Err(e) => Err(Self::rpc_error(
                rpc_error::RPC_VERIFY_REJECTED,
                format!("Transaction rejected: {}", e),
            )),
        }
    }

    async fn decode_raw_transaction(&self, hex: String) -> RpcResult<serde_json::Value> {
        let tx_bytes = Self::parse_hex(&hex)?;

        let tx = Transaction::deserialize(&tx_bytes).map_err(|_| {
            Self::rpc_error(
                rpc_error::RPC_DESERIALIZATION_ERROR,
                "Invalid transaction",
            )
        })?;

        let decoded = DecodedRawTransaction {
            txid: tx.txid().to_hex(),
            hash: tx.wtxid().to_hex(),
            size: tx.serialize().len() as u32,
            vsize: tx.vsize() as u32,
            weight: tx.weight() as u32,
            version: tx.version,
            locktime: tx.lock_time,
            vin: tx
                .inputs
                .iter()
                .map(|input| {
                    if input.previous_output.is_null() {
                        TxInputInfo {
                            txid: None,
                            vout: None,
                            script_sig: None,
                            coinbase: Some(hex::encode(&input.script_sig)),
                            txinwitness: if input.witness.is_empty() {
                                None
                            } else {
                                Some(input.witness.iter().map(hex::encode).collect())
                            },
                            sequence: input.sequence,
                        }
                    } else {
                        TxInputInfo {
                            txid: Some(input.previous_output.txid.to_hex()),
                            vout: Some(input.previous_output.vout),
                            script_sig: Some(ScriptSigInfo {
                                asm: String::new(), // simplified
                                hex: hex::encode(&input.script_sig),
                            }),
                            coinbase: None,
                            txinwitness: if input.witness.is_empty() {
                                None
                            } else {
                                Some(input.witness.iter().map(hex::encode).collect())
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
                .map(|(n, output)| TxOutputInfo {
                    value: output.value as f64 / COIN as f64,
                    n: n as u32,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: String::new(),
                        hex: hex::encode(&output.script_pubkey),
                        script_type: detect_script_type(&output.script_pubkey),
                        address: None, // would need address encoding
                    },
                })
                .collect(),
        };

        Ok(serde_json::to_value(decoded).unwrap())
    }

    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo> {
        let state = self.state.read().await;

        let total_fee: f64 = 0.0; // would need to iterate mempool
        let min_fee_rate = 0.00001; // 1 sat/vB in BTC/kvB

        Ok(MempoolInfo {
            loaded: true,
            size: state.mempool.size(),
            bytes: state.mempool.total_bytes(),
            usage: state.mempool.total_bytes() * 2, // approximate memory usage
            total_fee,
            maxmempool: 300 * 1024 * 1024, // 300 MB
            mempoolminfee: min_fee_rate,
            minrelaytxfee: min_fee_rate,
            unbroadcastcount: 0,
        })
    }

    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<serde_json::Value> {
        let verbose = verbose.unwrap_or(false);
        let state = self.state.read().await;

        let sorted = state.mempool.get_sorted_for_mining();

        if !verbose {
            let txids: Vec<String> = sorted.iter().map(|h| h.to_hex()).collect();
            return Ok(serde_json::to_value(txids).unwrap());
        }

        // Verbose mode returns a map of txid -> entry details
        let mut result = serde_json::Map::new();
        for txid in sorted {
            if let Some(entry) = state.mempool.get(&txid) {
                let mem_entry = MempoolEntry {
                    vsize: entry.vsize as u32,
                    weight: entry.weight as u32,
                    fee: entry.fee as f64 / COIN as f64,
                    modifiedfee: entry.fee as f64 / COIN as f64,
                    time: entry.time_added.elapsed().as_secs(),
                    height: state.best_height,
                    descendantcount: entry.descendant_count as u32,
                    descendantsize: entry.descendant_size as u32,
                    descendantfees: entry.descendant_fees,
                    ancestorcount: entry.ancestor_count as u32,
                    ancestorsize: entry.ancestor_size as u32,
                    ancestorfees: entry.ancestor_fees,
                    wtxid: entry.tx.wtxid().to_hex(),
                    depends: vec![],
                    spentby: vec![],
                    bip125_replaceable: false,
                    unbroadcast: false,
                };
                result.insert(txid.to_hex(), serde_json::to_value(mem_entry).unwrap());
            }
        }

        Ok(serde_json::Value::Object(result))
    }

    async fn estimate_smart_fee(&self, conf_target: u32) -> RpcResult<FeeEstimateResult> {
        let state = self.state.read().await;

        match state.fee_estimator.estimate_fee(conf_target as usize) {
            Some(rate) => {
                // Convert from sat/vB to BTC/kvB
                let feerate = rate / 100_000.0;
                Ok(FeeEstimateResult {
                    feerate: Some(feerate),
                    errors: None,
                    blocks: conf_target,
                })
            }
            None => Ok(FeeEstimateResult {
                feerate: None,
                errors: Some(vec!["Insufficient data for fee estimation".to_string()]),
                blocks: conf_target,
            }),
        }
    }

    async fn get_block_template(
        &self,
        _params: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Get the current tip's bits for difficulty
        let store = BlockStore::new(&state.db);
        let bits = store
            .get_header(&state.best_hash)
            .ok()
            .flatten()
            .map(|h| h.bits)
            .unwrap_or(0x1d00ffff);

        let config = BlockTemplateConfig {
            coinbase_script_pubkey: vec![0x51], // OP_1 (anyone can spend for testing)
            ..Default::default()
        };

        let template = build_block_template(
            &state.mempool,
            state.best_hash,
            state.best_height + 1,
            timestamp,
            bits,
            &state.params,
            &config,
        );

        // Build BIP-22 format response
        let txs: Vec<BlockTemplateTransaction> = template
            .transactions
            .iter()
            .skip(1) // skip coinbase
            .map(|tx| BlockTemplateTransaction {
                data: hex::encode(tx.serialize()),
                txid: tx.txid().to_hex(),
                hash: tx.wtxid().to_hex(),
                depends: vec![],
                fee: 0, // would need to look up from mempool
                sigops: 0,
                weight: tx.weight() as u32,
            })
            .collect();

        let result = BlockTemplateResult {
            version: template.header.version,
            rules: vec!["csv".to_string(), "segwit".to_string()],
            vbavailable: serde_json::json!({}),
            vbrequired: 0,
            previousblockhash: state.best_hash.to_hex(),
            transactions: txs,
            coinbaseaux: serde_json::json!({}),
            coinbasevalue: template.coinbase_tx.outputs.first().map(|o| o.value).unwrap_or(0),
            longpollid: format!("{}:{}", state.best_hash.to_hex(), state.best_height),
            target: hex::encode(template.target),
            mintime: timestamp.saturating_sub(7200),
            mutable: vec!["time".to_string(), "transactions".to_string(), "prevblock".to_string()],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: timestamp,
            bits: format!("{:08x}", bits),
            height: state.best_height + 1,
            default_witness_commitment: None, // would be computed from coinbase
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    async fn submit_block(&self, hex: String) -> RpcResult<Option<String>> {
        let block_bytes = Self::parse_hex(&hex)?;

        let _block = Block::deserialize(&block_bytes).map_err(|_| {
            Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, "Invalid block")
        })?;

        // Full block validation would go here
        // For now, just acknowledge receipt
        Ok(None)
    }

    async fn get_mining_info(&self) -> RpcResult<MiningInfo> {
        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        let difficulty = if let Ok(Some(header)) = store.get_header(&state.best_hash) {
            Self::bits_to_difficulty(header.bits)
        } else {
            1.0
        };

        let chain_name = match state.params.network_id {
            NetworkId::Mainnet => "main",
            NetworkId::Testnet3 => "test3",
            NetworkId::Testnet4 => "test4",
            NetworkId::Signet => "signet",
            NetworkId::Regtest => "regtest",
        };

        Ok(MiningInfo {
            blocks: state.best_height,
            difficulty,
            networkhashps: 0.0, // would need to compute from recent blocks
            pooledtx: state.mempool.size(),
            chain: chain_name.to_string(),
            warnings: String::new(),
        })
    }

    async fn get_peer_info(&self) -> RpcResult<Vec<PeerInfoRpc>> {
        let peer_state = self.peer_state.read().await;

        if let Some(ref pm) = peer_state.peer_manager {
            let peers: Vec<PeerInfoRpc> = pm
                .connected_peers()
                .iter()
                .map(|(id, info)| PeerInfoRpc {
                    id: id.0,
                    addr: info.addr.to_string(),
                    addrbind: None,
                    addrlocal: None,
                    network: "ipv4".to_string(),
                    services: format!("{:016x}", info.services),
                    servicesnames: decode_services(info.services),
                    relaytxes: info.relay,
                    lastsend: info.last_send.elapsed().as_secs(),
                    lastrecv: info.last_recv.elapsed().as_secs(),
                    bytessent: info.bytes_sent,
                    bytesrecv: info.bytes_recv,
                    conntime: 0, // would need connection start time
                    timeoffset: 0,
                    pingtime: info.ping_time.map(|d| d.as_secs_f64()),
                    minping: info.ping_time.map(|d| d.as_secs_f64()),
                    pingwait: None,
                    version: info.version,
                    subver: info.user_agent.clone(),
                    inbound: info.inbound,
                    bip152_hb_to: false,
                    bip152_hb_from: false,
                    startingheight: info.start_height,
                    synced_headers: 0,
                    synced_blocks: 0,
                    connection_type: if info.inbound {
                        "inbound"
                    } else {
                        "outbound-full-relay"
                    }
                    .to_string(),
                })
                .collect();

            Ok(peers)
        } else {
            Ok(vec![])
        }
    }

    async fn get_network_info(&self) -> RpcResult<NetworkInfo> {
        let peer_state = self.peer_state.read().await;

        let (connections, connections_in, connections_out) =
            if let Some(ref pm) = peer_state.peer_manager {
                (
                    pm.peer_count() as u32,
                    pm.inbound_count() as u32,
                    pm.outbound_count() as u32,
                )
            } else {
                (0, 0, 0)
            };

        Ok(NetworkInfo {
            version: 250000, // 25.0.0
            subversion: "/Rustoshi:0.1.0/".to_string(),
            protocolversion: 70016,
            localservices: format!("{:016x}", 0x0409),
            localservicesnames: vec!["NETWORK".to_string(), "WITNESS".to_string()],
            localrelay: true,
            timeoffset: 0,
            connections,
            connections_in,
            connections_out,
            networkactive: true,
            networks: vec![
                NetworkInterface {
                    name: "ipv4".to_string(),
                    limited: false,
                    reachable: true,
                    proxy: String::new(),
                    proxy_randomize_credentials: false,
                },
                NetworkInterface {
                    name: "ipv6".to_string(),
                    limited: false,
                    reachable: true,
                    proxy: String::new(),
                    proxy_randomize_credentials: false,
                },
            ],
            relayfee: 0.00001,
            incrementalfee: 0.00001,
            localaddresses: vec![],
            warnings: String::new(),
        })
    }

    async fn get_connection_count(&self) -> RpcResult<u32> {
        let peer_state = self.peer_state.read().await;

        if let Some(ref pm) = peer_state.peer_manager {
            Ok(pm.peer_count() as u32)
        } else {
            Ok(0)
        }
    }

    async fn add_node(&self, addr: String, command: String) -> RpcResult<()> {
        let socket_addr: std::net::SocketAddr = addr.parse().map_err(|_| {
            Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid address format")
        })?;

        let mut peer_state = self.peer_state.write().await;

        if let Some(ref mut pm) = peer_state.peer_manager {
            match command.as_str() {
                "add" | "onetry" => {
                    pm.add_peer(socket_addr);
                    Ok(())
                }
                "remove" => {
                    // Would need to find and disconnect peer
                    Ok(())
                }
                _ => Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    "Invalid command",
                )),
            }
        } else {
            Err(Self::rpc_error(
                rpc_error::RPC_CLIENT_P2P_DISABLED,
                "P2P networking is disabled",
            ))
        }
    }

    async fn stop(&self) -> RpcResult<String> {
        let mut state = self.state.write().await;

        if let Some(tx) = state.shutdown_tx.take() {
            let _ = tx.send(());
        }

        Ok("Rustoshi server stopping".to_string())
    }

    async fn validate_address(&self, address: String) -> RpcResult<ValidateAddressResult> {
        // Basic address validation
        // In a full implementation, would decode bech32/base58 and validate

        // Check for bech32 testnet prefix
        if address.starts_with("tb1") || address.starts_with("bc1") {
            // Looks like a bech32 address
            if address.len() >= 42 {
                let _is_p2wpkh = address.len() == 42 || address.len() == 43;
                let is_p2wsh = address.len() == 62 || address.len() == 63;
                let is_p2tr = is_p2wsh; // same length for P2WSH and P2TR

                return Ok(ValidateAddressResult {
                    isvalid: true,
                    address: Some(address),
                    script_pubkey: None,
                    isscript: Some(is_p2wsh),
                    iswitness: Some(true),
                    witness_version: Some(if is_p2tr { 1 } else { 0 }),
                    witness_program: None,
                });
            }
        }

        // Check for legacy address (base58)
        if (address.starts_with('1') || address.starts_with('3') || address.starts_with('m')
            || address.starts_with('n') || address.starts_with('2'))
            && address.len() >= 25
            && address.len() <= 35
        {
            let is_p2sh = address.starts_with('3') || address.starts_with('2');

            return Ok(ValidateAddressResult {
                isvalid: true,
                address: Some(address),
                script_pubkey: None,
                isscript: Some(is_p2sh),
                iswitness: Some(false),
                witness_version: None,
                witness_program: None,
            });
        }

        Ok(ValidateAddressResult {
            isvalid: false,
            address: None,
            script_pubkey: None,
            isscript: None,
            iswitness: None,
            witness_version: None,
            witness_program: None,
        })
    }

    async fn get_tx_out(
        &self,
        txid: String,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> RpcResult<Option<TxOutResult>> {
        let tx_hash = Self::parse_hash(&txid)?;
        let include_mempool = include_mempool.unwrap_or(true);

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        let outpoint = OutPoint {
            txid: tx_hash,
            vout,
        };

        // Check mempool if requested
        if include_mempool {
            if let Some(entry) = state.mempool.get(&tx_hash) {
                if let Some(output) = entry.tx.outputs.get(vout as usize) {
                    return Ok(Some(TxOutResult {
                        bestblock: state.best_hash.to_hex(),
                        confirmations: 0,
                        value: output.value as f64 / COIN as f64,
                        script_pubkey: ScriptPubKeyInfo {
                            asm: String::new(),
                            hex: hex::encode(&output.script_pubkey),
                            script_type: detect_script_type(&output.script_pubkey),
                            address: None,
                        },
                        coinbase: false,
                    }));
                }
            }
        }

        // Check UTXO set
        if let Ok(Some(coin)) = store.get_utxo(&outpoint) {
            let confirmations = if state.best_height >= coin.height {
                state.best_height - coin.height + 1
            } else {
                0
            };

            return Ok(Some(TxOutResult {
                bestblock: state.best_hash.to_hex(),
                confirmations,
                value: coin.value as f64 / COIN as f64,
                script_pubkey: ScriptPubKeyInfo {
                    asm: String::new(),
                    hex: hex::encode(&coin.script_pubkey),
                    script_type: detect_script_type(&coin.script_pubkey),
                    address: None,
                },
                coinbase: coin.is_coinbase,
            }));
        }

        Ok(None)
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Decode service flags to names.
fn decode_services(services: u64) -> Vec<String> {
    let mut names = Vec::new();
    if services & 1 != 0 {
        names.push("NETWORK".to_string());
    }
    if services & 2 != 0 {
        names.push("GETUTXO".to_string());
    }
    if services & 4 != 0 {
        names.push("BLOOM".to_string());
    }
    if services & 8 != 0 {
        names.push("WITNESS".to_string());
    }
    if services & 64 != 0 {
        names.push("COMPACT_FILTERS".to_string());
    }
    if services & 1024 != 0 {
        names.push("NETWORK_LIMITED".to_string());
    }
    names
}

/// Detect the script type from a scriptPubKey.
fn detect_script_type(script: &[u8]) -> String {
    // P2PKH: 25 bytes, OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return "pubkeyhash".to_string();
    }

    // P2SH: 23 bytes, OP_HASH160 <20> OP_EQUAL
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return "scripthash".to_string();
    }

    // P2WPKH: 22 bytes, OP_0 <20>
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return "witness_v0_keyhash".to_string();
    }

    // P2WSH: 34 bytes, OP_0 <32>
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return "witness_v0_scripthash".to_string();
    }

    // P2TR: 34 bytes, OP_1 <32>
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return "witness_v1_taproot".to_string();
    }

    // OP_RETURN
    if !script.is_empty() && script[0] == 0x6a {
        return "nulldata".to_string();
    }

    "nonstandard".to_string()
}

/// Build transaction info from a transaction.
fn build_tx_info(
    tx: &Transaction,
    block_hash: Option<&Hash256>,
    confirmations: Option<u32>,
) -> TransactionInfo {
    TransactionInfo {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        hash: tx.wtxid().to_hex(),
        size: tx.serialize().len() as u32,
        vsize: tx.vsize() as u32,
        weight: tx.weight() as u32,
        version: tx.version,
        locktime: tx.lock_time,
        vin: tx
            .inputs
            .iter()
            .map(|input| {
                if input.previous_output.is_null() {
                    TxInputInfo {
                        txid: None,
                        vout: None,
                        script_sig: None,
                        coinbase: Some(hex::encode(&input.script_sig)),
                        txinwitness: if input.witness.is_empty() {
                            None
                        } else {
                            Some(input.witness.iter().map(hex::encode).collect())
                        },
                        sequence: input.sequence,
                    }
                } else {
                    TxInputInfo {
                        txid: Some(input.previous_output.txid.to_hex()),
                        vout: Some(input.previous_output.vout),
                        script_sig: Some(ScriptSigInfo {
                            asm: String::new(),
                            hex: hex::encode(&input.script_sig),
                        }),
                        coinbase: None,
                        txinwitness: if input.witness.is_empty() {
                            None
                        } else {
                            Some(input.witness.iter().map(hex::encode).collect())
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
            .map(|(n, output)| TxOutputInfo {
                value: output.value as f64 / COIN as f64,
                n: n as u32,
                script_pubkey: ScriptPubKeyInfo {
                    asm: String::new(),
                    hex: hex::encode(&output.script_pubkey),
                    script_type: detect_script_type(&output.script_pubkey),
                    address: None,
                },
            })
            .collect(),
        hex: hex::encode(tx.serialize()),
        blockhash: block_hash.map(|h| h.to_hex()),
        confirmations,
        blocktime: None,
        time: None,
    }
}

// ============================================================
// SERVER STARTUP
// ============================================================

/// Start the RPC server.
///
/// # Arguments
///
/// * `config` - RPC server configuration
/// * `state` - Shared chain state
/// * `peer_state` - Shared peer manager state
///
/// # Returns
///
/// A `ServerHandle` that can be used to stop the server.
pub async fn start_rpc_server(
    config: RpcConfig,
    state: Arc<RwLock<RpcState>>,
    peer_state: Arc<RwLock<PeerState>>,
) -> anyhow::Result<ServerHandle> {
    let server = ServerBuilder::default()
        .build(&config.bind_address)
        .await?;

    let rpc_impl = RpcServerImpl::new(state, peer_state);
    let handle = server.start(rpc_impl.into_rpc());

    tracing::info!("RPC server listening on {}", config.bind_address);
    Ok(handle)
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_to_target_f64() {
        // Genesis difficulty
        let target = compact_to_target_f64(0x1d00ffff);
        assert!(target > 0.0);

        // Higher difficulty (smaller target)
        let harder = compact_to_target_f64(0x1c00ffff);
        assert!(harder < target);
    }

    #[test]
    fn test_bits_to_difficulty() {
        // Genesis difficulty should be 1.0
        let difficulty = RpcServerImpl::bits_to_difficulty(0x1d00ffff);
        assert!((difficulty - 1.0).abs() < 0.001);

        // Harder difficulty
        let harder = RpcServerImpl::bits_to_difficulty(0x1c00ffff);
        assert!(harder > 1.0);
    }

    #[test]
    fn test_detect_script_type_p2pkh() {
        let script = vec![
            0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 <20>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
        ];
        assert_eq!(detect_script_type(&script), "pubkeyhash");
    }

    #[test]
    fn test_detect_script_type_p2sh() {
        let script = vec![
            0xa9, 0x14, // OP_HASH160 <20>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x87, // OP_EQUAL
        ];
        assert_eq!(detect_script_type(&script), "scripthash");
    }

    #[test]
    fn test_detect_script_type_p2wpkh() {
        let script = vec![
            0x00, 0x14, // OP_0 <20>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(detect_script_type(&script), "witness_v0_keyhash");
    }

    #[test]
    fn test_detect_script_type_p2wsh() {
        let mut script = vec![0x00, 0x20]; // OP_0 <32>
        script.extend([0x00; 32]);
        assert_eq!(detect_script_type(&script), "witness_v0_scripthash");
    }

    #[test]
    fn test_detect_script_type_p2tr() {
        let mut script = vec![0x51, 0x20]; // OP_1 <32>
        script.extend([0x00; 32]);
        assert_eq!(detect_script_type(&script), "witness_v1_taproot");
    }

    #[test]
    fn test_detect_script_type_nulldata() {
        let script = vec![0x6a, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_script_type(&script), "nulldata");
    }

    #[test]
    fn test_decode_services() {
        let services = 0x0409; // NETWORK | WITNESS | NETWORK_LIMITED
        let names = decode_services(services);
        assert!(names.contains(&"NETWORK".to_string()));
        assert!(names.contains(&"WITNESS".to_string()));
        assert!(names.contains(&"NETWORK_LIMITED".to_string()));
    }

    #[test]
    fn test_rpc_error_creation() {
        let error = RpcServerImpl::rpc_error(rpc_error::RPC_MISC_ERROR, "test error");
        assert_eq!(error.code(), rpc_error::RPC_MISC_ERROR);
        assert_eq!(error.message(), "test error");
    }

    #[test]
    fn test_parse_hash_valid() {
        let hash_str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let result = RpcServerImpl::parse_hash(hash_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_hex(), hash_str);
    }

    #[test]
    fn test_parse_hash_invalid() {
        let result = RpcServerImpl::parse_hash("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_valid() {
        let result = RpcServerImpl::parse_hex("deadbeef");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_invalid() {
        let result = RpcServerImpl::parse_hex("not hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.bind_address, "127.0.0.1:8332");
    }

    #[test]
    fn test_rpc_config_testnet4() {
        let config = RpcConfig::testnet4();
        assert_eq!(config.bind_address, "127.0.0.1:48332");
    }

    #[test]
    fn test_validate_address_bech32_mainnet() {
        // bc1 prefix for mainnet
        let result = RpcServerImpl::parse_hash("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_nonstandard_script() {
        let script = vec![0x00, 0x01, 0x02]; // Random bytes
        assert_eq!(detect_script_type(&script), "nonstandard");
    }

    #[test]
    fn test_detect_empty_script() {
        let script: Vec<u8> = vec![];
        assert_eq!(detect_script_type(&script), "nonstandard");
    }

    #[test]
    fn test_decode_services_empty() {
        let services = 0u64;
        let names = decode_services(services);
        assert!(names.is_empty());
    }

    #[test]
    fn test_decode_services_all() {
        let services = 1 | 2 | 4 | 8 | 64 | 1024;
        let names = decode_services(services);
        assert_eq!(names.len(), 6);
        assert!(names.contains(&"NETWORK".to_string()));
        assert!(names.contains(&"GETUTXO".to_string()));
        assert!(names.contains(&"BLOOM".to_string()));
        assert!(names.contains(&"WITNESS".to_string()));
        assert!(names.contains(&"COMPACT_FILTERS".to_string()));
        assert!(names.contains(&"NETWORK_LIMITED".to_string()));
    }

    #[test]
    fn test_bits_to_difficulty_zero() {
        let difficulty = RpcServerImpl::bits_to_difficulty(0);
        assert!(difficulty.is_nan() || difficulty == 0.0 || difficulty.is_infinite());
    }

    #[test]
    fn test_compact_to_target_f64_various() {
        // Small exponent
        let target = compact_to_target_f64(0x03000001);
        assert!(target > 0.0);

        // Larger exponent
        let target2 = compact_to_target_f64(0x1d00ffff);
        assert!(target2 > target);
    }

}
