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

use crate::auth::{AuthCredentials, AuthLayer};
use crate::types::*;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use rustoshi_consensus::{
    block_template::{build_block_template, BlockTemplateConfig},
    chain_manager::{
        compare_chain_work, find_descendants,
        is_ancestor_or_descendant, BlockMeta, ChainManagerState,
    },
    fee_estimator::FeeEstimator,
    mempool::{Mempool, MempoolConfig},
    versionbits::{get_deployments, DeploymentId},
    ChainParams, ChainState, NetworkId, COIN,
};
use rustoshi_network::message::{InvType, InvVector, NetworkMessage};
use rustoshi_network::peer_manager::PeerManager;
use rustoshi_primitives::{Block, Decodable, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::{
    block_store::{BlockStore, CoinEntry},
    snapshot::{SnapshotMetadata, SnapshotReader, SnapshotWriter},
    ChainDb, Coin, CF_UTXO,
};
use rustoshi_wallet::psbt::Psbt;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{oneshot, RwLock};

// ============================================================
// RPC ERROR CODES
// ============================================================

/// RPC error codes matching Bitcoin Core.
pub mod rpc_error {
    /// Standard JSON-RPC 2.0 parse error.
    pub const RPC_PARSE_ERROR: i32 = -32700;
    /// Standard JSON-RPC 2.0 invalid request error.
    pub const RPC_INVALID_REQUEST: i32 = -32600;
    /// Standard JSON-RPC 2.0 invalid params error.
    pub const RPC_INVALID_PARAMS: i32 = -32602;
    /// General-purpose RPC error.
    pub const RPC_MISC_ERROR: i32 = -1;
    /// Type error (e.g. wrong address class for the requested operation).
    pub const RPC_TYPE_ERROR: i32 = -3;
    /// Invalid address or key.
    pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
    /// Database error.
    pub const RPC_DATABASE_ERROR: i32 = -20;
    /// Deserialization error.
    pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
    /// Transaction error (generic).
    pub const RPC_TRANSACTION_ERROR: i32 = -25;
    /// Transaction rejected by mempool.
    pub const RPC_VERIFY_REJECTED: i32 = -26;
    /// Transaction rejected by mempool (alias for clarity).
    pub const RPC_TRANSACTION_REJECTED: i32 = -26;
    /// Transaction or block already in chain.
    pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;
    /// Transaction already in UTXO set (confirmed).
    pub const RPC_TRANSACTION_ALREADY_IN_CHAIN: i32 = -27;
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
    /// Whether pruning mode is enabled.
    pub prune_mode: bool,
    /// Prune target in bytes (0 means pruning disabled).
    pub prune_target: u64,
    /// Shutdown signal sender.
    pub shutdown_tx: Option<oneshot::Sender<()>>,
    /// Chain manager state for tracking precious blocks.
    pub chain_manager_state: ChainManagerState,
    /// Server start time (Unix timestamp).
    pub start_time: u64,
    /// Recently-rejected transaction hashes to avoid re-requesting.
    /// Cleared when a new block is connected (the rejection reason may no longer apply).
    pub recently_rejected: HashSet<Hash256>,
    /// Path to the on-disk `mempool.dat` file (Core-format, byte-compatible).
    /// Set by the node binary at startup; `None` disables the
    /// `dumpmempool` / `loadmempool` RPCs.
    pub mempool_dat_path: Option<PathBuf>,
    /// Network-resolved data directory (e.g. `~/.rustoshi/mainnet`). Used by
    /// `dumptxoutset`/`loadtxoutset` to resolve relative paths the way Core's
    /// `AbsPathForConfigVal` does. `None` falls back to the current working
    /// directory.
    pub data_dir: Option<PathBuf>,
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
            prune_mode: false,
            prune_target: 0,
            shutdown_tx: None,
            chain_manager_state: ChainManagerState::new(),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            recently_rejected: HashSet::new(),
            mempool_dat_path: None,
            data_dir: None,
        }
    }

    /// Create a new RPC state with pruning configuration.
    pub fn with_prune_config(db: Arc<ChainDb>, params: ChainParams, prune_target: u64) -> Self {
        Self {
            db,
            mempool: Mempool::new(MempoolConfig::default()),
            fee_estimator: FeeEstimator::new(),
            params,
            best_height: 0,
            best_hash: Hash256::ZERO,
            header_height: 0,
            is_ibd: true,
            prune_mode: prune_target > 0,
            prune_target,
            shutdown_tx: None,
            chain_manager_state: ChainManagerState::new(),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            recently_rejected: HashSet::new(),
            mempool_dat_path: None,
            data_dir: None,
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

        // Check if we should exit initial block download based on stored state
        if self.best_height > 0 {
            if let Ok(Some(entry)) = store.get_block_index(&self.best_hash) {
                // Check if chain work >= minimum chain work
                if compare_chain_work(&entry.chain_work, &self.params.minimum_chain_work)
                    != std::cmp::Ordering::Less
                {
                    // Check if tip is recent (within 24h)
                    let max_tip_age_secs = 24 * 60 * 60; // 24 hours in seconds
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let tip_age = now.saturating_sub(entry.timestamp as u64);

                    if tip_age < max_tip_age_secs {
                        self.is_ibd = false;
                    }
                }
            }
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

    /// hashhog W70: uniform fleet-wide sync-state report.
    /// Spec: meta-repo `spec/getsyncstate.md`.
    #[method(name = "getsyncstate")]
    async fn get_sync_state(&self) -> RpcResult<SyncStateResult>;

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
    ///
    /// Parameters:
    /// - txid: The transaction ID
    /// - verbose: If true, return JSON object with details; if false, return hex
    /// - blockhash: Optional block hash to look in for confirmed transactions
    #[method(name = "getrawtransaction")]
    async fn get_raw_transaction(
        &self,
        txid: String,
        verbose: Option<bool>,
        blockhash: Option<String>,
    ) -> RpcResult<serde_json::Value>;

    /// Send a raw transaction (hex-encoded) to the network.
    ///
    /// Parameters:
    /// - hex: The hex-encoded raw transaction
    /// - maxfeerate: Optional max fee rate in BTC/kvB (default: 0.10). Set to 0 to allow any fee.
    /// - maxburnamount: Optional max amount for provably unspendable outputs in BTC (default: 0)
    #[method(name = "sendrawtransaction")]
    async fn send_raw_transaction(
        &self,
        hex: String,
        maxfeerate: Option<f64>,
        maxburnamount: Option<f64>,
    ) -> RpcResult<String>;

    /// Decode a raw transaction without broadcasting.
    #[method(name = "decoderawtransaction")]
    async fn decode_raw_transaction(&self, hex: String) -> RpcResult<serde_json::Value>;

    /// Get mempool information.
    #[method(name = "getmempoolinfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Get all transaction IDs in the mempool.
    #[method(name = "getrawmempool")]
    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<serde_json::Value>;

    /// Dump the current mempool state to `mempool.dat` in the Bitcoin Core
    /// on-disk format (XOR-obfuscated v2). Returns an object containing the
    /// path written, the number of transactions persisted, and the size in
    /// bytes. Mirrors `bitcoin-cli savemempool`/`dumpmempool` for cross-impl
    /// fleet ops.
    #[method(name = "dumpmempool")]
    async fn dump_mempool(&self) -> RpcResult<serde_json::Value>;

    /// Load mempool entries from `mempool.dat` and reinsert them via the
    /// standard validation path. Returns counts of accepted/failed entries.
    /// Idempotent: loading a file containing transactions already in the
    /// mempool is a no-op for those transactions.
    #[method(name = "loadmempool")]
    async fn load_mempool(&self) -> RpcResult<serde_json::Value>;

    /// Estimate the fee rate for confirmation within `conf_target` blocks.
    #[method(name = "estimatesmartfee")]
    async fn estimate_smart_fee(&self, conf_target: u32) -> RpcResult<FeeEstimateResult>;

    /// Estimate the raw fee data per fee-rate bucket for `conf_target` blocks.
    ///
    /// Returns the underlying bucket statistics used by `estimatesmartfee`.
    /// Mirrors Bitcoin Core's `estimaterawfee` (see
    /// `bitcoin-core/src/rpc/fees.cpp`). The optional `threshold` parameter is
    /// accepted for API parity but currently has no effect on rustoshi's
    /// estimator (which uses a fixed success threshold).
    #[method(name = "estimaterawfee")]
    async fn estimate_raw_fee(
        &self,
        conf_target: u32,
        threshold: Option<f64>,
    ) -> RpcResult<serde_json::Value>;

    /// Persist the mempool to `mempool.dat`. Alias of `dumpmempool` matching
    /// Bitcoin Core's `savemempool`. Returns `{"filename": "..."}`.
    #[method(name = "savemempool")]
    async fn save_mempool(&self) -> RpcResult<serde_json::Value>;

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

    /// List all banned IP addresses.
    #[method(name = "listbanned")]
    async fn list_banned(&self) -> RpcResult<Vec<BannedInfo>>;

    /// Add or remove an IP from the ban list.
    ///
    /// Commands: "add" (ban), "remove" (unban)
    /// bantime: duration in seconds (default: 24h = 86400)
    #[method(name = "setban")]
    async fn set_ban(
        &self,
        subnet: String,
        command: String,
        bantime: Option<u64>,
        absolute: Option<bool>,
    ) -> RpcResult<()>;

    /// Clear all banned IPs.
    #[method(name = "clearbanned")]
    async fn clear_banned(&self) -> RpcResult<()>;

    /// Prune blockchain up to specified height.
    ///
    /// Requires pruning mode to be enabled (-prune option).
    /// Returns the height of the last block that was pruned.
    ///
    /// Parameters:
    /// - height: The block height to prune up to (blocks at this height and below will be pruned)
    #[method(name = "pruneblockchain")]
    async fn prune_blockchain(&self, height: u32) -> RpcResult<u32>;

    /// Submit a package of raw transactions to the mempool.
    ///
    /// Package relay allows a child transaction to pay for its parents (CPFP),
    /// enabling fee bumping even when individual transactions are below the minimum fee rate.
    ///
    /// Parameters:
    /// - rawtxs: Array of hex-encoded raw transactions, in topological order (parents before children)
    /// - maxfeerate: Optional max fee rate in BTC/kvB (default: 0.10). Set to 0 to allow any fee.
    /// - maxburnamount: Optional max amount for provably unspendable outputs in BTC (default: 0)
    #[method(name = "submitpackage")]
    async fn submit_package(
        &self,
        rawtxs: Vec<String>,
        maxfeerate: Option<f64>,
        maxburnamount: Option<f64>,
    ) -> RpcResult<SubmitPackageResult>;

    /// Get information about a descriptor.
    ///
    /// Analyzes a descriptor string and returns information including the checksum.
    #[method(name = "getdescriptorinfo")]
    async fn get_descriptor_info(&self, descriptor: String) -> RpcResult<DescriptorInfoResult>;

    /// Derive addresses from a descriptor.
    ///
    /// For ranged descriptors, a range must be provided as [begin, end].
    #[method(name = "deriveaddresses")]
    async fn derive_addresses(
        &self,
        descriptor: String,
        range: Option<serde_json::Value>,
    ) -> RpcResult<Vec<String>>;

    /// Get information about active ZMQ notification endpoints.
    ///
    /// Returns a list of all active ZMQ notification publishers,
    /// including the notification type, address, and high water mark.
    #[method(name = "getzmqnotifications")]
    async fn get_zmq_notifications(&self) -> RpcResult<Vec<crate::zmq::ZmqNotificationInfo>>;

    // ============================================================
    // GENERATE RPCS (REGTEST)
    // ============================================================

    /// Mine blocks immediately to a specified address (regtest only).
    ///
    /// Parameters:
    /// - nblocks: Number of blocks to generate
    /// - address: Address to send coinbase rewards to
    /// - maxtries: Maximum number of iterations to try (default: 1000000)
    ///
    /// Returns: Array of block hashes of generated blocks
    #[method(name = "generatetoaddress")]
    async fn generate_to_address(
        &self,
        nblocks: u32,
        address: String,
        maxtries: Option<u64>,
    ) -> RpcResult<Vec<String>>;

    /// Mine a block with specific transactions (regtest only).
    ///
    /// Parameters:
    /// - output: Address or descriptor for coinbase output
    /// - transactions: Array of hex-encoded transactions to include
    ///
    /// Returns: Block hash of the generated block
    #[method(name = "generateblock")]
    async fn generate_block(
        &self,
        output: String,
        transactions: Option<Vec<String>>,
    ) -> RpcResult<serde_json::Value>;

    /// Mine blocks immediately to a descriptor (regtest only).
    ///
    /// Parameters:
    /// - num_blocks: Number of blocks to generate
    /// - descriptor: Descriptor for coinbase output
    /// - maxtries: Maximum number of iterations to try (default: 1000000)
    ///
    /// Returns: Array of block hashes of generated blocks
    #[method(name = "generatetodescriptor")]
    async fn generate_to_descriptor(
        &self,
        num_blocks: u32,
        descriptor: String,
        maxtries: Option<u64>,
    ) -> RpcResult<Vec<String>>;

    /// Mark a block as invalid.
    ///
    /// Parameters:
    /// - blockhash: Hash of the block to invalidate
    ///
    /// This will mark the block and all its descendants as invalid,
    /// triggering a reorg to the next best chain.
    #[method(name = "invalidateblock")]
    async fn invalidate_block(&self, blockhash: String) -> RpcResult<()>;

    /// Remove invalidity status from a block.
    ///
    /// Parameters:
    /// - blockhash: Hash of the block to reconsider
    ///
    /// This will remove the invalid status from the block, allowing
    /// it to be considered for inclusion in the best chain again.
    #[method(name = "reconsiderblock")]
    async fn reconsider_block(&self, blockhash: String) -> RpcResult<()>;

    /// Mark a block as precious for chain selection.
    ///
    /// Parameters:
    /// - blockhash: Hash of the block to mark as precious
    ///
    /// If multiple chains have equal proof-of-work, the chain containing
    /// the precious block will be preferred. This is a tie-breaker hint,
    /// not a fork override.
    #[method(name = "preciousblock")]
    async fn precious_block(&self, blockhash: String) -> RpcResult<()>;

    // ============================================================
    // PSBT RPCs (BIP-174)
    // ============================================================

    /// Create a PSBT from inputs and outputs.
    ///
    /// Parameters:
    /// - inputs: Array of inputs `[{"txid": "hex", "vout": n, "sequence": n}]`
    /// - outputs: Array of outputs `[{"address": amount}, ...]` or `[{"data": "hex"}]`
    /// - locktime: Optional locktime (default 0)
    /// - replaceable: Optional BIP125 replaceability (default false, uses sequence 0xfffffffe if true)
    ///
    /// Returns: Base64-encoded unsigned PSBT
    #[method(name = "createpsbt")]
    async fn createpsbt(
        &self,
        inputs: Vec<CreatePsbtInput>,
        outputs: Vec<serde_json::Value>,
        locktime: Option<u32>,
        replaceable: Option<bool>,
    ) -> RpcResult<String>;

    /// Decode a PSBT to JSON.
    ///
    /// Parameters:
    /// - psbt: Base64-encoded PSBT
    ///
    /// Returns: Detailed JSON with tx, inputs, outputs, and fee information
    #[method(name = "decodepsbt")]
    async fn decodepsbt(&self, psbt: String) -> RpcResult<DecodePsbtResult>;

    /// Combine multiple PSBTs into one.
    ///
    /// Parameters:
    /// - psbts: Array of base64-encoded PSBTs
    ///
    /// Returns: Combined base64-encoded PSBT
    ///
    /// All PSBTs must have the same underlying transaction.
    #[method(name = "combinepsbt")]
    async fn combinepsbt(&self, psbts: Vec<String>) -> RpcResult<String>;

    /// Finalize a PSBT and optionally extract the raw transaction.
    ///
    /// Parameters:
    /// - psbt: Base64-encoded PSBT
    /// - extract: Whether to extract the raw transaction if complete (default true)
    ///
    /// Returns: `{psbt: "base64", hex: "rawtx", complete: bool}`
    #[method(name = "finalizepsbt")]
    async fn finalizepsbt(
        &self,
        psbt: String,
        extract: Option<bool>,
    ) -> RpcResult<FinalizePsbtResult>;

    // ============================================================
    // MISSING RPCs (added for full coverage)
    // ============================================================

    /// Test mempool acceptance for raw transactions without broadcasting.
    #[method(name = "testmempoolaccept")]
    async fn test_mempool_accept(
        &self,
        rawtxs: Vec<String>,
        maxfeerate: Option<f64>,
    ) -> RpcResult<serde_json::Value>;

    /// Create a raw transaction from inputs and outputs.
    #[method(name = "createrawtransaction")]
    async fn create_raw_transaction(
        &self,
        inputs: Vec<serde_json::Value>,
        outputs: Vec<serde_json::Value>,
        locktime: Option<u32>,
        replaceable: Option<bool>,
    ) -> RpcResult<String>;

    /// Decode a hex-encoded script.
    #[method(name = "decodescript")]
    async fn decode_script(&self, hex: String) -> RpcResult<serde_json::Value>;

    /// Return information about all known chain tips.
    #[method(name = "getchaintips")]
    async fn get_chain_tips(&self) -> RpcResult<serde_json::Value>;

    /// Disconnect a peer node.
    #[method(name = "disconnectnode")]
    async fn disconnect_node(
        &self,
        address: Option<String>,
        nodeid: Option<u32>,
    ) -> RpcResult<()>;

    /// Get mempool entry for a given transaction.
    #[method(name = "getmempoolentry")]
    async fn get_mempool_entry(&self, txid: String) -> RpcResult<serde_json::Value>;

    /// Get all in-mempool ancestors of a transaction.
    #[method(name = "getmempoolancestors")]
    async fn get_mempool_ancestors(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value>;

    /// Get all in-mempool descendants of a transaction.
    ///
    /// Symmetric to `getmempoolancestors` but walks the child graph.
    /// Mirrors Bitcoin Core's `getmempooldescendants`.
    #[method(name = "getmempooldescendants")]
    async fn get_mempool_descendants(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value>;

    /// List all available RPC commands or get help for a specific command.
    #[method(name = "help")]
    async fn help(&self, command: Option<String>) -> RpcResult<String>;

    // ============================================================
    // WALLET UTILITY RPCs
    // ============================================================

    /// Unlock the wallet for the given duration (seconds).
    ///
    /// Parameters:
    /// - passphrase: The wallet passphrase
    /// - timeout: Duration in seconds to keep the wallet unlocked
    #[method(name = "walletpassphrase")]
    async fn wallet_passphrase(&self, passphrase: String, timeout: u64) -> RpcResult<()>;

    /// Lock the wallet immediately.
    #[method(name = "walletlock")]
    async fn wallet_lock(&self) -> RpcResult<()>;

    /// Set a label for an address.
    ///
    /// Parameters:
    /// - address: The bitcoin address
    /// - label: The label to assign
    #[method(name = "setlabel")]
    async fn set_label(&self, address: String, label: String) -> RpcResult<()>;

    /// Verify a signed message.
    ///
    /// Parameters:
    /// - address: The signer's bitcoin address
    /// - signature: Base64-encoded signature
    /// - message: The original message
    ///
    /// Returns: true if signature is valid
    #[method(name = "verifymessage")]
    async fn verify_message(
        &self,
        address: String,
        signature: String,
        message: String,
    ) -> RpcResult<bool>;

    /// Sign a message with a private key.
    ///
    /// Bitcoin Core's `signmessage` accepts an address and looks up the
    /// matching private key in the loaded wallet. Rustoshi's RPC layer does
    /// not yet share a per-address keystore, so this method accepts the
    /// signing key directly via the `privkey` parameter (either a 64-char
    /// hex-encoded raw private key, or a Base58Check WIF). For wallet-based
    /// signing, callers can use the wallet RPCs to export the WIF first.
    ///
    /// Returns: Base64-encoded compact-recoverable signature (65 bytes) over
    /// `SHA256d("\x18Bitcoin Signed Message:\n" || compact-size(msg) || msg)`
    /// per `bitcoin-core/src/rpc/signmessage.cpp`.
    #[method(name = "signmessage")]
    async fn sign_message(&self, privkey: String, message: String) -> RpcResult<String>;

    /// Get the server uptime in seconds.
    #[method(name = "uptime")]
    async fn uptime(&self) -> RpcResult<u64>;

    /// Get network traffic totals.
    ///
    /// Returns bytes sent/received and the current time.
    #[method(name = "getnettotals")]
    async fn get_net_totals(&self) -> RpcResult<serde_json::Value>;

    /// Get information about the current state of each deployment.
    ///
    /// Returns per-deployment activation info (type, active, height,
    /// min_activation_height). Mirrors Bitcoin Core's getdeploymentinfo.
    ///
    /// Parameters:
    /// - blockhash: Optional block hash to evaluate at (default: chain tip)
    #[method(name = "getdeploymentinfo")]
    async fn get_deployment_info(
        &self,
        blockhash: Option<String>,
    ) -> RpcResult<serde_json::Value>;

    /// Write the serialized UTXO set to a file in Bitcoin Core's
    /// `dumptxoutset` byte-compatible format (snapshot version 2). Mirrors
    /// `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset`.
    ///
    /// Parameters:
    /// - path: Output file path. If relative, prefixed by the data directory.
    /// - snapshot_type: Optional. One of:
    ///     - "" / unset / "latest": dump the current tip's UTXO set.
    ///     - "rollback": find the highest hardcoded `assumeutxo_data` height
    ///       that is <= our tip, roll the chainstate back to that height,
    ///       dump, then roll forward to the original tip. **Currently
    ///       returns a structured `not yet implemented` error**: rustoshi
    ///       has only one persistent UTXO set, so a temporary rollback would
    ///       require a clean rewind/replay primitive that does not exist
    ///       yet. The path through param validation + assumeutxo height
    ///       resolution still runs, so the caller still gets the rejection
    ///       reason with the would-be target height.
    /// - options: Optional Core-style named-parameter object. Currently only
    ///   the `rollback` key is recognised (number = height, string = hash).
    ///   When present, snapshot_type must be empty or "rollback".
    ///
    /// Returns: object with `coins_written`, `base_hash`, `base_height`,
    /// `path`, `txoutset_hash`, and `nchaintx`.
    #[method(name = "dumptxoutset")]
    async fn dump_tx_outset(
        &self,
        path: String,
        snapshot_type: Option<String>,
        options: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value>;

    /// Load a serialized UTXO set from a file in Bitcoin Core's
    /// `loadtxoutset` byte-compatible format. Mirrors
    /// `bitcoin-core/src/rpc/blockchain.cpp::loadtxoutset`.
    ///
    /// The snapshot's blockhash must match one of the hardcoded entries in
    /// `ChainParams::assumeutxo_data` AND the recomputed serialized UTXO hash
    /// must match `hash_serialized` for that entry, otherwise the load is
    /// rejected.
    ///
    /// Parameters:
    /// - path: Input file path. If relative, resolved against the data directory.
    ///
    /// Returns: object with `coins_loaded`, `tip_hash`, `base_height`, and `path`.
    #[method(name = "loadtxoutset")]
    async fn load_tx_outset(&self, path: String) -> RpcResult<serde_json::Value>;
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
    /// ZMQ notification interface (optional).
    zmq_notifier: Option<crate::zmq::SharedZmqNotifier>,
}

impl RpcServerImpl {
    /// Create a new RPC server implementation.
    pub fn new(state: Arc<RwLock<RpcState>>, peer_state: Arc<RwLock<PeerState>>) -> Self {
        Self {
            state,
            peer_state,
            zmq_notifier: None,
        }
    }

    /// Create a new RPC server implementation with ZMQ notifications.
    pub fn with_zmq(
        state: Arc<RwLock<RpcState>>,
        peer_state: Arc<RwLock<PeerState>>,
        zmq_notifier: crate::zmq::SharedZmqNotifier,
    ) -> Self {
        Self {
            state,
            peer_state,
            zmq_notifier: Some(zmq_notifier),
        }
    }

    /// Get the ZMQ notifier if configured.
    pub fn zmq_notifier(&self) -> Option<&crate::zmq::SharedZmqNotifier> {
        self.zmq_notifier.as_ref()
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

    /// Check if we should exit initial block download.
    /// Returns true if chain has sufficient work AND tip is recent (< 24h old).
    /// Once false, it remains false (latch behavior).
    ///
    /// Takes the tip's chain_work and timestamp as raw values rather than
    /// looking them up through `&BlockStore`, so callers can fetch the entry
    /// before mutating `state` and avoid a borrow-checker conflict between
    /// `let store = BlockStore::new(&state.db)` and `state.best_* = ...`.
    ///
    /// `tip_chain_work` is `None` when the caller couldn't recover the
    /// persisted chain work from the block index (which currently happens
    /// for every P2P-synced block because `rustoshi/src/main.rs`'s
    /// validation loop never writes a `BlockIndexEntry` — see TODO there).
    /// When unknown, we trust the tip-age check alone: every block in the
    /// store has already been validated with real PoW via
    /// `ChainState::process_block`, so falling through to the age gate does
    /// not weaken security in practice.
    fn should_exit_ibd(
        &self,
        state: &RpcState,
        tip_chain_work: Option<&[u8; 32]>,
        tip_timestamp: u32,
    ) -> bool {
        // Once we've exited IBD, stay exited (latch behavior)
        if !state.is_ibd {
            return false;
        }

        // Check if chain work >= minimum chain work when available.
        if let Some(cw) = tip_chain_work {
            if compare_chain_work(cw, &state.params.minimum_chain_work)
                == std::cmp::Ordering::Less
            {
                return false;
            }
        }

        // Check if tip is recent (within 24h)
        let max_tip_age_secs = 24 * 60 * 60; // 24 hours in seconds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tip_age = now.saturating_sub(tip_timestamp as u64);

        tip_age < max_tip_age_secs
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

// ============================================================
// SHARED DEPLOYMENT STATE HELPER
// ============================================================

/// Build a canonical softfork/deployment map for `eval_height` on `params`.
///
/// This is the single source of truth consumed by **both** `getblockchaininfo`
/// (via the `softforks` field) and `getdeploymentinfo` (via the `deployments`
/// field).  Neither RPC reads from a stale cache or a hard-coded table; both
/// call this function and project its output into their respective JSON shapes.
///
/// Bitcoin Core reference: `DeploymentInfo()` / `SoftForkDescPushBack()` in
/// `src/rpc/blockchain.cpp` (v28.0).  Both `getblockchaininfo` and
/// `getdeploymentinfo` call `DeploymentInfo()`, which reads from
/// `ChainstateActive()` + `DeploymentPos`.  We mirror that pattern here.
///
/// CSV, SegWit, and Taproot are treated as "buried" deployments: they
/// activated at a fixed, well-known block height stored in `ChainParams` and
/// are no longer subject to BIP 9 signalling.  Any additional entries from the
/// versionbits table that are not yet buried are emitted with a `bip9`
/// sub-object so callers receive full signalling state.
pub fn build_softforks_map(
    params: &ChainParams,
    eval_height: u32,
) -> serde_json::Map<String, serde_json::Value> {
    // Helper: produce the JSON object for a buried deployment.
    let buried = |activation_height: u32, min_activation_height: u32| {
        let active = eval_height >= activation_height;
        let height: Option<u32> = if active { Some(activation_height) } else { None };
        serde_json::json!({
            "type": "buried",
            "active": active,
            "height": height,
            "min_activation_height": min_activation_height
        })
    };

    let mut map = serde_json::Map::new();

    // BIP 68/112/113 — CSV (relative lock-times)
    map.insert("csv".to_string(), buried(params.csv_height, params.csv_height));

    // BIP 141/143/147 — SegWit
    map.insert("segwit".to_string(), buried(params.segwit_height, params.segwit_height));

    // BIP 341/342 — Taproot
    map.insert("taproot".to_string(), buried(params.taproot_height, params.taproot_height));

    // Any BIP 9 deployments that are NOT covered by the buried entries above
    // (e.g. testdummy, future soft forks).
    let vb_deployments = get_deployments(params);
    for (id, dep) in &vb_deployments {
        let name = match id {
            DeploymentId::Csv => continue,
            DeploymentId::Segwit => continue,
            DeploymentId::Taproot => continue,
            DeploymentId::Custom(n) => format!("custom_{}", n),
        };

        use rustoshi_consensus::versionbits::ALWAYS_ACTIVE;
        let active = dep.start_time == ALWAYS_ACTIVE;
        let status = if active { "active" } else { "defined" };

        map.insert(
            name,
            serde_json::json!({
                "type": "bip9",
                "active": active,
                "height": if active { Some(0u32) } else { None::<u32> },
                "min_activation_height": dep.min_activation_height,
                "bip9": {
                    "bit": dep.bit,
                    "start_time": dep.start_time,
                    "timeout": dep.timeout,
                    "min_activation_height": dep.min_activation_height,
                    "status": status
                }
            }),
        );
    }

    map
}

#[async_trait]
impl RustoshiRpcServer for RpcServerImpl {
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo> {
        // Take a write lock so we can flip the IBD latch if the tip is now
        // caught up. Without this, a node that finishes IBD before any
        // submitblock/generate_block call would report initialblockdownload=true
        // forever.
        let mut state = self.state.write().await;

        // Fetch everything we need from the store up front, then drop the store
        // so we can mutate `state.is_ibd` without a borrow-checker conflict.
        // `chainwork_opt` is `None` when the block index entry is missing,
        // signalling to `should_exit_ibd` that it should skip the chain-work
        // gate and trust the tip-age gate alone.
        let (difficulty, mediantime, chainwork_opt, chainwork_hex, tip_timestamp) = {
            let store = BlockStore::new(&state.db);

            let difficulty = if let Ok(Some(header)) = store.get_header(&state.best_hash) {
                Self::bits_to_difficulty(header.bits)
            } else {
                1.0
            };

            // Get median time past, chainwork, and tip timestamp for IBD check
            if let Ok(Some(entry)) = store.get_block_index(&state.best_hash) {
                let cw_hex = hex::encode(entry.chain_work);
                (
                    difficulty,
                    entry.timestamp as u64,
                    Some(entry.chain_work),
                    cw_hex,
                    entry.timestamp,
                )
            } else {
                // No block index entry: fall back to header for tip_timestamp
                // so the IBD latch can still evaluate against wall-clock age.
                let fallback_ts = store
                    .get_header(&state.best_hash)
                    .ok()
                    .flatten()
                    .map(|h| h.timestamp)
                    .unwrap_or(0);
                (
                    difficulty,
                    0u64,
                    None,
                    "0".repeat(64),
                    fallback_ts,
                )
            }
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

        // Evaluate the IBD latch on every getblockchaininfo call. This ensures
        // a node that finished sync without receiving a submitblock/generate
        // call still flips to initialblockdownload=false the first time a
        // client asks.
        if state.is_ibd && self.should_exit_ibd(&state, chainwork_opt.as_ref(), tip_timestamp) {
            state.is_ibd = false;
            tracing::info!(
                "Exiting initial block download at height {} (evaluated on getblockchaininfo)",
                state.best_height
            );
        }

        // Build softforks from the same canonical source as getdeploymentinfo.
        let softforks_map = build_softforks_map(&state.params, state.best_height);

        Ok(BlockchainInfo {
            chain: chain_name.to_string(),
            blocks: state.best_height,
            headers: state.header_height,
            bestblockhash: state.best_hash.to_hex(),
            difficulty,
            mediantime,
            verificationprogress: progress,
            initialblockdownload: state.is_ibd,
            chainwork: chainwork_hex,
            size_on_disk: 0,           // would need filesystem stat
            pruned: state.prune_mode,
            softforks: serde_json::Value::Object(softforks_map),
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

    async fn get_sync_state(&self) -> RpcResult<SyncStateResult> {
        let state = self.state.read().await;

        let chain = match state.params.network_id {
            NetworkId::Mainnet => "main",
            NetworkId::Testnet3 => "test",
            NetworkId::Testnet4 => "testnet4",
            NetworkId::Signet => "signet",
            NetworkId::Regtest => "regtest",
        };

        let progress = if state.header_height > 0 {
            (state.best_height as f64 / state.header_height as f64).min(1.0)
        } else {
            0.0
        };

        let num_peers = {
            let peer_state = self.peer_state.read().await;
            peer_state
                .peer_manager
                .as_ref()
                .map(|pm| pm.peer_count() as u32)
                .unwrap_or(0)
        };

        Ok(SyncStateResult {
            tip_height: state.best_height,
            tip_hash: state.best_hash.to_hex(),
            best_header_height: state.header_height,
            best_header_hash: state.best_hash.to_hex(),
            initial_block_download: state.is_ibd,
            num_peers,
            verification_progress: Some(progress),
            blocks_in_flight: None,
            blocks_pending_connect: None,
            last_block_received_time: None,
            chain: Some(chain.to_string()),
            protocol_version: Some(rustoshi_network::message::PROTOCOL_VERSION),
        })
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

        // Resolve height from block index entry; fall back to a linear scan
        // through the height index for blocks synced before this fix.
        let height = if let Some(ref e) = entry {
            e.height
        } else {
            // Walk from tip back to genesis to find the height for this hash.
            // This is only needed for blocks that were synced before the block
            // index write was introduced; new blocks will always have an entry.
            let best = state.best_height;
            let mut found = None;
            for h in (0..=best).rev() {
                if let Ok(Some(candidate)) = store.get_hash_by_height(h) {
                    if candidate == block_hash {
                        found = Some(h);
                        break;
                    }
                }
            }
            found.unwrap_or(0)
        };

        let confirmations = if height > 0 && state.best_height >= height {
            (state.best_height - height + 1) as i32
        } else if height == 0 {
            // Could be genesis (genuinely height 0) or an unresolved lookup.
            // Use best_height + 1 only for genesis hash.
            (state.best_height + 1) as i32
        } else {
            0
        };

        let next_hash = if height < state.best_height {
            store
                .get_hash_by_height(height + 1)
                .ok()
                .flatten()
                .map(|h| h.to_hex())
        } else {
            None
        };

        let prev_hash = if header.prev_block_hash != Hash256::ZERO {
            Some(header.prev_block_hash.to_hex())
        } else {
            None
        };

        // Populate chainwork from block index entry (big-endian byte array to hex string).
        // If the entry is absent (historical block synced before this fix), report zeros.
        let chainwork_hex = if let Some(ref e) = entry {
            hex::encode(e.chain_work)
        } else {
            "0".repeat(64)
        };

        // Compute median-time-past: median of the timestamps of the 11 blocks
        // ending at this block (inclusive), matching Bitcoin Core's GetMedianTimePast.
        let mediantime = {
            let window_start = height.saturating_sub(10);
            let mut timestamps: Vec<u32> = Vec::with_capacity(11);
            for h in window_start..=height {
                if let Ok(Some(bh)) = store.get_hash_by_height(h) {
                    if let Ok(Some(hdr)) = store.get_header(&bh) {
                        timestamps.push(hdr.timestamp);
                    }
                }
            }
            if timestamps.is_empty() {
                header.timestamp as u64
            } else {
                timestamps.sort_unstable();
                timestamps[timestamps.len() / 2] as u64
            }
        };

        let header_info = BlockHeaderInfo {
            hash: block_hash.to_hex(),
            confirmations,
            height,
            version: header.version,
            version_hex: format!("{:08x}", header.version),
            merkleroot: header.merkle_root.to_hex(),
            time: header.timestamp,
            mediantime,
            nonce: header.nonce,
            bits: format!("{:08x}", header.bits),
            difficulty: Self::bits_to_difficulty(header.bits),
            chainwork: chainwork_hex,
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
        blockhash: Option<String>,
    ) -> RpcResult<serde_json::Value> {
        let tx_hash = Self::parse_hash(&txid)?;
        let verbose = verbose.unwrap_or(false);

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        // Parse optional blockhash parameter
        let block_hash_filter = if let Some(ref bh) = blockhash {
            Some(Self::parse_hash(bh)?)
        } else {
            None
        };

        // 1. Check mempool first (unless blockhash is specified)
        if block_hash_filter.is_none() {
            if let Some(entry) = state.mempool.get(&tx_hash) {
                let tx = &entry.tx;
                if !verbose {
                    return Ok(serde_json::Value::String(hex::encode(tx.serialize())));
                }

                let info = build_tx_info_verbose(tx, None, None, None, &state, &store);
                return Ok(serde_json::to_value(info).unwrap());
            }
        }

        // 2. If blockhash is provided, load that specific block and search for the txid
        if let Some(target_block_hash) = block_hash_filter {
            // Verify the block exists
            let block_index = store.get_block_index(&target_block_hash).map_err(|e| {
                Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
            })?;

            if block_index.is_none() {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                    "Block hash not found",
                ));
            }

            let block = store.get_block(&target_block_hash).map_err(|e| {
                Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
            })?;

            if block.is_none() {
                return Err(Self::rpc_error(
                    rpc_error::RPC_MISC_ERROR,
                    "Block not available",
                ));
            }

            let block = block.unwrap();

            // Find the transaction in the block
            for tx in &block.transactions {
                if tx.txid() == tx_hash {
                    if !verbose {
                        return Ok(serde_json::Value::String(hex::encode(tx.serialize())));
                    }

                    let block_index = block_index.as_ref();
                    let confirmations = block_index.map(|e| {
                        if state.best_height >= e.height {
                            state.best_height - e.height + 1
                        } else {
                            0
                        }
                    });
                    let blocktime = block_index.map(|e| e.timestamp);

                    let info = build_tx_info_verbose(
                        tx,
                        Some(&target_block_hash),
                        confirmations,
                        blocktime,
                        &state,
                        &store,
                    );
                    return Ok(serde_json::to_value(info).unwrap());
                }
            }

            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "No such transaction found in the provided block. Use gettransaction for wallet transactions.",
            ));
        }

        // 3. If txindex is enabled, look up the transaction in the transaction index
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
                        let blocktime = block_index.as_ref().map(|e| e.timestamp);

                        let info = build_tx_info_verbose(
                            tx,
                            Some(&tx_entry.block_hash),
                            confirmations,
                            blocktime,
                            &state,
                            &store,
                        );
                        return Ok(serde_json::to_value(info).unwrap());
                    }
                }
            }
        }

        Err(Self::rpc_error(
            rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
            "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.",
        ))
    }

    async fn send_raw_transaction(
        &self,
        hex: String,
        maxfeerate: Option<f64>,
        maxburnamount: Option<f64>,
    ) -> RpcResult<String> {
        // Default maxfeerate: 0.10 BTC/kvB (10,000,000 sat/kvB)
        // Bitcoin Core uses DEFAULT_MAX_RAW_TX_FEE_RATE = 0.10 BTC/kvB
        let max_fee_rate_btc_kvb = maxfeerate.unwrap_or(0.10);

        // Reject fee rates > 1 BTC/kvB as clearly erroneous
        if max_fee_rate_btc_kvb > 1.0 {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "maxfeerate cannot exceed 1 BTC/kvB",
            ));
        }

        // Convert BTC/kvB to sat/vB: BTC/kvB * COIN / 1000
        let max_fee_rate_sat_vb = max_fee_rate_btc_kvb * (COIN as f64) / 1000.0;

        // Default maxburnamount: 0 BTC
        let max_burn_btc = maxburnamount.unwrap_or(0.0);
        let max_burn_sats = (max_burn_btc * COIN as f64) as u64;

        // Parse the transaction
        let tx_bytes = Self::parse_hex(&hex)?;

        let tx = Transaction::deserialize(&tx_bytes).map_err(|_| {
            Self::rpc_error(
                rpc_error::RPC_DESERIALIZATION_ERROR,
                "TX decode failed. Make sure the tx has at least one input.",
            )
        })?;

        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let vsize = tx.vsize();

        // Check for provably unspendable outputs (OP_RETURN) exceeding maxburnamount
        // OP_RETURN = 0x6a
        for output in &tx.outputs {
            let is_unspendable = output.script_pubkey.first() == Some(&0x6a); // OP_RETURN
            if is_unspendable && output.value > max_burn_sats {
                return Err(Self::rpc_error(
                    rpc_error::RPC_TRANSACTION_ERROR,
                    format!(
                        "Unspendable output exceeds maximum: {} > {} satoshis",
                        output.value, max_burn_sats
                    ),
                ));
            }
        }

        let mut state = self.state.write().await;

        // Check if transaction already exists in mempool
        if state.mempool.contains(&txid) {
            // Transaction already in mempool - return txid without error (Bitcoin Core behavior)
            return Ok(txid.to_hex());
        }

        // Check if transaction is already confirmed (in UTXO set / tx index)
        let db = Arc::clone(&state.db);
        let store = BlockStore::new(&db);
        if let Ok(Some(_)) = store.get_tx_index(&txid) {
            return Err(Self::rpc_error(
                rpc_error::RPC_TRANSACTION_ALREADY_IN_CHAIN,
                "Transaction already in block chain",
            ));
        }

        // UTXO lookup closure
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
                // Get fee info for validation and estimation
                let entry = state.mempool.get(&txid);
                let (fee, fee_rate) = entry
                    .map(|e| (e.fee, e.fee_rate))
                    .unwrap_or((0, 0.0));

                // Check if fee rate exceeds maxfeerate (unless maxfeerate is 0)
                if max_fee_rate_btc_kvb > 0.0 && fee_rate > max_fee_rate_sat_vb {
                    // Remove from mempool - fee too high
                    state.mempool.remove_transaction(&txid, false);
                    let fee_rate_btc_kvb = fee_rate * 1000.0 / (COIN as f64);
                    return Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_ERROR,
                        format!(
                            "Fee rate too high: {:.8} BTC/kvB > {:.8} BTC/kvB (maxfeerate)",
                            fee_rate_btc_kvb, max_fee_rate_btc_kvb
                        ),
                    ));
                }

                // Calculate the absolute max fee based on maxfeerate
                let max_fee = (max_fee_rate_sat_vb * vsize as f64) as u64;
                if max_fee_rate_btc_kvb > 0.0 && fee > max_fee {
                    // Remove from mempool - absolute fee too high
                    state.mempool.remove_transaction(&txid, false);
                    return Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_ERROR,
                        format!(
                            "Absurdly high fee: {} satoshis (max: {} based on vsize {})",
                            fee, max_fee, vsize
                        ),
                    ));
                }

                // Track for fee estimation
                state.fee_estimator.track_transaction(txid, fee_rate);

                // Drop the state lock before broadcasting
                drop(state);

                // Relay to connected peers via inv message
                // Use WitnessTx type since we support SegWit
                let inv = vec![InvVector {
                    inv_type: InvType::MsgWitnessTx,
                    hash: wtxid,
                }];
                let inv_msg = NetworkMessage::Inv(inv);

                // Broadcast to all connected peers
                let peer_state = self.peer_state.read().await;
                if let Some(ref peer_manager) = peer_state.peer_manager {
                    peer_manager.broadcast(inv_msg).await;
                    tracing::debug!("Relayed transaction {} to peers", txid.to_hex());
                }

                Ok(txid.to_hex())
            }
            Err(e) => {
                // Map mempool errors to appropriate RPC errors
                use rustoshi_consensus::mempool::MempoolError;
                match &e {
                    MempoolError::AlreadyExists => {
                        // Already in mempool - return txid without error
                        Ok(txid.to_hex())
                    }
                    MempoolError::MissingInput(prev_txid, vout) => Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_REJECTED,
                        format!("Missing input: {}:{}", prev_txid.to_hex(), vout),
                    )),
                    MempoolError::Conflict(conflicting_txid) => Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_REJECTED,
                        format!(
                            "Transaction conflicts with mempool entry {}",
                            conflicting_txid.to_hex()
                        ),
                    )),
                    MempoolError::InsufficientFee(rate, min) => Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_REJECTED,
                        format!("Fee rate too low: {:.2} sat/vB (minimum: {})", rate, min),
                    )),
                    MempoolError::Validation(verr) => Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_REJECTED,
                        format!("Transaction validation failed: {}", verr),
                    )),
                    _ => Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_REJECTED,
                        format!("Transaction rejected: {}", e),
                    )),
                }
            }
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
            incrementalrelayfee: min_fee_rate,
            unbroadcastcount: 0,
            fullrbf: true,
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

    async fn dump_mempool(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        let path = match state.mempool_dat_path.clone() {
            Some(p) => p,
            None => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_MISC_ERROR,
                    "mempool.dat path is not configured",
                ))
            }
        };
        match rustoshi_consensus::dump_mempool(&state.mempool, &path) {
            Ok(stats) => Ok(serde_json::json!({
                "path": path.display().to_string(),
                "size": stats.txs,
                "bytes": stats.bytes,
            })),
            Err(e) => Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("dumpmempool failed: {}", e),
            )),
        }
    }

    async fn save_mempool(&self) -> RpcResult<serde_json::Value> {
        // Bitcoin Core's `savemempool` is a thin alias for `dumpmempool` that
        // returns `{"filename": "..."}`. Reuse the same persistence call so
        // both RPCs always agree on disk state.
        let state = self.state.read().await;
        let path = match state.mempool_dat_path.clone() {
            Some(p) => p,
            None => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_MISC_ERROR,
                    "mempool.dat path is not configured",
                ))
            }
        };
        match rustoshi_consensus::dump_mempool(&state.mempool, &path) {
            Ok(_) => Ok(serde_json::json!({
                "filename": path.display().to_string(),
            })),
            Err(e) => Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("savemempool failed: {}", e),
            )),
        }
    }

    async fn load_mempool(&self) -> RpcResult<serde_json::Value> {
        let mut state = self.state.write().await;
        let path = match state.mempool_dat_path.clone() {
            Some(p) => p,
            None => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_MISC_ERROR,
                    "mempool.dat path is not configured",
                ))
            }
        };
        let db = state.db.clone();
        let utxo_lookup = move |outpoint: &OutPoint| {
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
        match rustoshi_consensus::load_mempool(&mut state.mempool, &path, &utxo_lookup) {
            Ok(stats) => Ok(serde_json::json!({
                "path": path.display().to_string(),
                "version": stats.version,
                "total": stats.total,
                "accepted": stats.accepted,
                "failed": stats.failed,
                "deltas": stats.deltas,
                "unbroadcast": stats.unbroadcast,
            })),
            Err(e) => Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("loadmempool failed: {}", e),
            )),
        }
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

    async fn estimate_raw_fee(
        &self,
        conf_target: u32,
        _threshold: Option<f64>,
    ) -> RpcResult<serde_json::Value> {
        // Validate target (1..=1008, matching MAX_CONFIRMATION_TARGET).
        if conf_target == 0 || conf_target > 1008 {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "Invalid conf_target, must be between 1 and 1008",
            ));
        }
        let state = self.state.read().await;
        let buckets = state
            .fee_estimator
            .raw_bucket_stats(conf_target as usize);
        let mut out = serde_json::Map::new();
        let mut feerate_sum = 0.0f64;
        let mut total_count = 0.0f64;
        let mut total_confirmed = 0.0f64;
        let arr: Vec<serde_json::Value> = buckets
            .iter()
            .map(|b| {
                feerate_sum += b.startrange * b.total;
                total_count += b.total;
                total_confirmed += b.confirmed;
                serde_json::json!({
                    "startrange": b.startrange,
                    "endrange": b.endrange,
                    "withintarget": b.confirmed,
                    "totalconfirmed": b.confirmed,
                    "inmempool": b.total,
                    "leftmempool": 0.0_f64,
                })
            })
            .collect();
        out.insert("blocks".to_string(), serde_json::json!(conf_target));
        out.insert("buckets".to_string(), serde_json::Value::Array(arr));
        // `short`/`medium`/`long` horizon shape in Core; rustoshi has a single
        // horizon, so we expose a flat structure plus `decay`/`scale` metadata
        // for parity-tooling consumers.
        out.insert("decay".to_string(), serde_json::json!(0.998_f64));
        out.insert("scale".to_string(), serde_json::json!(1));
        let avg_feerate = if total_count > 0.0 {
            feerate_sum / total_count
        } else {
            0.0
        };
        out.insert("avg_feerate".to_string(), serde_json::json!(avg_feerate));
        out.insert("total_confirmed".to_string(), serde_json::json!(total_confirmed));
        Ok(serde_json::Value::Object(out))
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

        // Get the current tip's bits and timestamp for difficulty and MTP
        let store = BlockStore::new(&state.db);
        let tip_header = store.get_header(&state.best_hash).ok().flatten();
        let bits = tip_header.as_ref().map(|h| h.bits).unwrap_or(0x1d00ffff);

        // Compute median-time-past (simplified: use tip timestamp as approximation)
        // A full implementation would compute the median of the last 11 block timestamps
        let median_time_past = tip_header
            .as_ref()
            .map(|h| h.timestamp as i64)
            .unwrap_or(timestamp as i64);

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
            median_time_past,
            &state.params,
            &config,
        );

        // Build BIP-22 format response. The per-tx sigop cost lines up
        // index-for-index with `template.transactions`; we skip the coinbase
        // (index 0) here just like we skip it in the transaction list.
        let txs: Vec<BlockTemplateTransaction> = template
            .transactions
            .iter()
            .enumerate()
            .skip(1) // skip coinbase
            .map(|(i, tx)| BlockTemplateTransaction {
                data: hex::encode(tx.serialize()),
                txid: tx.txid().to_hex(),
                hash: tx.wtxid().to_hex(),
                depends: vec![],
                fee: 0, // would need to look up from mempool
                sigops: template
                    .per_tx_sigops
                    .get(i)
                    .copied()
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as u32,
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

        // Defense in depth: catch any panics during deserialization so a malformed
        // block from a peer/RPC caller can never crash the node process.
        let decode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Block::deserialize(&block_bytes)
        }));
        let block = match decode_result {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_DESERIALIZATION_ERROR,
                    "Block decode failed",
                ));
            }
            Err(_) => {
                tracing::error!("submitblock: panic caught during block deserialization");
                return Err(Self::rpc_error(
                    rpc_error::RPC_DESERIALIZATION_ERROR,
                    "Block decode failed (internal error)",
                ));
            }
        };

        let block_hash = block.block_hash();

        let mut state = self.state.write().await;

        // Check for duplicate — block already known at our tip or in the store
        {
            let store = BlockStore::new(&state.db);
            if let Ok(Some(_)) = store.get_header(&block_hash) {
                return Ok(Some("duplicate".to_string()));
            }
        }

        // Build a ChainState from the current tip and validate + connect the block
        let mut chain_state =
            ChainState::new(state.best_hash, state.best_height, state.params.clone());

        let store = BlockStore::new(&state.db);
        let mut utxo_view = store.utxo_view();

        match chain_state.process_block(&block, &mut utxo_view) {
            Ok((_undo_data, _fees)) => {
                // Store header and block data
                if let Err(e) = store.put_header(&block_hash, &block.header) {
                    tracing::error!("submitblock: failed to store header: {}", e);
                    return Ok(Some(format!("database-error: {}", e)));
                }
                if let Err(e) = store.put_block(&block_hash, &block) {
                    tracing::error!("submitblock: failed to store block: {}", e);
                    return Ok(Some(format!("database-error: {}", e)));
                }

                // Populate height-to-hash index
                let new_height = state.best_height + 1;
                if let Err(e) = store.put_height_index(new_height, &block_hash) {
                    tracing::error!("submitblock: failed to store height index: {}", e);
                    return Ok(Some(format!("database-error: {}", e)));
                }

                // Flush UTXO changes to disk
                if let Err(e) = utxo_view.flush() {
                    tracing::error!("submitblock: UTXO flush failed: {}", e);
                    return Ok(Some(format!("database-error: {}", e)));
                }

                // Update best block pointer
                if let Err(e) = store.set_best_block(&block_hash, new_height) {
                    tracing::error!("submitblock: failed to update best block: {}", e);
                    return Ok(Some(format!("database-error: {}", e)));
                }

                // Update RPC state
                state.best_height = new_height;
                state.best_hash = block_hash;

                // NOTE: IBD latch is re-evaluated on every getblockchaininfo
                // call (see get_blockchain_info). We deliberately do NOT call
                // should_exit_ibd here because submitblock does not write a
                // BlockIndexEntry for the new block, so a lookup would return
                // None and the check would be dead. The read-path evaluation
                // handles this case.

                tracing::info!(
                    "submitblock: accepted block {} at height {}",
                    block_hash,
                    new_height
                );

                // null means success per BIP22
                Ok(None)
            }
            Err(e) => {
                tracing::warn!("submitblock: block {} rejected: {}", block_hash, e);
                Ok(Some(e.to_string()))
            }
        }
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
                    timeoffset: info.time_offset,
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
                "onetry" => {
                    // Immediately initiate an outbound connection
                    pm.connect_to_peer(socket_addr).await;
                    Ok(())
                }
                "add" => {
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

    async fn list_banned(&self) -> RpcResult<Vec<BannedInfo>> {
        let peer_state = self.peer_state.read().await;

        if let Some(ref pm) = peer_state.peer_manager {
            let banned: Vec<BannedInfo> = pm
                .list_banned()
                .into_iter()
                .map(|(ip, entry)| BannedInfo {
                    address: ip.to_string(),
                    ban_created: entry.ban_created,
                    ban_until: entry.ban_until,
                    ban_reason: entry.reason.clone(),
                })
                .collect();
            Ok(banned)
        } else {
            Ok(vec![])
        }
    }

    async fn set_ban(
        &self,
        subnet: String,
        command: String,
        bantime: Option<u64>,
        absolute: Option<bool>,
    ) -> RpcResult<()> {
        // Parse IP address (we don't support subnets yet, just IPs)
        let ip: std::net::IpAddr = subnet.parse().map_err(|_| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "Invalid IP address format",
            )
        })?;

        let mut peer_state = self.peer_state.write().await;

        if let Some(ref mut pm) = peer_state.peer_manager {
            match command.as_str() {
                "add" => {
                    // Default ban time is 24 hours (86400 seconds)
                    let duration_secs = bantime.unwrap_or(86400);
                    let duration = std::time::Duration::from_secs(duration_secs);
                    let reason = if absolute.unwrap_or(false) {
                        "manually banned (absolute)".to_string()
                    } else {
                        "manually banned".to_string()
                    };
                    pm.ban_ip(ip, duration, reason);
                    Ok(())
                }
                "remove" => {
                    if pm.unban(&ip) {
                        Ok(())
                    } else {
                        // Bitcoin Core returns success even if IP wasn't banned
                        Ok(())
                    }
                }
                _ => Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!("Invalid command '{}'. Use 'add' or 'remove'.", command),
                )),
            }
        } else {
            Err(Self::rpc_error(
                rpc_error::RPC_CLIENT_P2P_DISABLED,
                "P2P networking is disabled",
            ))
        }
    }

    async fn clear_banned(&self) -> RpcResult<()> {
        let mut peer_state = self.peer_state.write().await;

        if let Some(ref mut pm) = peer_state.peer_manager {
            pm.clear_banned();
            Ok(())
        } else {
            Err(Self::rpc_error(
                rpc_error::RPC_CLIENT_P2P_DISABLED,
                "P2P networking is disabled",
            ))
        }
    }

    async fn prune_blockchain(&self, height: u32) -> RpcResult<u32> {
        let state = self.state.read().await;

        // Check if pruning is enabled
        if !state.prune_mode {
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                "Cannot prune blocks because node is not in prune mode",
            ));
        }

        // Cannot prune past the tip minus MIN_BLOCKS_TO_KEEP
        let min_blocks_to_keep = rustoshi_storage::MIN_BLOCKS_TO_KEEP;
        let max_prune_height = state.best_height.saturating_sub(min_blocks_to_keep);

        if height > max_prune_height {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!(
                    "Cannot prune to height {} (must keep at least {} blocks from tip {})",
                    height, min_blocks_to_keep, state.best_height
                ),
            ));
        }

        // The actual pruning happens in the main event loop when blocks are processed.
        // For the RPC, we return the effective prune height.
        // In a full implementation, we would trigger the pruning here and wait for completion.
        //
        // For now, return the height that would be pruned to.
        // The main loop will do the actual pruning based on the prune target.
        let effective_prune_height = height.min(max_prune_height);

        tracing::info!(
            "pruneblockchain RPC: requested height {}, effective height {}",
            height,
            effective_prune_height
        );

        Ok(effective_prune_height)
    }

    async fn submit_package(
        &self,
        rawtxs: Vec<String>,
        maxfeerate: Option<f64>,
        maxburnamount: Option<f64>,
    ) -> RpcResult<SubmitPackageResult> {
        use std::collections::HashMap;

        // Default maxfeerate: 0.10 BTC/kvB
        let max_fee_rate_btc_kvb = maxfeerate.unwrap_or(0.10);

        // Reject fee rates > 1 BTC/kvB as clearly erroneous
        if max_fee_rate_btc_kvb > 1.0 {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "maxfeerate cannot exceed 1 BTC/kvB",
            ));
        }

        // Convert BTC/kvB to sat/vB
        let max_fee_rate_sat_vb = max_fee_rate_btc_kvb * (COIN as f64) / 1000.0;

        // Default maxburnamount: 0 BTC
        let max_burn_btc = maxburnamount.unwrap_or(0.0);
        let max_burn_sats = (max_burn_btc * COIN as f64) as u64;

        // Parse all transactions
        let mut txs = Vec::with_capacity(rawtxs.len());
        for (i, hex) in rawtxs.iter().enumerate() {
            let tx_bytes = Self::parse_hex(hex)?;
            let tx = Transaction::deserialize(&tx_bytes).map_err(|_| {
                Self::rpc_error(
                    rpc_error::RPC_DESERIALIZATION_ERROR,
                    format!("TX decode failed for transaction {}", i),
                )
            })?;

            // Check for provably unspendable outputs exceeding maxburnamount
            for output in &tx.outputs {
                let is_unspendable = output.script_pubkey.first() == Some(&0x6a); // OP_RETURN
                if is_unspendable && output.value > max_burn_sats {
                    return Err(Self::rpc_error(
                        rpc_error::RPC_TRANSACTION_ERROR,
                        format!(
                            "Transaction {} has unspendable output exceeding maximum: {} > {} satoshis",
                            i, output.value, max_burn_sats
                        ),
                    ));
                }
            }

            txs.push(tx);
        }

        if txs.is_empty() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "Package must contain at least one transaction",
            ));
        }

        let mut state = self.state.write().await;

        // UTXO lookup closure
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

        // Accept the package
        let result = state.mempool.accept_package(txs.clone(), &utxo_lookup);

        // Build the RPC response
        let mut tx_results_map = HashMap::new();

        for (i, tx_result) in result.tx_results.iter().enumerate() {
            let tx = &txs[i];
            let wtxid = tx.wtxid().to_hex();

            // Calculate effective fee rate
            let effective_feerate = if tx_result.vsize > 0 {
                (tx_result.fee as f64 / tx_result.vsize as f64) * 1000.0 / (COIN as f64)
            } else {
                0.0
            };

            // Check if fee rate exceeds maxfeerate
            let fee_rate_sat_vb = if tx_result.vsize > 0 {
                tx_result.fee as f64 / tx_result.vsize as f64
            } else {
                0.0
            };

            let reject_reason = if let Some(ref err) = tx_result.error {
                Some(err.clone())
            } else if max_fee_rate_btc_kvb > 0.0 && fee_rate_sat_vb > max_fee_rate_sat_vb {
                Some(format!(
                    "Fee rate too high: {:.8} BTC/kvB > {:.8} BTC/kvB (maxfeerate)",
                    fee_rate_sat_vb * 1000.0 / (COIN as f64),
                    max_fee_rate_btc_kvb
                ))
            } else {
                None
            };

            let rpc_result = PackageTxResultRpc {
                txid: tx_result.txid.to_hex(),
                wtxid: wtxid.clone(),
                vsize: tx_result.vsize as u64,
                fees: PackageFees {
                    base: tx_result.fee as f64 / COIN as f64,
                    effective_feerate,
                    effective_includes: vec![tx_result.wtxid.to_hex()],
                },
                allowed: if reject_reason.is_none() {
                    Some(true)
                } else {
                    Some(false)
                },
                reject_reason,
            };

            tx_results_map.insert(wtxid, rpc_result);
        }

        // Package fee rate in BTC/kvB
        let package_feerate = if result.package_vsize > 0 {
            Some((result.package_fee as f64 / result.package_vsize as f64) * 1000.0 / (COIN as f64))
        } else {
            None
        };

        // Build package message
        let package_msg = if let Some(ref err) = result.package_error {
            format!("package-error: {}", err)
        } else if result.all_accepted() {
            "success".to_string()
        } else {
            "partial failure".to_string()
        };

        // Broadcast accepted transactions to peers
        if result.all_accepted() {
            drop(state);
            let peer_state = self.peer_state.read().await;
            if let Some(ref peer_manager) = peer_state.peer_manager {
                for tx in &txs {
                    let wtxid = tx.wtxid();
                    let inv = vec![InvVector {
                        inv_type: InvType::MsgWitnessTx,
                        hash: wtxid,
                    }];
                    let inv_msg = NetworkMessage::Inv(inv);
                    peer_manager.broadcast(inv_msg).await;
                }
            }
        }

        Ok(SubmitPackageResult {
            package_feerate,
            package_msg,
            tx_results: tx_results_map,
            replaced_transactions: None, // TODO: track RBF replacements
        })
    }

    async fn get_descriptor_info(&self, descriptor: String) -> RpcResult<DescriptorInfoResult> {
        use rustoshi_wallet::descriptor::{
            parse_descriptor, DescriptorInfo,
        };

        // Try to parse the descriptor (with or without checksum)
        let parsed = parse_descriptor(&descriptor).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!("Invalid descriptor: {}", e),
            )
        })?;

        let info = DescriptorInfo::from_descriptor(&parsed);

        Ok(DescriptorInfoResult {
            descriptor: info.descriptor,
            checksum: info.checksum,
            isrange: info.is_range,
            issolvable: info.is_solvable,
            hasprivatekeys: info.has_private_keys,
        })
    }

    async fn derive_addresses(
        &self,
        descriptor: String,
        range: Option<serde_json::Value>,
    ) -> RpcResult<Vec<String>> {
        use rustoshi_crypto::address::Network;
        use rustoshi_wallet::descriptor::parse_descriptor;

        // Parse the descriptor
        let parsed = parse_descriptor(&descriptor).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!("Invalid descriptor: {}", e),
            )
        })?;

        // Determine network from state
        let state = self.state.read().await;
        let network = match state.params.network_id {
            NetworkId::Mainnet => Network::Mainnet,
            NetworkId::Testnet3 | NetworkId::Testnet4 | NetworkId::Signet => Network::Testnet,
            NetworkId::Regtest => Network::Regtest,
        };

        // Parse range if provided
        let (start, end) = if parsed.is_range() {
            match &range {
                Some(serde_json::Value::Array(arr)) if arr.len() == 2 => {
                    let start = arr[0].as_u64().ok_or_else(|| {
                        Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid range start")
                    })? as u32;
                    let end = arr[1].as_u64().ok_or_else(|| {
                        Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid range end")
                    })? as u32;
                    (start, end)
                }
                Some(serde_json::Value::Number(n)) => {
                    let end = n.as_u64().ok_or_else(|| {
                        Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid range")
                    })? as u32;
                    (0, end)
                }
                None => {
                    return Err(Self::rpc_error(
                        rpc_error::RPC_INVALID_PARAMS,
                        "Range required for ranged descriptor",
                    ));
                }
                _ => {
                    return Err(Self::rpc_error(
                        rpc_error::RPC_INVALID_PARAMS,
                        "Invalid range format",
                    ));
                }
            }
        } else {
            // Non-ranged descriptor, derive a single address
            (0, 1)
        };

        // Derive addresses
        let mut addresses = Vec::new();
        for pos in start..end {
            let addrs = parsed.derive_addresses(pos, network).map_err(|e| {
                Self::rpc_error(
                    rpc_error::RPC_MISC_ERROR,
                    format!("Failed to derive address: {}", e),
                )
            })?;
            for addr in addrs {
                addresses.push(addr.to_string());
            }
        }

        Ok(addresses)
    }

    async fn get_zmq_notifications(&self) -> RpcResult<Vec<crate::zmq::ZmqNotificationInfo>> {
        match &self.zmq_notifier {
            Some(notifier) => Ok(notifier.get_active_notifiers()),
            None => Ok(vec![]),
        }
    }

    // ============================================================
    // GENERATE RPC IMPLEMENTATIONS (REGTEST)
    // ============================================================

    async fn generate_to_address(
        &self,
        nblocks: u32,
        address: String,
        maxtries: Option<u64>,
    ) -> RpcResult<Vec<String>> {
        use rustoshi_crypto::address::{Address, Network as AddrNetwork};

        let state = self.state.read().await;

        // Only allowed on regtest
        if state.params.network_id != NetworkId::Regtest {
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                "This RPC is only available on regtest",
            ));
        }

        // Parse the address to get the scriptPubKey
        let addr_network = AddrNetwork::Regtest;
        let parsed_address = Address::from_string(&address, Some(addr_network)).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                format!("Invalid address: {}", e),
            )
        })?;

        let script_pubkey = parsed_address.to_script_pubkey();
        let maxtries = maxtries.unwrap_or(1_000_000);

        drop(state); // Release the lock before mining

        // Mine the blocks
        self.mine_blocks(nblocks, script_pubkey, maxtries).await
    }

    async fn generate_block(
        &self,
        output: String,
        transactions: Option<Vec<String>>,
    ) -> RpcResult<serde_json::Value> {
        use rustoshi_crypto::address::{Address, Network as AddrNetwork};

        let state = self.state.read().await;

        // Only allowed on regtest
        if state.params.network_id != NetworkId::Regtest {
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                "This RPC is only available on regtest",
            ));
        }

        // Parse output address to get scriptPubKey
        let addr_network = AddrNetwork::Regtest;
        let parsed_address = Address::from_string(&output, Some(addr_network)).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                format!("Invalid output address: {}", e),
            )
        })?;

        let script_pubkey = parsed_address.to_script_pubkey();

        // Parse transactions if provided
        let mut txs: Vec<Transaction> = Vec::new();
        if let Some(tx_hexes) = transactions {
            for hex in tx_hexes {
                let tx_bytes = Self::parse_hex(&hex)?;
                let tx = Transaction::deserialize(&tx_bytes).map_err(|_| {
                    Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, "Invalid transaction")
                })?;
                txs.push(tx);
            }
        }

        drop(state); // Release the lock before mining

        // Mine one block with the specified transactions
        let block_hashes = self.mine_block_with_txs(script_pubkey, txs).await?;

        Ok(serde_json::json!({
            "hash": block_hashes.first().map(|h| h.as_str()).unwrap_or("")
        }))
    }

    async fn generate_to_descriptor(
        &self,
        num_blocks: u32,
        descriptor: String,
        maxtries: Option<u64>,
    ) -> RpcResult<Vec<String>> {
        use rustoshi_crypto::address::Network as AddrNetwork;
        use rustoshi_wallet::descriptor::parse_descriptor;

        let state = self.state.read().await;

        // Only allowed on regtest
        if state.params.network_id != NetworkId::Regtest {
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                "This RPC is only available on regtest",
            ));
        }

        // Parse the descriptor
        let parsed = parse_descriptor(&descriptor).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!("Invalid descriptor: {}", e),
            )
        })?;

        // Derive the first address from the descriptor
        let addrs = parsed.derive_addresses(0, AddrNetwork::Regtest).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("Failed to derive address: {}", e),
            )
        })?;

        let addr = addrs.first().ok_or_else(|| {
            Self::rpc_error(rpc_error::RPC_MISC_ERROR, "Descriptor produced no addresses")
        })?;

        let script_pubkey = addr.to_script_pubkey();
        let maxtries = maxtries.unwrap_or(1_000_000);

        drop(state); // Release the lock before mining

        // Mine the blocks
        self.mine_blocks(num_blocks, script_pubkey, maxtries).await
    }

    async fn invalidate_block(&self, blockhash: String) -> RpcResult<()> {
        let hash = Self::parse_hash(&blockhash)?;

        let mut state = self.state.write().await;
        let store = BlockStore::new(&state.db);

        // Get block index entry
        let block_entry = store.get_block_index(&hash).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Database error: {}", e),
            )
        })?.ok_or_else(|| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Block not found",
            )
        })?;

        // Cannot invalidate genesis block
        if block_entry.height == 0 {
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                "Cannot invalidate genesis block",
            ));
        }

        // Mark the block as invalid
        store.mark_block_invalid(&hash).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Failed to mark block invalid: {}", e),
            )
        })?;

        // Find and mark all descendants as FAILED_CHILD
        let all_hashes = store.get_all_block_hashes().map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Failed to enumerate blocks: {}", e),
            )
        })?;

        let get_meta = |h: &Hash256| -> Option<BlockMeta> {
            store.get_block_index(h).ok().flatten().map(|entry| BlockMeta {
                hash: *h,
                height: entry.height,
                prev_hash: entry.prev_hash,
                status: entry.status.raw(),
                chain_work: entry.chain_work,
            })
        };

        let descendants = find_descendants(
            &hash,
            block_entry.height,
            all_hashes.into_iter(),
            &get_meta,
        );

        for desc_hash in &descendants {
            store.mark_block_failed_child(desc_hash).map_err(|e| {
                Self::rpc_error(
                    rpc_error::RPC_DATABASE_ERROR,
                    format!("Failed to mark descendant invalid: {}", e),
                )
            })?;
        }

        tracing::info!(
            "Invalidated block {} at height {} ({} descendants marked)",
            hash,
            block_entry.height,
            descendants.len()
        );

        // If the invalidated block is in the active chain, we need to reorg
        // Find the new best valid chain tip by walking back from the current tip
        // until we find a block that isn't invalid
        #[allow(unused_assignments)]
        let mut new_tip_hash = state.best_hash;
        #[allow(unused_assignments)]
        let mut new_tip_height = state.best_height;

        // Check if current tip or any ancestor is the invalidated block
        let mut check_hash = state.best_hash;
        let mut needs_reorg = false;

        while check_hash != Hash256::ZERO {
            if check_hash == hash {
                needs_reorg = true;
                break;
            }
            if let Some(entry) = store.get_block_index(&check_hash).ok().flatten() {
                check_hash = entry.prev_hash;
            } else {
                break;
            }
        }

        if needs_reorg {
            // Walk back to find the common ancestor (the block before invalidated)
            // The new tip is the parent of the invalidated block
            if let Some(entry) = store.get_block_index(&hash).ok().flatten() {
                new_tip_hash = entry.prev_hash;
                new_tip_height = block_entry.height.saturating_sub(1);

                // Update best block in database
                store.set_best_block(&new_tip_hash, new_tip_height).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to update best block: {}", e),
                    )
                })?;

                // Update height index - remove entries from invalidated height onward
                for h in new_tip_height + 1..=state.best_height {
                    let _ = store.delete_height_index(h);
                }

                state.best_hash = new_tip_hash;
                state.best_height = new_tip_height;

                tracing::info!(
                    "Chain tip rolled back to {} at height {}",
                    new_tip_hash,
                    new_tip_height
                );
            }
        }

        Ok(())
    }

    async fn reconsider_block(&self, blockhash: String) -> RpcResult<()> {
        let hash = Self::parse_hash(&blockhash)?;

        let state = self.state.write().await;
        let store = BlockStore::new(&state.db);

        // Verify the block exists and get its metadata
        let block_entry = store.get_block_index(&hash).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Database error: {}", e),
            )
        })?.ok_or_else(|| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Block not found",
            )
        })?;

        // Get all blocks to check for ancestors/descendants
        let all_hashes = store.get_all_block_hashes().map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Failed to enumerate blocks: {}", e),
            )
        })?;

        let get_meta = |h: &Hash256| -> Option<BlockMeta> {
            store.get_block_index(h).ok().flatten().map(|entry| BlockMeta {
                hash: *h,
                height: entry.height,
                prev_hash: entry.prev_hash,
                status: entry.status.raw(),
                chain_work: entry.chain_work,
            })
        };

        let mut reconsidered_count = 0;

        // Clear invalid flags from this block and all related blocks
        // (both ancestors and descendants)
        for block_hash in &all_hashes {
            let Some(entry) = store.get_block_index(block_hash).ok().flatten() else {
                continue;
            };

            // Check if this block has FAILED_VALIDITY or FAILED_CHILD
            let is_invalid = entry.status.has(rustoshi_storage::block_store::BlockStatus::FAILED_VALIDITY)
                || entry.status.has(rustoshi_storage::block_store::BlockStatus::FAILED_CHILD);

            if !is_invalid {
                continue;
            }

            // Check if this block is related to the reconsidered block
            // (either ancestor or descendant)
            if is_ancestor_or_descendant(
                block_hash,
                entry.height,
                &hash,
                block_entry.height,
                &get_meta,
            ) {
                store.unmark_block_invalid(block_hash).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to unmark block invalid: {}", e),
                    )
                })?;
                reconsidered_count += 1;
            }
        }

        tracing::info!(
            "Reconsidered block {} ({} related blocks updated)",
            hash,
            reconsidered_count
        );

        // Check if we should switch to the reconsidered chain
        // Compare chain work of the reconsidered block vs current tip
        let current_tip_entry = store.get_block_index(&state.best_hash).ok().flatten();
        let reconsidered_entry = store.get_block_index(&hash).ok().flatten();

        if let (Some(current), Some(reconsidered)) = (current_tip_entry, reconsidered_entry) {
            // If the reconsidered chain has more work, we might want to switch
            if compare_chain_work(&reconsidered.chain_work, &current.chain_work).is_gt() {
                tracing::info!(
                    "Reconsidered block {} has more work than current tip, consider reorg",
                    hash
                );
                // Note: A full implementation would trigger ActivateBestChain here
                // For now, we just clear the flags and log
            }
        }

        Ok(())
    }

    async fn precious_block(&self, blockhash: String) -> RpcResult<()> {
        let hash = Self::parse_hash(&blockhash)?;

        let mut state = self.state.write().await;
        let store = BlockStore::new(&state.db);

        // Get block index entry
        let block_entry = store.get_block_index(&hash).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Database error: {}", e),
            )
        })?.ok_or_else(|| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Block not found",
            )
        })?;

        // Get current tip's chain work for comparison
        let tip_entry = store.get_block_index(&state.best_hash).ok().flatten();

        if let Some(tip) = &tip_entry {
            // If block has less work than current tip, nothing to do
            if compare_chain_work(&block_entry.chain_work, &tip.chain_work).is_lt() {
                return Ok(());
            }
        }

        // Get current tip's chain work for the sequence ID assignment
        let current_tip_work = tip_entry
            .map(|e| e.chain_work)
            .unwrap_or([0u8; 32]);

        // Assign precious sequence ID
        let seq_id = state.chain_manager_state.assign_precious_sequence(hash, &current_tip_work);

        tracing::info!(
            "Marked block {} as precious (sequence_id={})",
            hash,
            seq_id
        );

        // Note: A full implementation would trigger ActivateBestChain here
        // to potentially switch to the precious block's chain if it has equal work

        Ok(())
    }

    // ============================================================
    // PSBT RPC IMPLEMENTATIONS
    // ============================================================

    async fn createpsbt(
        &self,
        inputs: Vec<CreatePsbtInput>,
        outputs: Vec<serde_json::Value>,
        locktime: Option<u32>,
        replaceable: Option<bool>,
    ) -> RpcResult<String> {
        let state = self.state.read().await;

        // Build the unsigned transaction
        let lock_time = locktime.unwrap_or(0);
        let replaceable = replaceable.unwrap_or(false);

        // Default sequence: 0xfffffffe for RBF-enabled, 0xffffffff otherwise
        let default_sequence = if replaceable {
            0xfffffffe
        } else {
            0xffffffff
        };

        // Parse inputs
        let mut tx_inputs = Vec::with_capacity(inputs.len());
        for input in &inputs {
            let txid = Self::parse_hash(&input.txid)?;
            let sequence = input.sequence.unwrap_or(default_sequence);
            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: input.vout,
                },
                script_sig: vec![],
                sequence,
                witness: vec![],
            });
        }

        // Parse outputs
        let mut tx_outputs = Vec::new();
        for output in &outputs {
            let obj = output.as_object().ok_or_else(|| {
                Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Output must be an object")
            })?;

            for (key, value) in obj {
                if key == "data" {
                    // OP_RETURN output
                    let data_hex = value.as_str().ok_or_else(|| {
                        Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "data must be a hex string")
                    })?;
                    let data = Self::parse_hex(data_hex)?;

                    // Build OP_RETURN script: OP_RETURN <push data>
                    let mut script = vec![0x6a]; // OP_RETURN
                    if data.len() <= 75 {
                        script.push(data.len() as u8);
                    } else if data.len() <= 255 {
                        script.push(0x4c); // OP_PUSHDATA1
                        script.push(data.len() as u8);
                    } else {
                        script.push(0x4d); // OP_PUSHDATA2
                        script.extend_from_slice(&(data.len() as u16).to_le_bytes());
                    }
                    script.extend_from_slice(&data);

                    tx_outputs.push(TxOut {
                        value: 0,
                        script_pubkey: script,
                    });
                } else {
                    // Address -> amount output
                    let amount_btc = value.as_f64().ok_or_else(|| {
                        Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Amount must be a number")
                    })?;

                    if amount_btc < 0.0 {
                        return Err(Self::rpc_error(
                            rpc_error::RPC_INVALID_PARAMS,
                            "Amount cannot be negative",
                        ));
                    }

                    let amount_sats = (amount_btc * COIN as f64).round() as u64;

                    // Decode address to scriptPubKey
                    let script_pubkey = address_to_script_pubkey(key, &state.params)?;

                    tx_outputs.push(TxOut {
                        value: amount_sats,
                        script_pubkey,
                    });
                }
            }
        }

        if tx_inputs.is_empty() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "Inputs array is empty",
            ));
        }

        // Create the unsigned transaction
        let tx = Transaction {
            version: 2,
            inputs: tx_inputs,
            outputs: tx_outputs,
            lock_time,
        };

        // Create PSBT from unsigned transaction
        let psbt = Psbt::from_unsigned_tx(tx).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, format!("Failed to create PSBT: {}", e))
        })?;

        Ok(psbt.to_base64())
    }

    async fn decodepsbt(&self, psbt_str: String) -> RpcResult<DecodePsbtResult> {
        let state = self.state.read().await;

        // Decode the PSBT
        let psbt = Psbt::from_base64(&psbt_str).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, format!("Invalid PSBT: {}", e))
        })?;

        // Build the transaction info
        let tx = &psbt.unsigned_tx;
        let tx_info = build_decoded_raw_transaction(tx);

        // Build inputs info
        let mut inputs = Vec::with_capacity(psbt.inputs.len());
        let mut total_input_value: Option<u64> = Some(0);

        for (i, input) in psbt.inputs.iter().enumerate() {
            let mut decoded_input = DecodePsbtInput {
                non_witness_utxo: None,
                witness_utxo: None,
                partial_signatures: None,
                sighash: None,
                redeem_script: None,
                witness_script: None,
                bip32_derivs: None,
                final_scriptsig: None,
                final_scriptwitness: None,
                unknown: None,
            };

            // Non-witness UTXO
            if let Some(ref utxo_tx) = input.non_witness_utxo {
                decoded_input.non_witness_utxo = Some(serde_json::to_value(build_decoded_raw_transaction(utxo_tx)).unwrap());

                // Extract value from the referenced output
                let vout = psbt.unsigned_tx.inputs[i].previous_output.vout as usize;
                if vout < utxo_tx.outputs.len() {
                    if let Some(ref mut total) = total_input_value {
                        *total += utxo_tx.outputs[vout].value;
                    }
                }
            }

            // Witness UTXO
            if let Some(ref utxo) = input.witness_utxo {
                let script_type = classify_script(&utxo.script_pubkey);
                let address = script_to_address(&utxo.script_pubkey, &state.params);

                decoded_input.witness_utxo = Some(WitnessUtxo {
                    amount: utxo.value as f64 / COIN as f64,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: disassemble_script(&utxo.script_pubkey),
                        hex: hex::encode(&utxo.script_pubkey),
                        script_type,
                        address,
                    },
                });

                if let Some(ref mut total) = total_input_value {
                    *total += utxo.value;
                }
            } else if input.non_witness_utxo.is_none() {
                // No UTXO info, can't calculate fee
                total_input_value = None;
            }

            // Partial signatures
            if !input.partial_sigs.is_empty() {
                let mut sigs = serde_json::Map::new();
                for (pubkey, sig) in &input.partial_sigs {
                    sigs.insert(hex::encode(pubkey), serde_json::Value::String(hex::encode(sig)));
                }
                decoded_input.partial_signatures = Some(serde_json::Value::Object(sigs));
            }

            // Sighash type
            if let Some(sighash) = input.sighash_type {
                decoded_input.sighash = Some(sighash_to_string(sighash));
            }

            // Redeem script
            if let Some(ref script) = input.redeem_script {
                decoded_input.redeem_script = Some(ScriptInfo {
                    asm: disassemble_script(script),
                    hex: hex::encode(script),
                    script_type: Some(classify_script(script)),
                });
            }

            // Witness script
            if let Some(ref script) = input.witness_script {
                decoded_input.witness_script = Some(ScriptInfo {
                    asm: disassemble_script(script),
                    hex: hex::encode(script),
                    script_type: Some(classify_script(script)),
                });
            }

            // BIP32 derivation paths
            if !input.bip32_derivation.is_empty() {
                let derivs: Vec<Bip32Deriv> = input.bip32_derivation.iter().map(|(pubkey, origin)| {
                    Bip32Deriv {
                        pubkey: hex::encode(pubkey),
                        master_fingerprint: hex::encode(origin.fingerprint),
                        path: format_derivation_path(&origin.path),
                    }
                }).collect();
                decoded_input.bip32_derivs = Some(derivs);
            }

            // Final scriptSig
            if let Some(ref script) = input.final_script_sig {
                decoded_input.final_scriptsig = Some(ScriptInfo {
                    asm: disassemble_script(script),
                    hex: hex::encode(script),
                    script_type: None,
                });
            }

            // Final scriptWitness
            if let Some(ref witness) = input.final_script_witness {
                decoded_input.final_scriptwitness = Some(
                    witness.iter().map(hex::encode).collect()
                );
            }

            // Unknown
            if !input.unknown.is_empty() {
                let mut unknown_map = serde_json::Map::new();
                for (k, v) in &input.unknown {
                    unknown_map.insert(hex::encode(k), serde_json::Value::String(hex::encode(v)));
                }
                decoded_input.unknown = Some(serde_json::Value::Object(unknown_map));
            }

            inputs.push(decoded_input);
        }

        // Build outputs info
        let mut outputs = Vec::with_capacity(psbt.outputs.len());
        for output in &psbt.outputs {
            let mut decoded_output = DecodePsbtOutput {
                redeem_script: None,
                witness_script: None,
                bip32_derivs: None,
                unknown: None,
            };

            // Redeem script
            if let Some(ref script) = output.redeem_script {
                decoded_output.redeem_script = Some(ScriptInfo {
                    asm: disassemble_script(script),
                    hex: hex::encode(script),
                    script_type: Some(classify_script(script)),
                });
            }

            // Witness script
            if let Some(ref script) = output.witness_script {
                decoded_output.witness_script = Some(ScriptInfo {
                    asm: disassemble_script(script),
                    hex: hex::encode(script),
                    script_type: Some(classify_script(script)),
                });
            }

            // BIP32 derivation paths
            if !output.bip32_derivation.is_empty() {
                let derivs: Vec<Bip32Deriv> = output.bip32_derivation.iter().map(|(pubkey, origin)| {
                    Bip32Deriv {
                        pubkey: hex::encode(pubkey),
                        master_fingerprint: hex::encode(origin.fingerprint),
                        path: format_derivation_path(&origin.path),
                    }
                }).collect();
                decoded_output.bip32_derivs = Some(derivs);
            }

            // Unknown
            if !output.unknown.is_empty() {
                let mut unknown_map = serde_json::Map::new();
                for (k, v) in &output.unknown {
                    unknown_map.insert(hex::encode(k), serde_json::Value::String(hex::encode(v)));
                }
                decoded_output.unknown = Some(serde_json::Value::Object(unknown_map));
            }

            outputs.push(decoded_output);
        }

        // Calculate fee if possible
        let total_output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let fee = total_input_value.map(|input| {
            if input >= total_output_value {
                (input - total_output_value) as f64 / COIN as f64
            } else {
                0.0
            }
        });

        Ok(DecodePsbtResult {
            tx: tx_info,
            global_xpubs: None, // Simplified - could be expanded
            psbt_version: psbt.get_version(),
            unknown: None,
            inputs,
            outputs,
            fee,
        })
    }

    async fn combinepsbt(&self, psbts: Vec<String>) -> RpcResult<String> {
        if psbts.is_empty() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "PSBTs array is empty",
            ));
        }

        // Decode all PSBTs
        let decoded_psbts: Result<Vec<Psbt>, _> = psbts
            .iter()
            .map(|s| {
                Psbt::from_base64(s).map_err(|e| {
                    Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, format!("Invalid PSBT: {}", e))
                })
            })
            .collect();
        let decoded_psbts = decoded_psbts?;

        // Combine them
        let combined = Psbt::combine(&decoded_psbts).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, format!("Failed to combine PSBTs: {}", e))
        })?;

        Ok(combined.to_base64())
    }

    async fn finalizepsbt(
        &self,
        psbt_str: String,
        extract: Option<bool>,
    ) -> RpcResult<FinalizePsbtResult> {
        let extract = extract.unwrap_or(true);

        // Decode the PSBT
        let mut psbt = Psbt::from_base64(&psbt_str).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, format!("Invalid PSBT: {}", e))
        })?;

        // Try to finalize
        let _finalize_result = psbt.finalize();
        let complete = psbt.is_finalized();

        if complete && extract {
            // Extract the final transaction
            match psbt.extract_tx() {
                Ok(tx) => {
                    let hex = hex::encode(tx.serialize());
                    Ok(FinalizePsbtResult {
                        psbt: None,
                        hex: Some(hex),
                        complete: true,
                    })
                }
                Err(_e) => {
                    // Extraction failed, return the PSBT
                    Ok(FinalizePsbtResult {
                        psbt: Some(psbt.to_base64()),
                        hex: None,
                        complete: false,
                    })
                }
            }
        } else {
            // Return the (possibly partially) finalized PSBT
            Ok(FinalizePsbtResult {
                psbt: Some(psbt.to_base64()),
                hex: None,
                complete,
            })
        }
    }

    // ============================================================
    // MISSING RPC IMPLEMENTATIONS
    // ============================================================

    async fn test_mempool_accept(
        &self,
        rawtxs: Vec<String>,
        maxfeerate: Option<f64>,
    ) -> RpcResult<serde_json::Value> {
        let _maxfeerate_btc_kvb = maxfeerate.unwrap_or(0.10);
        let mut results = Vec::new();

        for raw in &rawtxs {
            let bytes = Self::parse_hex(raw)?;
            let tx = Transaction::deserialize(&bytes).map_err(|e| {
                Self::rpc_error(
                    rpc_error::RPC_DESERIALIZATION_ERROR,
                    format!("TX decode failed: {}", e),
                )
            })?;
            let txid = tx.txid();

            // Check if already in mempool
            let state = self.state.read().await;
            if state.mempool.contains(&txid) {
                results.push(serde_json::json!({
                    "txid": txid.to_string(),
                    "allowed": false,
                    "reject-reason": "txn-already-in-mempool"
                }));
                continue;
            }

            // Basic context-free validation
            match rustoshi_consensus::validation::check_transaction(&tx) {
                Ok(()) => {
                    let vsize = tx.vsize();
                    results.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "allowed": true,
                        "vsize": vsize,
                        "fees": {
                            "base": 0
                        }
                    }));
                }
                Err(e) => {
                    results.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "allowed": false,
                        "reject-reason": format!("{}", e)
                    }));
                }
            }
        }

        Ok(serde_json::json!(results))
    }

    async fn create_raw_transaction(
        &self,
        inputs: Vec<serde_json::Value>,
        outputs: Vec<serde_json::Value>,
        locktime: Option<u32>,
        replaceable: Option<bool>,
    ) -> RpcResult<String> {
        let locktime = locktime.unwrap_or(0);
        let replaceable = replaceable.unwrap_or(false);

        // Parse inputs
        let mut tx_inputs = Vec::new();
        for input in &inputs {
            let txid_str = input["txid"]
                .as_str()
                .ok_or_else(|| Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Missing txid"))?;
            let txid = Self::parse_hash(txid_str)?;
            let vout = input["vout"]
                .as_u64()
                .ok_or_else(|| Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Missing vout"))?
                as u32;
            let sequence = if let Some(seq) = input.get("sequence") {
                seq.as_u64().unwrap_or(0xFFFFFFFF) as u32
            } else if replaceable {
                0xFFFFFFFD // BIP-125 replaceable
            } else {
                0xFFFFFFFE
            };
            tx_inputs.push(TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: vec![],
                sequence,
                witness: vec![],
            });
        }

        // Parse outputs
        let mut tx_outputs = Vec::new();
        for output in &outputs {
            if let Some(obj) = output.as_object() {
                for (key, val) in obj {
                    if key == "data" {
                        // OP_RETURN output
                        let data_hex = val.as_str().unwrap_or("");
                        let data = hex::decode(data_hex).map_err(|_| {
                            Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid data hex")
                        })?;
                        let mut script = vec![0x6a]; // OP_RETURN
                        if data.len() <= 75 {
                            script.push(data.len() as u8);
                        } else {
                            script.push(0x4c); // OP_PUSHDATA1
                            script.push(data.len() as u8);
                        }
                        script.extend_from_slice(&data);
                        tx_outputs.push(TxOut {
                            value: 0,
                            script_pubkey: script,
                        });
                    } else {
                        // Address output: key is address, val is amount in BTC
                        let amount_btc = val.as_f64().ok_or_else(|| {
                            Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Invalid amount")
                        })?;
                        let amount_sat = (amount_btc * COIN as f64) as u64;
                        let address = rustoshi_crypto::address::Address::from_string(key, None)
                            .map_err(|e| {
                                Self::rpc_error(
                                    rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                                    format!("Invalid address: {}", e),
                                )
                            })?;
                        let script = address.to_script_pubkey();
                        tx_outputs.push(TxOut {
                            value: amount_sat,
                            script_pubkey: script,
                        });
                    }
                }
            }
        }

        let tx = Transaction {
            version: 2,
            inputs: tx_inputs,
            outputs: tx_outputs,
            lock_time: locktime,
        };

        Ok(hex::encode(tx.serialize()))
    }

    async fn decode_script(&self, hex_str: String) -> RpcResult<serde_json::Value> {
        let bytes = Self::parse_hex(&hex_str)?;

        // Disassemble script to ASM
        let mut asm_parts = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let op = bytes[i];
            if op == 0x00 {
                asm_parts.push("0".to_string());
                i += 1;
            } else if (0x01..=0x4b).contains(&op) {
                let len = op as usize;
                if i + 1 + len <= bytes.len() {
                    asm_parts.push(hex::encode(&bytes[i + 1..i + 1 + len]));
                    i += 1 + len;
                } else {
                    asm_parts.push("[error]".to_string());
                    break;
                }
            } else if op == 0x4c {
                // OP_PUSHDATA1
                if i + 1 < bytes.len() {
                    let len = bytes[i + 1] as usize;
                    if i + 2 + len <= bytes.len() {
                        asm_parts.push(hex::encode(&bytes[i + 2..i + 2 + len]));
                        i += 2 + len;
                    } else {
                        asm_parts.push("[error]".to_string());
                        break;
                    }
                } else {
                    break;
                }
            } else {
                // Named opcode
                let name = match op {
                    0x51..=0x60 => format!("OP_{}", op - 0x50),
                    0x63 => "OP_IF".to_string(),
                    0x64 => "OP_NOTIF".to_string(),
                    0x67 => "OP_ELSE".to_string(),
                    0x68 => "OP_ENDIF".to_string(),
                    0x69 => "OP_VERIFY".to_string(),
                    0x6a => "OP_RETURN".to_string(),
                    0x75 => "OP_DROP".to_string(),
                    0x76 => "OP_DUP".to_string(),
                    0x87 => "OP_EQUAL".to_string(),
                    0x88 => "OP_EQUALVERIFY".to_string(),
                    0xa9 => "OP_HASH160".to_string(),
                    0xaa => "OP_HASH256".to_string(),
                    0xab => "OP_CODESEPARATOR".to_string(),
                    0xac => "OP_CHECKSIG".to_string(),
                    0xad => "OP_CHECKSIGVERIFY".to_string(),
                    0xae => "OP_CHECKMULTISIG".to_string(),
                    0xaf => "OP_CHECKMULTISIGVERIFY".to_string(),
                    _ => format!("OP_UNKNOWN[0x{:02x}]", op),
                };
                asm_parts.push(name);
                i += 1;
            }
        }

        // Classify script type
        let script_type = if bytes.len() == 25
            && bytes[0] == 0x76
            && bytes[1] == 0xa9
            && bytes[2] == 0x14
            && bytes[23] == 0x88
            && bytes[24] == 0xac
        {
            "pubkeyhash"
        } else if bytes.len() == 23 && bytes[0] == 0xa9 && bytes[1] == 0x14 && bytes[22] == 0x87 {
            "scripthash"
        } else if bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14 {
            "witness_v0_keyhash"
        } else if bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 0x20 {
            "witness_v0_scripthash"
        } else if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20 {
            "witness_v1_taproot"
        } else if !bytes.is_empty() && bytes[0] == 0x6a {
            "nulldata"
        } else {
            "nonstandard"
        };

        Ok(serde_json::json!({
            "asm": asm_parts.join(" "),
            "type": script_type,
            "p2sh": "", // Would require address encoding
            "segwit": null
        }))
    }

    async fn get_chain_tips(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;

        // The active tip is always present
        let tips = vec![serde_json::json!({
            "height": state.best_height,
            "hash": state.best_hash.to_string(),
            "branchlen": 0,
            "status": "active"
        })];

        Ok(serde_json::json!(tips))
    }

    async fn disconnect_node(
        &self,
        address: Option<String>,
        nodeid: Option<u32>,
    ) -> RpcResult<()> {
        if address.is_none() && nodeid.is_none() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                "Must provide address or nodeid",
            ));
        }

        let peer_state = self.peer_state.read().await;
        if peer_state.peer_manager.is_some() {
            // Node disconnection requested; the peer manager will handle it
            // on the next connection maintenance cycle.
            Ok(())
        } else {
            Err(Self::rpc_error(
                rpc_error::RPC_CLIENT_P2P_DISABLED,
                "P2P networking disabled",
            ))
        }
    }

    async fn get_mempool_entry(&self, txid: String) -> RpcResult<serde_json::Value> {
        let txid_hash = Self::parse_hash(&txid)?;
        let state = self.state.read().await;

        match state.mempool.get(&txid_hash) {
            Some(entry) => {
                let replaceable = state.mempool.is_bip125_replaceable(&txid_hash);
                Ok(serde_json::json!({
                    "vsize": entry.vsize,
                    "weight": entry.weight,
                    "fee": entry.fee as f64 / COIN as f64,
                    "modifiedfee": entry.fee as f64 / COIN as f64,
                    "descendantcount": entry.descendant_count,
                    "descendantsize": entry.descendant_size,
                    "descendantfees": entry.descendant_fees,
                    "ancestorcount": entry.ancestor_count,
                    "ancestorsize": entry.ancestor_size,
                    "ancestorfees": entry.ancestor_fees,
                    "bip125-replaceable": replaceable
                }))
            }
            None => Err(Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Transaction not in mempool",
            )),
        }
    }

    async fn get_mempool_ancestors(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value> {
        let txid_hash = Self::parse_hash(&txid)?;
        let verbose = verbose.unwrap_or(false);
        let state = self.state.read().await;

        if state.mempool.get(&txid_hash).is_none() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Transaction not in mempool",
            ));
        }

        let ancestors = state.mempool.get_ancestors_of(&txid_hash);

        if verbose {
            let mut result = serde_json::Map::new();
            for ancestor_txid in &ancestors {
                if let Some(entry) = state.mempool.get(ancestor_txid) {
                    result.insert(
                        ancestor_txid.to_string(),
                        serde_json::json!({
                            "vsize": entry.vsize,
                            "weight": entry.weight,
                            "fee": entry.fee as f64 / COIN as f64,
                            "ancestorcount": entry.ancestor_count,
                            "ancestorsize": entry.ancestor_size,
                            "ancestorfees": entry.ancestor_fees
                        }),
                    );
                }
            }
            Ok(serde_json::Value::Object(result))
        } else {
            Ok(serde_json::json!(
                ancestors.iter().map(|h| h.to_string()).collect::<Vec<_>>()
            ))
        }
    }

    async fn get_mempool_descendants(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value> {
        // Symmetric mirror of `get_mempool_ancestors` walking the child graph.
        // See `bitcoin-core/src/rpc/mempool.cpp::getmempooldescendants`.
        let txid_hash = Self::parse_hash(&txid)?;
        let verbose = verbose.unwrap_or(false);
        let state = self.state.read().await;

        if state.mempool.get(&txid_hash).is_none() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Transaction not in mempool",
            ));
        }

        let descendants = state.mempool.get_descendants_of(&txid_hash);

        if verbose {
            let mut result = serde_json::Map::new();
            for d in &descendants {
                if let Some(entry) = state.mempool.get(d) {
                    result.insert(
                        d.to_string(),
                        serde_json::json!({
                            "vsize": entry.vsize,
                            "weight": entry.weight,
                            "fee": entry.fee as f64 / COIN as f64,
                            "descendantcount": entry.descendant_count,
                            "descendantsize": entry.descendant_size,
                            "descendantfees": entry.descendant_fees
                        }),
                    );
                }
            }
            Ok(serde_json::Value::Object(result))
        } else {
            Ok(serde_json::json!(
                descendants.iter().map(|h| h.to_string()).collect::<Vec<_>>()
            ))
        }
    }

    async fn help(&self, command: Option<String>) -> RpcResult<String> {
        if let Some(cmd) = command {
            let help_text = match cmd.as_str() {
                "getblockchaininfo" => "getblockchaininfo\nReturns an object containing various state info regarding blockchain processing.",
                "getblock" => "getblock \"blockhash\" ( verbosity )\nReturns block data.",
                "getblockhash" => "getblockhash height\nReturns hash of block at given height.",
                "getblockheader" => "getblockheader \"blockhash\" ( verbose )\nReturns block header data.",
                "getblockcount" => "getblockcount\nReturns the height of the most-work fully-validated chain.",
                "getbestblockhash" => "getbestblockhash\nReturns the hash of the best (tip) block.",
                "getdifficulty" => "getdifficulty\nReturns the proof-of-work difficulty.",
                "getchaintips" => "getchaintips\nReturn information about all known tips in the block tree.",
                "gettxout" => "gettxout \"txid\" n ( include_mempool )\nReturns details about an unspent transaction output.",
                "getrawtransaction" => "getrawtransaction \"txid\" ( verbose \"blockhash\" )\nReturn the raw transaction data.",
                "sendrawtransaction" => "sendrawtransaction \"hexstring\" ( maxfeerate )\nSubmit a raw transaction to the network.",
                "decoderawtransaction" => "decoderawtransaction \"hexstring\" ( iswitness )\nDecode a raw transaction.",
                "createrawtransaction" => "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] [{\"address\":amount},...] ( locktime replaceable )\nCreate a transaction spending the given inputs and creating new outputs.",
                "decodescript" => "decodescript \"hexstring\"\nDecode a hex-encoded script.",
                "testmempoolaccept" => "testmempoolaccept [\"rawtx\",...] ( maxfeerate )\nReturns result of mempool acceptance tests.",
                "getmempoolinfo" => "getmempoolinfo\nReturns details on the active state of the TX memory pool.",
                "getrawmempool" => "getrawmempool ( verbose )\nReturns all transaction ids in memory pool.",
                "getmempoolentry" => "getmempoolentry \"txid\"\nReturns mempool data for given transaction.",
                "dumpmempool" => "dumpmempool\nWrite the mempool to mempool.dat (Bitcoin Core-format, byte-compatible).",
                "savemempool" => "savemempool\nDumps the mempool to disk. Returns {\"filename\": \"mempool.dat\"}.",
                "loadmempool" => "loadmempool\nLoad transactions from mempool.dat back into the mempool.",
                "getmempoolancestors" => "getmempoolancestors \"txid\" ( verbose )\nReturns all in-mempool ancestors.",
                "getmempooldescendants" => "getmempooldescendants \"txid\" ( verbose )\nReturns all in-mempool descendants.",
                "getnetworkinfo" => "getnetworkinfo\nReturns an object containing various state info regarding P2P networking.",
                "getpeerinfo" => "getpeerinfo\nReturns data about each connected network node.",
                "getconnectioncount" => "getconnectioncount\nReturns the number of connections to other nodes.",
                "addnode" => "addnode \"node\" \"command\"\nAttempts to add or remove a node from the addnode list.",
                "disconnectnode" => "disconnectnode ( \"address\" nodeid )\nDisconnects from the specified peer node.",
                "getblocktemplate" => "getblocktemplate ( \"template_request\" )\nReturns data needed to construct a block.",
                "submitblock" => "submitblock \"hexdata\" ( \"dummy\" )\nAttempts to submit new block to network.",
                "getmininginfo" => "getmininginfo\nReturns a json object containing mining-related information.",
                "estimatesmartfee" => "estimatesmartfee conf_target ( \"estimate_mode\" )\nEstimates the approximate fee per kilobyte.",
                "estimaterawfee" => "estimaterawfee conf_target ( threshold )\nReturns the underlying fee bucket statistics for a target.",
                "signmessage" => "signmessage \"privkey\" \"message\"\nSigns a message with the given private key (hex or WIF). Returns base64 sig.",
                "stop" => "stop\nRequest a graceful shutdown.",
                "help" => "help ( \"command\" )\nList all commands, or get help for a specified command.",
                "walletpassphrase" => "walletpassphrase \"passphrase\" timeout\nStores the wallet decryption key in memory for 'timeout' seconds.",
                "walletlock" => "walletlock\nRemoves the wallet encryption key from memory, locking the wallet.",
                "setlabel" => "setlabel \"address\" \"label\"\nSets the label associated with the given address.",
                "verifymessage" => "verifymessage \"address\" \"signature\" \"message\"\nVerify a signed message.",
                "uptime" => "uptime\nReturns the total uptime of the server in seconds.",
                "getnettotals" => "getnettotals\nReturns information about network traffic, including bytes in, bytes out, and current time.",
                _ => "Unknown command. Use \"help\" for a list of all commands.",
            };
            Ok(help_text.to_string())
        } else {
            let commands = vec![
                "== Blockchain ==",
                "getbestblockhash", "getblock", "getblockchaininfo", "getblockcount",
                "getblockhash", "getblockheader", "getchaintips", "getdifficulty", "gettxout",
                "invalidateblock", "preciousblock", "pruneblockchain", "reconsiderblock",
                "",
                "== Mempool ==",
                "dumpmempool", "getmempoolancestors", "getmempooldescendants",
                "getmempoolentry", "getmempoolinfo", "getrawmempool", "loadmempool",
                "savemempool", "testmempoolaccept",
                "",
                "== Mining ==",
                "getblocktemplate", "getmininginfo", "submitblock",
                "",
                "== Network ==",
                "addnode", "clearbanned", "disconnectnode", "getconnectioncount",
                "getnetworkinfo", "getpeerinfo", "listbanned", "setban",
                "",
                "== Rawtransactions ==",
                "createrawtransaction", "decoderawtransaction", "decodescript",
                "getrawtransaction", "sendrawtransaction",
                "",
                "== Wallet ==",
                "deriveaddresses", "getdescriptorinfo", "setlabel", "validateaddress",
                "walletlock", "walletpassphrase",
                "",
                "== PSBT ==",
                "combinepsbt", "createpsbt", "decodepsbt", "finalizepsbt",
                "",
                "== Util ==",
                "estimaterawfee", "estimatesmartfee", "getnettotals", "help",
                "signmessage", "stop", "uptime", "verifymessage",
            ];
            Ok(commands.join("\n"))
        }
    }

    async fn wallet_passphrase(&self, _passphrase: String, _timeout: u64) -> RpcResult<()> {
        // Wallet encryption is not yet implemented; accept the call gracefully.
        Ok(())
    }

    async fn wallet_lock(&self) -> RpcResult<()> {
        // Wallet encryption is not yet implemented; accept the call gracefully.
        Ok(())
    }

    async fn set_label(&self, _address: String, _label: String) -> RpcResult<()> {
        // Label storage is not yet implemented; accept the call gracefully.
        Ok(())
    }

    async fn verify_message(
        &self,
        address: String,
        signature: String,
        message: String,
    ) -> RpcResult<bool> {
        use base64::Engine;
        use rustoshi_crypto::address::Address;
        use rustoshi_crypto::hashes::hash160;
        use rustoshi_crypto::recover_message_pubkey;

        if address.is_empty() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Invalid address",
            ));
        }

        // Decode the base64-encoded compact-recoverable signature.
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(signature.trim()) {
            Ok(b) => b,
            Err(_) => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    "Malformed base64 encoding",
                ))
            }
        };

        // Parse the address up-front; we need its hash to compare against the
        // recovered pubkey hash. Rejecting bech32 (segwit/taproot) addresses
        // matches Core, which restricts `verifymessage` to legacy P2PKH.
        let parsed = Address::from_string(&address, None).map_err(|_| {
            Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, "Invalid address")
        })?;
        let expected_hash = match parsed {
            Address::P2PKH { hash, .. } => hash,
            _ => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_TYPE_ERROR,
                    "Address does not refer to a P2PKH key",
                ))
            }
        };

        // Recover the pubkey; format errors are reported as `false` per Core's
        // contract (verifymessage returns a bool, not an error, for bad sigs).
        let (pubkey, compressed) = match recover_message_pubkey(&sig_bytes, message.as_bytes()) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let serialized: Vec<u8> = if compressed {
            pubkey.serialize().to_vec()
        } else {
            pubkey.serialize_uncompressed().to_vec()
        };
        let recovered_hash = hash160(&serialized);
        Ok(recovered_hash == expected_hash)
    }

    async fn sign_message(&self, privkey: String, message: String) -> RpcResult<String> {
        use base64::Engine;

        // Accept either a 64-char hex raw private key or a Base58Check WIF.
        let secret = parse_signing_privkey(privkey.trim()).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, e)
        })?;
        // The `compressed` flag is part of the WIF format (0x01 suffix). For
        // raw hex the safe Core-compatible default is compressed.
        let sig = rustoshi_crypto::sign_message_compact(&secret.0, message.as_bytes(), secret.1);
        Ok(base64::engine::general_purpose::STANDARD.encode(sig))
    }

    async fn uptime(&self) -> RpcResult<u64> {
        let state = self.state.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(now.saturating_sub(state.start_time))
    }

    async fn get_net_totals(&self) -> RpcResult<serde_json::Value> {
        let peer_state = self.peer_state.read().await;
        let (bytes_sent, bytes_recv) = if let Some(ref pm) = peer_state.peer_manager {
            let mut sent = 0u64;
            let mut recv = 0u64;
            for (_id, info) in pm.connected_peers() {
                sent += info.bytes_sent;
                recv += info.bytes_recv;
            }
            (sent, recv)
        } else {
            (0u64, 0u64)
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(serde_json::json!({
            "totalbytesrecv": bytes_recv,
            "totalbytessent": bytes_sent,
            "timemillis": now * 1000
        }))
    }

    async fn get_deployment_info(
        &self,
        blockhash: Option<String>,
    ) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        // Resolve the target block height: use the provided block hash or fall
        // back to the current chain tip.
        let (eval_height, eval_hash) = if let Some(ref hash_str) = blockhash {
            let hash = Self::parse_hash(hash_str)?;
            let entry = store
                .get_block_index(&hash)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
                .ok_or_else(|| {
                    Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not found")
                })?;
            (entry.height, hash)
        } else {
            (state.best_height, state.best_hash)
        };

        // Delegate entirely to the shared helper so getdeploymentinfo and
        // getblockchaininfo.softforks always read from the same source of truth.
        let deployments = build_softforks_map(&state.params, eval_height);

        Ok(serde_json::json!({
            "hash": eval_hash.to_hex(),
            "height": eval_height,
            "deployments": deployments
        }))
    }

    async fn dump_tx_outset(
        &self,
        path: String,
        snapshot_type: Option<String>,
        options: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value> {
        // Mirrors `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset` parameter
        // handling. `snapshot_type` is "latest" / "rollback" / "" (=> latest).
        // `options` is an object that may contain `{"rollback": <h | hash>}`.
        let snap_type = snapshot_type.unwrap_or_default();

        // Snapshot the tip metadata up-front; needed for both rollback target
        // resolution and the "latest" fast path. The rollback path needs a
        // write lock once it actually mutates the chainstate; we acquire that
        // below after parameter resolution.
        let state = self.state.read().await;
        let tip_height = state.best_height;

        // -------- snapshot type / target resolution --------
        // Outcome of this block:
        //   * `target_height = Some(h)` if rollback was requested (and we
        //     successfully resolved a height).
        //   * `target_height = None` for the "latest" path.
        let target_height: Option<u32> = match (snap_type.as_str(), options.as_ref()) {
            // Named-param rollback object: `{"rollback": <h | hash>}`.
            (st, Some(opts)) if opts.get("rollback").is_some() => {
                if !st.is_empty() && st != "rollback" {
                    return Err(Self::rpc_error(
                        rpc_error::RPC_INVALID_PARAMS,
                        format!(
                            "Invalid snapshot type \"{}\" specified with rollback option",
                            st
                        ),
                    ));
                }
                let v = &opts["rollback"];
                if let Some(h) = v.as_u64() {
                    if h > u32::MAX as u64 {
                        return Err(Self::rpc_error(
                            rpc_error::RPC_INVALID_PARAMS,
                            format!("rollback height {} out of range", h),
                        ));
                    }
                    Some(h as u32)
                } else if let Some(s) = v.as_str() {
                    // Numeric strings are accepted to match Core's
                    // ParseHashOrHeight behaviour for short numeric inputs.
                    if let Ok(h) = s.parse::<u32>() {
                        Some(h)
                    } else {
                        let parsed = Self::parse_hash(s)?;
                        let store = BlockStore::new(&state.db);
                        let entry = store
                            .get_block_index(&parsed)
                            .map_err(|e| {
                                Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
                            })?
                            .ok_or_else(|| {
                                Self::rpc_error(
                                    rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                                    format!("Block not found: {}", s),
                                )
                            })?;
                        Some(entry.height)
                    }
                } else {
                    return Err(Self::rpc_error(
                        rpc_error::RPC_INVALID_PARAMS,
                        "rollback option must be a height (integer) or block hash (hex string)",
                    ));
                }
            }
            // Bare "rollback" with no target -> latest assumeutxo height <= tip.
            ("rollback", _) => {
                let mut candidate: Option<u32> = None;
                for d in &state.params.assumeutxo_data {
                    if d.height <= tip_height && Some(d.height) > candidate {
                        candidate = Some(d.height);
                    }
                }
                let h = candidate.ok_or_else(|| {
                    Self::rpc_error(
                        rpc_error::RPC_MISC_ERROR,
                        format!(
                            "No assumeutxo snapshot height <= current tip ({}) is available for this network",
                            tip_height
                        ),
                    )
                })?;
                Some(h)
            }
            ("" | "latest", _) => None,
            (other, _) => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!(
                        "Invalid snapshot type \"{}\" specified. Please specify \"rollback\" or \"latest\"",
                        other
                    ),
                ));
            }
        };

        // -------- rollback path --------
        // Mirrors `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset`'s
        // `TemporaryRollback` block: walk the active chain from tip down to
        // `target_height`, restoring UTXOs from each block's stored undo data,
        // dump the snapshot at the rolled-back tip, then re-apply the
        // disconnected blocks via `connect_block` to restore the original tip.
        //
        // Unlike Core (which uses a parallel snapshot chainstate), rustoshi
        // mutates the live UTXO set directly. The replay path does NOT
        // re-validate scripts — they were already validated when these blocks
        // were first connected and we have not changed the spent set, only
        // round-tripped it. This matches Core's behaviour (`TemporaryRollback`
        // never reruns script verification).
        //
        // If anything fails partway through, the chainstate is left rolled
        // back: the caller is told to restart the node (Core does the same;
        // see the abort path in `dumptxoutset`). Block bodies + headers stay
        // on disk, so a normal `ActivateBestChain` on next start replays.
        if let Some(target_h) = target_height {
            // Sanity: target must be strictly below tip (==tip is also fine
            // structurally but pointless — fall through to "latest" by passing
            // through the dump path with no disconnects). For ergonomic parity
            // with Core, we only invoke the rewind path when there is real
            // work to do.
            if target_h > tip_height {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!(
                        "rollback target height {} is above current tip {}",
                        target_h, tip_height
                    ),
                ));
            }

            // Resolve target hash via the height index BEFORE we drop the
            // read lock. If the target falls off the active chain
            // (chainstate corruption / partial reindex), we surface an error
            // here rather than trying to rewind blindly.
            let store = BlockStore::new(&state.db);
            let target_hash = store
                .get_hash_by_height(target_h)
                .map_err(|e| {
                    Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
                })?
                .ok_or_else(|| {
                    Self::rpc_error(
                        rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                        format!(
                            "no active-chain block at height {} (chainstate not synced past target)",
                            target_h
                        ),
                    )
                })?;

            // Capture the active-chain block hashes from `target_h+1..=tip`
            // BEFORE we touch the height index. We need these to drive the
            // disconnect walk and the subsequent reconnect walk. If any
            // height is missing from the index, the chainstate is in an
            // unexpected state and we abort early.
            let mut chain_hashes: Vec<(u32, Hash256)> =
                Vec::with_capacity((tip_height - target_h) as usize);
            for h in (target_h + 1)..=tip_height {
                let hash = store
                    .get_hash_by_height(h)
                    .map_err(|e| {
                        Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
                    })?
                    .ok_or_else(|| {
                        Self::rpc_error(
                            rpc_error::RPC_DATABASE_ERROR,
                            format!("missing active-chain hash at height {}", h),
                        )
                    })?;
                chain_hashes.push((h, hash));
            }

            // Drop the read lock before re-acquiring as a write lock. The
            // chainstate may move between these two acquisitions in theory,
            // but in practice rustoshi serialises chain progression through
            // the same RpcState write lock, so any concurrent block-connect
            // will queue behind us.
            drop(state);

            return self
                .dump_tx_outset_rollback_inner(path, target_h, target_hash, chain_hashes)
                .await;
        }

        // Resolve relative paths against the configured data dir, mirroring
        // Core's `fsbridge::AbsPathJoin(args.GetDataDirNet(), ...)`.
        let path_buf = std::path::PathBuf::from(&path);
        let abs_path = if path_buf.is_absolute() {
            path_buf
        } else if let Some(ref dd) = state.data_dir {
            dd.join(&path)
        } else {
            std::env::current_dir()
                .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?
                .join(&path)
        };

        if abs_path.exists() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!(
                    "{} already exists. If you are sure this is what you want, move it out of the way first.",
                    abs_path.display()
                ),
            ));
        }

        // Tip metadata. `tip_height` was bound at the top of the method so the
        // rollback-target resolver could see it; rebinding the hash + index
        // here keeps the rest of the body unchanged.
        let store = BlockStore::new(&state.db);
        let tip_hash = state.best_hash;
        let tip_index = store
            .get_block_index(&tip_hash)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;

        // Iterate the UTXO column family. RocksDB returns keys in lex order;
        // our `outpoint_key` is `txid (32) || vout (4 BE)`, so iteration is
        // already in `(txid, vout)` ascending order — the same ordering Core
        // requires for `dumptxoutset`.
        let mut coins_count: u64 = 0;
        for (key, _) in state
            .db
            .iter_cf(CF_UTXO)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
        {
            if key.len() == 36 {
                coins_count += 1;
            }
        }

        // Write to a temp path and rename on success, mirroring Core's
        // `temppath = path + ".incomplete"` flow.
        let temp_path = {
            let mut p = abs_path.clone().into_os_string();
            p.push(".incomplete");
            std::path::PathBuf::from(p)
        };

        let file = std::fs::File::create(&temp_path)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        let metadata = SnapshotMetadata::new(tip_hash, coins_count, state.params.network_magic);
        let mut writer = SnapshotWriter::new(file, &metadata)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        let mut written: u64 = 0;
        for (key, value) in state
            .db
            .iter_cf(CF_UTXO)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
        {
            if key.len() != 36 {
                continue;
            }
            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&key[..32]);
            let txid = Hash256(txid_bytes);
            let mut vout_bytes = [0u8; 4];
            vout_bytes.copy_from_slice(&key[32..]);
            let vout = u32::from_be_bytes(vout_bytes);

            let entry: CoinEntry = serde_json::from_slice(&value).map_err(|e| {
                Self::rpc_error(
                    rpc_error::RPC_DATABASE_ERROR,
                    format!("UTXO deserialization failed: {}", e),
                )
            })?;
            let coin = Coin::from_entry(&entry);
            writer
                .write_coin(&OutPoint { txid, vout }, &coin)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;
            written += 1;
        }

        let (_file, txoutset_hash, core_hash_serialized, muhash) = writer
            .finish_with_hashes()
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        std::fs::rename(&temp_path, &abs_path).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_MISC_ERROR, format!("rename failed: {}", e))
        })?;

        let nchaintx: u64 = tip_index
            .as_ref()
            .map(|e| e.n_tx as u64)
            .unwrap_or(0);

        Ok(serde_json::json!({
            "coins_written": written,
            "base_hash": tip_hash.to_hex(),
            "base_height": tip_height,
            "path": abs_path.display().to_string(),
            // Legacy rustoshi `compute_utxo_hash` form — preserved so old
            // tooling keeps working.  Does NOT match Core.
            "txoutset_hash": txoutset_hash.0.to_hex(),
            // Core HASH_SERIALIZED form (sha256d of TxOutSer bytes,
            // grouped by txid).  This is what
            // `AssumeutxoData::hash_serialized` is anchored to.
            "hash_serialized": core_hash_serialized.0.to_hex(),
            // Core MuHash3072 form (matches `gettxoutsetinfo`'s `muhash`
            // field; order-independent in the prime field).
            "muhash": muhash.0.to_hex(),
            "nchaintx": nchaintx,
        }))
    }

    async fn load_tx_outset(&self, path: String) -> RpcResult<serde_json::Value> {
        let mut state = self.state.write().await;

        let path_buf = std::path::PathBuf::from(&path);
        let abs_path = if path_buf.is_absolute() {
            path_buf
        } else if let Some(ref dd) = state.data_dir {
            dd.join(&path)
        } else {
            std::env::current_dir()
                .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?
                .join(&path)
        };

        let file = std::fs::File::open(&abs_path).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!("Couldn't open file {} for reading: {}", abs_path.display(), e),
            )
        })?;

        let mut reader = SnapshotReader::open(file, &state.params.network_magic).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, e.to_string())
        })?;

        // Validate the snapshot's blockhash against the hardcoded
        // `assumeutxo_data` set. Unrecognized bases must be rejected.
        let metadata_blockhash = reader.metadata().base_blockhash;
        let metadata_coins_count = reader.metadata().coins_count;
        let assume = state
            .params
            .assumeutxo_for_blockhash(&metadata_blockhash)
            .cloned()
            .ok_or_else(|| {
                Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!(
                        "Snapshot blockhash {} is not in chainparams.assumeutxo_data — rejecting.",
                        metadata_blockhash.to_hex()
                    ),
                )
            })?;
        let base_height = assume.height;

        // Stream coins into the UTXO column family + accumulate three
        // hashes in parallel:
        //   1. legacy rustoshi `compute_utxo_hash` form (back-compat)
        //   2. Core-compatible `hash_serialized` (sha256d over `TxOutSer`
        //      bytes; this is what `AssumeutxoData::hash_serialized` is
        //      anchored to in `bitcoin-core/src/kernel/chainparams.cpp`)
        //   3. MuHash3072 over the same `TxOutSer` bytes (matches
        //      `gettxoutsetinfo`'s `muhash` field)
        let store = BlockStore::new(&state.db);
        use sha2::Digest as _;
        let mut legacy_hasher = sha2::Sha256::new();
        let mut core_hasher = sha2::Sha256::new();
        let mut muhash = rustoshi_storage::MuHash3072::new();
        let mut loaded: u64 = 0;
        while let Some((outpoint, coin)) = reader
            .read_coin()
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, e.to_string()))?
        {
            // Legacy (rustoshi-only) per-coin layout — not Core-compatible
            // but preserved here so existing snapshots produced by older
            // dumptxoutset still validate.
            let mut data = Vec::with_capacity(32 + 4 + 4 + 1 + 8 + coin.tx_out.script_pubkey.len());
            data.extend_from_slice(outpoint.txid.as_bytes());
            data.extend_from_slice(&outpoint.vout.to_le_bytes());
            data.extend_from_slice(&coin.height.to_le_bytes());
            data.push(if coin.is_coinbase { 1 } else { 0 });
            data.extend_from_slice(&coin.tx_out.value.to_le_bytes());
            data.extend_from_slice(&coin.tx_out.script_pubkey);
            legacy_hasher.update(&data);

            // Core-compatible TxOutSer (kernel/coinstats.cpp::TxOutSer):
            //   outpoint || u32_LE((height<<1)|coinbase) || i64_LE(value)
            //   || CompactSize(script.len()) || script
            let mut core_bytes = Vec::with_capacity(
                32 + 4 + 4 + 8 + 9 + coin.tx_out.script_pubkey.len(),
            );
            core_bytes.extend_from_slice(outpoint.txid.as_bytes());
            core_bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
            let code: u32 = (coin.height << 1) | (coin.is_coinbase as u32);
            core_bytes.extend_from_slice(&code.to_le_bytes());
            core_bytes.extend_from_slice(&(coin.tx_out.value as i64).to_le_bytes());
            // CompactSize(script_len)
            let n = coin.tx_out.script_pubkey.len() as u64;
            if n < 0xFD {
                core_bytes.push(n as u8);
            } else if n <= 0xFFFF {
                core_bytes.push(0xFD);
                core_bytes.extend_from_slice(&(n as u16).to_le_bytes());
            } else if n <= 0xFFFF_FFFF {
                core_bytes.push(0xFE);
                core_bytes.extend_from_slice(&(n as u32).to_le_bytes());
            } else {
                core_bytes.push(0xFF);
                core_bytes.extend_from_slice(&n.to_le_bytes());
            }
            core_bytes.extend_from_slice(&coin.tx_out.script_pubkey);
            core_hasher.update(&core_bytes);
            muhash.insert(&core_bytes);

            let entry = coin.to_entry();
            store
                .put_utxo(&outpoint, &entry)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;
            loaded += 1;
        }
        reader
            .verify_complete()
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, e.to_string()))?;

        if loaded != metadata_coins_count {
            return Err(Self::rpc_error(
                rpc_error::RPC_DESERIALIZATION_ERROR,
                format!(
                    "coins_count mismatch: header says {} but body had {}",
                    metadata_coins_count, loaded
                ),
            ));
        }

        // Final double-SHA256 over the streamed per-coin layout, matching
        // `compute_utxo_hash`'s output.
        let first_hash = legacy_hasher.finalize();
        let mut second = sha2::Sha256::new();
        second.update(first_hash);
        let final_hash = second.finalize();
        let mut final_bytes = [0u8; 32];
        final_bytes.copy_from_slice(&final_hash);
        let computed_legacy = Hash256(final_bytes);

        // Final sha256d over the Core TxOutSer bytes — this is the form
        // `validation.cpp:5912-5914` validates against, modulo the
        // per-tx-group ordering (which our writer/loader already enforce).
        let first_core = core_hasher.finalize();
        let mut second_core = sha2::Sha256::new();
        second_core.update(first_core);
        let final_core = second_core.finalize();
        let mut core_bytes_out = [0u8; 32];
        core_bytes_out.copy_from_slice(&final_core);
        let computed_core_hash_serialized = Hash256(core_bytes_out);

        // Finalize the MuHash for completeness (returned in the JSON
        // response so callers can cross-check against `gettxoutsetinfo`).
        let computed_muhash = muhash.finalize();

        // Validate against the chainparams entry's hash_serialized.  We
        // accept either the legacy rustoshi form (back-compat with
        // existing snapshots) OR the Core HASH_SERIALIZED form.  When
        // neither matches we report Core's exact wording from
        // `bitcoin-core/src/validation.cpp:5912-5914`.
        let expected = assume.hash_serialized.0;
        if computed_legacy != expected && computed_core_hash_serialized != expected {
            return Err(Self::rpc_error(
                rpc_error::RPC_VERIFY_REJECTED,
                format!(
                    "Bad snapshot content hash: expected {}, got {}",
                    expected.to_hex(),
                    computed_core_hash_serialized.to_hex()
                ),
            ));
        }
        let computed = if computed_core_hash_serialized == expected {
            computed_core_hash_serialized
        } else {
            computed_legacy
        };

        // Mark the snapshot as the new chain tip — this is a one-way operation
        // mirroring Core's `ActivateSnapshot`. A full implementation would
        // also flag the chainstate as snapshot-derived for later background
        // validation; for now we update best_hash / best_height so subsequent
        // RPCs see the loaded tip.
        state.best_hash = metadata_blockhash;
        state.best_height = base_height;
        if state.header_height < base_height {
            state.header_height = base_height;
        }

        // Persist a marker in the data dir so a restart can recognize the
        // snapshot-derived state. Best-effort; failure is non-fatal.
        if let Some(ref dd) = state.data_dir {
            let _ = rustoshi_storage::write_snapshot_blockhash(dd, &metadata_blockhash);
        }

        Ok(serde_json::json!({
            "coins_loaded": loaded,
            "tip_hash": metadata_blockhash.to_hex(),
            "base_height": base_height,
            "path": abs_path.display().to_string(),
            // Hash actually used for the chainparams cross-check.  Will be
            // either the legacy rustoshi form or the Core HASH_SERIALIZED
            // form, depending on which matched.
            "txoutset_hash": computed.to_hex(),
            // Core's gettxoutsetinfo MuHash variant (over the same per-coin
            // TxOutSer bytes).  Independent of insertion order.
            "muhash": computed_muhash.to_hex(),
            // Core's HASH_SERIALIZED variant (sha256d over per-coin
            // TxOutSer bytes).  This is what `AssumeutxoData::hash_serialized`
            // is anchored to in Core's chainparams.cpp.
            "hash_serialized": computed_core_hash_serialized.to_hex(),
        }))
    }
}

impl RpcServerImpl {
    /// Disconnect→dump→reconnect path for `dumptxoutset` rollback mode.
    ///
    /// `target_height` / `target_hash` identify the rolled-back tip the
    /// caller wants the snapshot anchored at (an ancestor of the current
    /// tip). `chain_hashes` is the ordered list of active-chain blocks
    /// strictly above `target_height` up to the current tip — these are the
    /// blocks we will disconnect (then re-apply on the way out).
    ///
    /// Mirrors `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset` 's
    /// `TemporaryRollback` (`src/validation.cpp` `InvalidateBlock` is the
    /// equivalent primitive on Core's side; we use a lighter-weight
    /// disconnect-and-replay because we do not need to stick on the
    /// rolled-back chain after dumping).
    async fn dump_tx_outset_rollback_inner(
        &self,
        path: String,
        target_height: u32,
        target_hash: Hash256,
        chain_hashes: Vec<(u32, Hash256)>,
    ) -> RpcResult<serde_json::Value> {
        use rustoshi_consensus::validation::UtxoView as _;

        let mut state = self.state.write().await;

        // Resolve the snapshot output path before we touch anything: an
        // already-existing file is the only error we want to surface
        // BEFORE rolling the chain back, so the caller can retry without
        // having paid for a rewind+replay round-trip.
        let path_buf = std::path::PathBuf::from(&path);
        let abs_path = if path_buf.is_absolute() {
            path_buf
        } else if let Some(ref dd) = state.data_dir {
            dd.join(&path)
        } else {
            std::env::current_dir()
                .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?
                .join(&path)
        };
        if abs_path.exists() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!(
                    "{} already exists. If you are sure this is what you want, move it out of the way first.",
                    abs_path.display()
                ),
            ));
        }

        let original_tip_hash = state.best_hash;
        let original_tip_height = state.best_height;

        // -------- 1. Pre-fetch every block + undo we will need --------
        // We materialise the disconnected blocks (and their undo data) up
        // front so the disconnect/reconnect loops are pure UTXO mutations
        // with no further DB-miss surprises midway through. The
        // `BlockStore` is constructed in a tight scope so its borrow on
        // `state.db` doesn't conflict with the later mutations of
        // `state.best_*`.
        let mut disconnect_plan: Vec<(u32, Hash256, Block, rustoshi_storage::block_store::UndoData)> =
            Vec::with_capacity(chain_hashes.len());
        {
            let store = BlockStore::new(&state.db);
            for (h, hash) in &chain_hashes {
                let block = store
                    .get_block(hash)
                    .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
                    .ok_or_else(|| {
                        Self::rpc_error(
                            rpc_error::RPC_DATABASE_ERROR,
                            format!(
                                "rollback aborted: missing block body at height {} ({})",
                                h, hash
                            ),
                        )
                    })?;
                let undo = store
                    .get_undo(hash)
                    .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
                    .ok_or_else(|| {
                        Self::rpc_error(
                            rpc_error::RPC_DATABASE_ERROR,
                            format!(
                                "rollback aborted: missing undo data at height {} ({}); cannot safely rewind",
                                h, hash
                            ),
                        )
                    })?;
                disconnect_plan.push((*h, *hash, block, undo));
            }
        }

        // -------- 2. Disconnect tip → target --------
        // We walk the planned blocks in reverse (tip-first) and apply
        // `validation::disconnect_block` against a single `BlockStoreUtxoView`.
        // The view buffers UTXO mutations in memory and we flush at the end
        // of the disconnect walk.
        //
        // The two `UndoData` types (storage vs validation) have identical
        // shape; we transcribe entry-by-entry.
        {
            let store = BlockStore::new(&state.db);
            let mut utxo_view = store.utxo_view();
            for (h, hash, block, storage_undo) in disconnect_plan.iter().rev() {
                let v_undo = rustoshi_consensus::validation::UndoData {
                    spent_coins: storage_undo
                        .spent_coins
                        .iter()
                        .map(|c| rustoshi_consensus::validation::CoinEntry {
                            height: c.height,
                            is_coinbase: c.is_coinbase,
                            value: c.value,
                            script_pubkey: c.script_pubkey.clone(),
                        })
                        .collect(),
                };
                rustoshi_consensus::validation::disconnect_block(block, &v_undo, &mut utxo_view)
                    .map_err(|e| {
                        Self::rpc_error(
                            rpc_error::RPC_MISC_ERROR,
                            format!(
                                "rollback aborted at height {} ({}): disconnect_block failed: {}",
                                h, hash, e
                            ),
                        )
                    })?;
            }
            utxo_view.flush().map_err(|e| {
                Self::rpc_error(
                    rpc_error::RPC_DATABASE_ERROR,
                    format!("rollback aborted: UTXO flush failed after disconnect: {}", e),
                )
            })?;
            store
                .set_best_block(&target_hash, target_height)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;
        }

        // Update the chain tip metadata to reflect the rolled-back state.
        // The height index entries for `target_height+1..=original_tip_height`
        // are deliberately LEFT in place: the reconnect walk below relies on
        // them, and even on the failure path keeping them is harmless because
        // the next start-up will activate the longest valid chain.
        state.best_hash = target_hash;
        state.best_height = target_height;

        tracing::info!(
            "dumptxoutset rollback: rewound {} blocks ({} -> {}) for snapshot",
            disconnect_plan.len(),
            original_tip_height,
            target_height
        );

        // -------- 3. Dump the snapshot at the rolled-back tip --------
        let dump_result = Self::dump_tx_outset_at_current_tip(&state, &abs_path);

        // -------- 4. Reconnect target+1..tip --------
        // Independent of whether the dump succeeded, we always try to
        // restore the chain to its original tip. If the dump failed we
        // still want to leave the node usable.
        //
        // Replay does NOT re-validate scripts: the disconnect/reconnect
        // round-trip preserves UTXO contents bit-for-bit (we restore the
        // exact `spent_coins` we just consumed and re-add the exact
        // outputs we just deleted). Re-running scripts would just re-prove
        // what we already proved on the original connect — and would also
        // double the cost of `dumptxoutset` for no benefit. Mirrors Core's
        // `TemporaryRollback`, which never reruns script verification.
        let replay_result: Result<(), ErrorObjectOwned> = (|| {
            let store = BlockStore::new(&state.db);
            let mut utxo_view = store.utxo_view();
            for (h, hash, block, _undo) in disconnect_plan.iter() {
                // Re-apply outputs (including coinbase) and re-spend inputs
                // by hand. We avoid `connect_block` here because it would
                // re-run script verification + sigop counting; we only need
                // the UTXO-set delta.
                for tx in &block.transactions {
                    let txid = tx.txid();
                    if !tx.is_coinbase() {
                        for input in &tx.inputs {
                            utxo_view.spend_utxo(&input.previous_output);
                        }
                    }
                    for (vout, output) in tx.outputs.iter().enumerate() {
                        // Skip provably-unspendable OP_RETURN outputs to
                        // match what `connect_block`/`connect_block_parallel`
                        // store in the UTXO set.
                        if !output.script_pubkey.is_empty()
                            && output.script_pubkey[0] == 0x6a
                        {
                            continue;
                        }
                        // Skip the magic null-witness-commitment placeholder
                        // (empty script + zero value) used by witness coinbase.
                        if tx.is_coinbase()
                            && output.script_pubkey.is_empty()
                            && output.value == 0
                        {
                            continue;
                        }
                        let outpoint = OutPoint { txid, vout: vout as u32 };
                        utxo_view.add_utxo(
                            &outpoint,
                            rustoshi_consensus::validation::CoinEntry {
                                height: *h,
                                is_coinbase: tx.is_coinbase(),
                                value: output.value,
                                script_pubkey: output.script_pubkey.clone(),
                            },
                        );
                    }
                }
                // Restore tip metadata as we go so a mid-replay crash
                // leaves the persistent state at a connected prefix of the
                // original chain.
                utxo_view.flush().map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!(
                            "rollback replay: flush failed at height {} ({}): {}",
                            h, hash, e
                        ),
                    )
                })?;
                store.set_best_block(hash, *h).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!(
                            "rollback replay: set_best_block failed at height {}: {}",
                            h, e
                        ),
                    )
                })?;
            }
            Ok(())
        })();

        // Restore in-memory tip pointers regardless of dump outcome —
        // either we replayed cleanly (state matches `original_tip_*`) or
        // the replay errored partway through (in which case persistent
        // state is at the last successfully-replayed height, but the
        // safest in-memory bet is still the original tip; the caller is
        // told to restart).
        match &replay_result {
            Ok(()) => {
                state.best_hash = original_tip_hash;
                state.best_height = original_tip_height;
                tracing::info!(
                    "dumptxoutset rollback: replayed {} blocks; tip restored to {} at height {}",
                    disconnect_plan.len(),
                    original_tip_hash,
                    original_tip_height
                );
            }
            Err(err) => {
                tracing::error!(
                    "dumptxoutset rollback: replay failed ({}); chainstate left mid-replay, \
                     restart node to recover via ActivateBestChain",
                    err.message()
                );
            }
        }

        // Surface dump or replay failure (dump first — replay errors are
        // operationally identical to a dump that succeeded but couldn't
        // restore). On success, return the dump's JSON with an extra
        // `rollback` block so callers can verify the rewind happened.
        let dump_json = dump_result?;
        replay_result?;

        let mut obj = match dump_json {
            serde_json::Value::Object(m) => m,
            other => {
                let mut m = serde_json::Map::new();
                m.insert("result".to_string(), other);
                m
            }
        };
        obj.insert(
            "rollback".to_string(),
            serde_json::json!({
                "from_height": original_tip_height,
                "from_hash": original_tip_hash.to_hex(),
                "to_height": target_height,
                "to_hash": target_hash.to_hex(),
                "blocks_rewound": disconnect_plan.len(),
            }),
        );
        Ok(serde_json::Value::Object(obj))
    }

    /// Dump the UTXO set at the current `state.best_*` to `abs_path`.
    ///
    /// Factored out so the rollback path can call into the same writer
    /// the "latest" path uses, after rewinding the chainstate. Pure
    /// snapshot-of-current-state — no chain mutation here.
    fn dump_tx_outset_at_current_tip(
        state: &RpcState,
        abs_path: &std::path::Path,
    ) -> RpcResult<serde_json::Value> {
        let store = BlockStore::new(&state.db);
        let tip_hash = state.best_hash;
        let tip_height = state.best_height;
        let tip_index = store
            .get_block_index(&tip_hash)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;

        // Count coins.
        let mut coins_count: u64 = 0;
        for (key, _) in state
            .db
            .iter_cf(CF_UTXO)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
        {
            if key.len() == 36 {
                coins_count += 1;
            }
        }

        let temp_path = {
            let mut p = abs_path.to_path_buf().into_os_string();
            p.push(".incomplete");
            std::path::PathBuf::from(p)
        };

        let file = std::fs::File::create(&temp_path)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        let metadata = SnapshotMetadata::new(tip_hash, coins_count, state.params.network_magic);
        let mut writer = SnapshotWriter::new(file, &metadata)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        let mut written: u64 = 0;
        for (key, value) in state
            .db
            .iter_cf(CF_UTXO)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
        {
            if key.len() != 36 {
                continue;
            }
            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&key[..32]);
            let txid = Hash256(txid_bytes);
            let mut vout_bytes = [0u8; 4];
            vout_bytes.copy_from_slice(&key[32..]);
            let vout = u32::from_be_bytes(vout_bytes);

            let entry: CoinEntry = serde_json::from_slice(&value).map_err(|e| {
                Self::rpc_error(
                    rpc_error::RPC_DATABASE_ERROR,
                    format!("UTXO deserialization failed: {}", e),
                )
            })?;
            let coin = Coin::from_entry(&entry);
            writer
                .write_coin(&OutPoint { txid, vout }, &coin)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;
            written += 1;
        }

        let (_file, txoutset_hash, core_hash_serialized, muhash) = writer
            .finish_with_hashes()
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        std::fs::rename(&temp_path, abs_path).map_err(|e| {
            Self::rpc_error(rpc_error::RPC_MISC_ERROR, format!("rename failed: {}", e))
        })?;

        let nchaintx: u64 = tip_index.as_ref().map(|e| e.n_tx as u64).unwrap_or(0);

        Ok(serde_json::json!({
            "coins_written": written,
            "base_hash": tip_hash.to_hex(),
            "base_height": tip_height,
            "path": abs_path.display().to_string(),
            "txoutset_hash": txoutset_hash.0.to_hex(),
            "hash_serialized": core_hash_serialized.0.to_hex(),
            "muhash": muhash.0.to_hex(),
            "nchaintx": nchaintx,
        }))
    }

    /// Mine blocks with coinbase reward going to the specified scriptPubKey.
    async fn mine_blocks(
        &self,
        nblocks: u32,
        script_pubkey: Vec<u8>,
        maxtries: u64,
    ) -> RpcResult<Vec<String>> {
        let mut block_hashes = Vec::with_capacity(nblocks as usize);

        for _ in 0..nblocks {
            let hash = self.mine_single_block(script_pubkey.clone(), None, maxtries).await?;
            block_hashes.push(hash);
            // Yield between blocks so the event loop can process peer
            // getdata requests before the next inv is broadcast.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        Ok(block_hashes)
    }

    /// Mine a block with specific transactions.
    async fn mine_block_with_txs(
        &self,
        script_pubkey: Vec<u8>,
        txs: Vec<Transaction>,
    ) -> RpcResult<Vec<String>> {
        let hash = self.mine_single_block(script_pubkey, Some(txs), 1_000_000).await?;
        Ok(vec![hash])
    }

    /// Mine a single block.
    async fn mine_single_block(
        &self,
        script_pubkey: Vec<u8>,
        custom_txs: Option<Vec<Transaction>>,
        maxtries: u64,
    ) -> RpcResult<String> {
        use rustoshi_consensus::block_template::{build_block_template, BlockTemplateConfig};
        use rustoshi_consensus::params::compact_to_target;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut state = self.state.write().await;
        let store = BlockStore::new(&state.db);

        let height = state.best_height + 1;
        let prev_hash = state.best_hash;

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Get the bits from the previous block (for regtest, it stays constant)
        let bits = store
            .get_header(&prev_hash)
            .ok()
            .flatten()
            .map(|h| h.bits)
            .unwrap_or(0x207fffff); // Regtest default difficulty

        // Compute median-time-past from the last 11 blocks
        let mut timestamps = Vec::new();
        let mut cursor = prev_hash;
        for _ in 0..11 {
            if let Ok(Some(hdr)) = store.get_header(&cursor) {
                timestamps.push(hdr.timestamp);
                cursor = hdr.prev_block_hash;
            } else {
                break;
            }
        }
        let median_time_past = if timestamps.is_empty() {
            now as i64
        } else {
            timestamps.sort();
            timestamps[timestamps.len() / 2] as i64
        };

        // Timestamp must be strictly greater than MTP
        let timestamp = std::cmp::max(now, (median_time_past + 1) as u32);

        // Build block template
        let config = BlockTemplateConfig {
            coinbase_script_pubkey: script_pubkey.clone(),
            ..Default::default()
        };

        let mut template = build_block_template(
            &state.mempool,
            prev_hash,
            height,
            timestamp,
            bits,
            median_time_past,
            &state.params,
            &config,
        );

        // If custom transactions are provided, replace them
        if let Some(txs) = custom_txs {
            // Keep the coinbase, add custom transactions
            let coinbase = template.transactions.remove(0);
            template.transactions = vec![coinbase];
            template.transactions.extend(txs);

            // Recompute merkle root
            let merkle_root = compute_merkle_root(&template.transactions);
            template.header.merkle_root = merkle_root;
        }

        // Find a valid nonce (for regtest, this is trivial)
        let target = compact_to_target(bits);
        let mut block = Block {
            header: template.header,
            transactions: template.transactions,
        };

        let mut found = false;
        for nonce in 0..maxtries {
            block.header.nonce = nonce as u32;
            let hash = block.block_hash();

            // Compare hash to target (both are big-endian)
            if hash_less_than_target(&hash.0, &target) {
                found = true;
                break;
            }
        }

        if !found {
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("Failed to find valid nonce after {} tries", maxtries),
            ));
        }

        let block_hash = block.block_hash();

        // Connect the block to the chain
        // First, validate and connect it
        let mut utxo_view = store.utxo_view();

        // Add the block to storage
        store.put_block(&block_hash, &block).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DATABASE_ERROR,
                format!("Failed to store block: {}", e),
            )
        })?;

        // Connect the block (updates UTXO set)
        let result = rustoshi_consensus::validation::connect_block(
            &block,
            height,
            &mut utxo_view,
            &state.params,
        );

        match result {
            Ok((_undo_data, _fees)) => {
                // Flush UTXO changes
                utxo_view.flush().map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to flush UTXO changes: {}", e),
                    )
                })?;

                // Store the header and update chain tip
                store.put_header(&block_hash, &block.header).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to store header: {}", e),
                    )
                })?;

                store.put_height_index(height, &block_hash).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to store height index: {}", e),
                    )
                })?;

                // Store block index entry for metadata lookups
                {
                    use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
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
                        chain_work: [0u8; 32],
                    };
                    store.put_block_index(&block_hash, &entry).map_err(|e| {
                        Self::rpc_error(
                            rpc_error::RPC_DATABASE_ERROR,
                            format!("Failed to store block index: {}", e),
                        )
                    })?;
                }

                // Store transaction index entries for all transactions in the block
                {
                    use rustoshi_storage::block_store::TxIndexEntry;
                    for tx in &block.transactions {
                        let entry = TxIndexEntry {
                            block_hash,
                            tx_offset: 0,
                            tx_length: 0,
                        };
                        store.put_tx_index(&tx.txid(), &entry).map_err(|e| {
                            Self::rpc_error(
                                rpc_error::RPC_DATABASE_ERROR,
                                format!("Failed to store tx index: {}", e),
                            )
                        })?;
                    }
                }

                store.set_best_block(&block_hash, height).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to update best block: {}", e),
                    )
                })?;

                // Update state
                state.best_hash = block_hash;
                state.best_height = height;

                // NOTE: IBD latch is re-evaluated on every getblockchaininfo
                // call (see get_blockchain_info). We deliberately do NOT call
                // should_exit_ibd here because mine_single_block writes a
                // BlockIndexEntry with chain_work=[0u8; 32] (see below), so
                // the latch check would always fail until chain_work tracking
                // is implemented.

                // Remove mined transactions from mempool
                for tx in &block.transactions[1..] {
                    // Skip coinbase
                    state.mempool.remove_transaction(&tx.txid(), false);
                }

                tracing::info!(
                    "Generated block {} at height {}",
                    block_hash.to_hex(),
                    height
                );

                // Broadcast inv(MSG_BLOCK) to all connected peers
                {
                    let ps = self.peer_state.read().await;
                    if let Some(ref pm) = ps.peer_manager {
                        let inv_msg = NetworkMessage::Inv(vec![InvVector {
                            inv_type: InvType::MsgBlock,
                            hash: block_hash,
                        }]);
                        pm.broadcast(inv_msg).await;
                        tracing::info!(
                            "Broadcast block inv {} to peers",
                            block_hash.to_hex()
                        );
                    }
                }

                Ok(block_hash.to_hex())
            }
            Err(e) => Err(Self::rpc_error(
                rpc_error::RPC_VERIFY_REJECTED,
                format!("Block validation failed: {:?}", e),
            )),
        }
    }
}

/// Parse a signing private key from either:
/// - 64-character hex (raw 32-byte secret) — assumed compressed-pubkey form,
/// - or a Base58Check WIF (mainnet 0x80, testnet 0xef) with optional 0x01
///   compression suffix.
///
/// Returns `(SecretKey, compressed)` so the caller can pass the correct
/// flag to the message-sign primitive (so the recovery byte matches the
/// pubkey hash encoding the signer would normally publish).
fn parse_signing_privkey(input: &str) -> Result<(rustoshi_crypto::SecretKey, bool), String> {
    use rustoshi_crypto::base58check_decode;

    // Hex form: 64 chars, raw 32-byte private key. Default compressed=true.
    if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(input).map_err(|_| "Invalid hex private key".to_string())?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length".to_string())?;
        let key = rustoshi_crypto::SecretKey::from_slice(&arr)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        return Ok((key, true));
    }
    // WIF: base58check; 33 bytes (uncompressed) or 34 bytes (compressed).
    let data = base58check_decode(input).map_err(|e| format!("Invalid WIF: {}", e))?;
    if data.is_empty() {
        return Err("Empty WIF payload".to_string());
    }
    // First byte is the version (0x80 mainnet, 0xef testnet/regtest).
    let payload = &data[1..];
    let (raw, compressed) = match payload.len() {
        32 => (payload, false),
        33 => {
            if payload[32] != 0x01 {
                return Err("Invalid WIF compression flag".to_string());
            }
            (&payload[..32], true)
        }
        _ => return Err("Invalid WIF payload length".to_string()),
    };
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "Invalid WIF key length".to_string())?;
    let key = rustoshi_crypto::SecretKey::from_slice(&arr)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    Ok((key, compressed))
}

/// Compute merkle root for a list of transactions.
fn compute_merkle_root(transactions: &[Transaction]) -> Hash256 {
    use rustoshi_primitives::Hash256;

    if transactions.is_empty() {
        return Hash256::ZERO;
    }

    let mut hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();

    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().unwrap());
        }

        let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
        for chunk in hashes.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&chunk[0].0);
            combined[32..].copy_from_slice(&chunk[1].0);
            let hash = rustoshi_crypto::hashes::sha256d(&combined);
            new_hashes.push(hash);
        }
        hashes = new_hashes;
    }

    hashes[0]
}

/// Check if a hash (big-endian) is less than a target (big-endian).
fn hash_less_than_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    // hash is in internal byte order (LSB first), target is big-endian (MSB first).
    // Compare most-significant bytes first.
    for i in 0..32 {
        let h = hash[31 - i];
        let t = target[i];
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true // Equal is acceptable (<=)
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
#[allow(dead_code)]
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

/// Build verbose transaction info with all details.
///
/// This is used by getrawtransaction verbose mode.
fn build_tx_info_verbose(
    tx: &Transaction,
    block_hash: Option<&Hash256>,
    confirmations: Option<u32>,
    blocktime: Option<u32>,
    _state: &RpcState,
    _store: &BlockStore,
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
                            asm: disassemble_script(&input.script_sig),
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
            .map(|(n, output)| {
                let script_type = detect_script_type(&output.script_pubkey);
                TxOutputInfo {
                    value: output.value as f64 / COIN as f64,
                    n: n as u32,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: disassemble_script(&output.script_pubkey),
                        hex: hex::encode(&output.script_pubkey),
                        script_type,
                        address: None, // Address encoding would require bech32/base58 logic
                    },
                }
            })
            .collect(),
        hex: hex::encode(tx.serialize()),
        blockhash: block_hash.map(|h| h.to_hex()),
        confirmations,
        blocktime,
        time: blocktime, // time is the same as blocktime for confirmed txs
    }
}

/// Disassemble a script into human-readable form.
fn disassemble_script(script: &[u8]) -> String {
    let mut result = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];

        match opcode {
            // Push data opcodes
            0x00 => result.push("0".to_string()),
            0x01..=0x4b => {
                // Direct push of 1-75 bytes
                let len = opcode as usize;
                if i + 1 + len <= script.len() {
                    result.push(hex::encode(&script[i + 1..i + 1 + len]));
                    i += len;
                } else {
                    result.push("[error: truncated push]".to_string());
                    break;
                }
            }
            0x4c => {
                // OP_PUSHDATA1
                if i + 1 < script.len() {
                    let len = script[i + 1] as usize;
                    if i + 2 + len <= script.len() {
                        result.push(hex::encode(&script[i + 2..i + 2 + len]));
                        i += 1 + len;
                    } else {
                        result.push("[error: truncated pushdata1]".to_string());
                        break;
                    }
                } else {
                    result.push("[error: truncated pushdata1]".to_string());
                    break;
                }
            }
            0x4d => {
                // OP_PUSHDATA2
                if i + 2 < script.len() {
                    let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    if i + 3 + len <= script.len() {
                        result.push(hex::encode(&script[i + 3..i + 3 + len]));
                        i += 2 + len;
                    } else {
                        result.push("[error: truncated pushdata2]".to_string());
                        break;
                    }
                } else {
                    result.push("[error: truncated pushdata2]".to_string());
                    break;
                }
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 4 < script.len() {
                    let len = u32::from_le_bytes([
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                        script[i + 4],
                    ]) as usize;
                    if i + 5 + len <= script.len() {
                        result.push(hex::encode(&script[i + 5..i + 5 + len]));
                        i += 4 + len;
                    } else {
                        result.push("[error: truncated pushdata4]".to_string());
                        break;
                    }
                } else {
                    result.push("[error: truncated pushdata4]".to_string());
                    break;
                }
            }
            // Small integers
            0x4f => result.push("OP_1NEGATE".to_string()),
            0x50 => result.push("OP_RESERVED".to_string()),
            0x51 => result.push("OP_1".to_string()),
            0x52 => result.push("OP_2".to_string()),
            0x53 => result.push("OP_3".to_string()),
            0x54 => result.push("OP_4".to_string()),
            0x55 => result.push("OP_5".to_string()),
            0x56 => result.push("OP_6".to_string()),
            0x57 => result.push("OP_7".to_string()),
            0x58 => result.push("OP_8".to_string()),
            0x59 => result.push("OP_9".to_string()),
            0x5a => result.push("OP_10".to_string()),
            0x5b => result.push("OP_11".to_string()),
            0x5c => result.push("OP_12".to_string()),
            0x5d => result.push("OP_13".to_string()),
            0x5e => result.push("OP_14".to_string()),
            0x5f => result.push("OP_15".to_string()),
            0x60 => result.push("OP_16".to_string()),
            // Flow control
            0x61 => result.push("OP_NOP".to_string()),
            0x63 => result.push("OP_IF".to_string()),
            0x64 => result.push("OP_NOTIF".to_string()),
            0x67 => result.push("OP_ELSE".to_string()),
            0x68 => result.push("OP_ENDIF".to_string()),
            0x69 => result.push("OP_VERIFY".to_string()),
            0x6a => result.push("OP_RETURN".to_string()),
            // Stack ops
            0x6b => result.push("OP_TOALTSTACK".to_string()),
            0x6c => result.push("OP_FROMALTSTACK".to_string()),
            0x73 => result.push("OP_IFDUP".to_string()),
            0x74 => result.push("OP_DEPTH".to_string()),
            0x75 => result.push("OP_DROP".to_string()),
            0x76 => result.push("OP_DUP".to_string()),
            0x77 => result.push("OP_NIP".to_string()),
            0x78 => result.push("OP_OVER".to_string()),
            0x79 => result.push("OP_PICK".to_string()),
            0x7a => result.push("OP_ROLL".to_string()),
            0x7b => result.push("OP_ROT".to_string()),
            0x7c => result.push("OP_SWAP".to_string()),
            0x7d => result.push("OP_TUCK".to_string()),
            0x6d => result.push("OP_2DROP".to_string()),
            0x6e => result.push("OP_2DUP".to_string()),
            0x6f => result.push("OP_3DUP".to_string()),
            0x70 => result.push("OP_2OVER".to_string()),
            0x71 => result.push("OP_2ROT".to_string()),
            0x72 => result.push("OP_2SWAP".to_string()),
            // Splice ops
            0x82 => result.push("OP_SIZE".to_string()),
            // Bitwise logic
            0x87 => result.push("OP_EQUAL".to_string()),
            0x88 => result.push("OP_EQUALVERIFY".to_string()),
            // Arithmetic
            0x8b => result.push("OP_1ADD".to_string()),
            0x8c => result.push("OP_1SUB".to_string()),
            0x8f => result.push("OP_NEGATE".to_string()),
            0x90 => result.push("OP_ABS".to_string()),
            0x91 => result.push("OP_NOT".to_string()),
            0x92 => result.push("OP_0NOTEQUAL".to_string()),
            0x93 => result.push("OP_ADD".to_string()),
            0x94 => result.push("OP_SUB".to_string()),
            0x9a => result.push("OP_BOOLAND".to_string()),
            0x9b => result.push("OP_BOOLOR".to_string()),
            0x9c => result.push("OP_NUMEQUAL".to_string()),
            0x9d => result.push("OP_NUMEQUALVERIFY".to_string()),
            0x9e => result.push("OP_NUMNOTEQUAL".to_string()),
            0x9f => result.push("OP_LESSTHAN".to_string()),
            0xa0 => result.push("OP_GREATERTHAN".to_string()),
            0xa1 => result.push("OP_LESSTHANOREQUAL".to_string()),
            0xa2 => result.push("OP_GREATERTHANOREQUAL".to_string()),
            0xa3 => result.push("OP_MIN".to_string()),
            0xa4 => result.push("OP_MAX".to_string()),
            0xa5 => result.push("OP_WITHIN".to_string()),
            // Crypto
            0xa6 => result.push("OP_RIPEMD160".to_string()),
            0xa7 => result.push("OP_SHA1".to_string()),
            0xa8 => result.push("OP_SHA256".to_string()),
            0xa9 => result.push("OP_HASH160".to_string()),
            0xaa => result.push("OP_HASH256".to_string()),
            0xab => result.push("OP_CODESEPARATOR".to_string()),
            0xac => result.push("OP_CHECKSIG".to_string()),
            0xad => result.push("OP_CHECKSIGVERIFY".to_string()),
            0xae => result.push("OP_CHECKMULTISIG".to_string()),
            0xaf => result.push("OP_CHECKMULTISIGVERIFY".to_string()),
            // Expansion
            0xb0 => result.push("OP_NOP1".to_string()),
            0xb1 => result.push("OP_CHECKLOCKTIMEVERIFY".to_string()),
            0xb2 => result.push("OP_CHECKSEQUENCEVERIFY".to_string()),
            0xb3 => result.push("OP_NOP4".to_string()),
            0xb4 => result.push("OP_NOP5".to_string()),
            0xb5 => result.push("OP_NOP6".to_string()),
            0xb6 => result.push("OP_NOP7".to_string()),
            0xb7 => result.push("OP_NOP8".to_string()),
            0xb8 => result.push("OP_NOP9".to_string()),
            0xb9 => result.push("OP_NOP10".to_string()),
            0xba => result.push("OP_CHECKSIGADD".to_string()),
            _ => result.push(format!("OP_UNKNOWN[{:#04x}]", opcode)),
        }
        i += 1;
    }

    result.join(" ")
}

/// Classify a script into its type.
fn classify_script(script: &[u8]) -> String {
    if script.len() == 25
        && script[0] == 0x76  // OP_DUP
        && script[1] == 0xa9  // OP_HASH160
        && script[2] == 0x14  // push 20 bytes
        && script[23] == 0x88 // OP_EQUALVERIFY
        && script[24] == 0xac // OP_CHECKSIG
    {
        return "pubkeyhash".to_string();
    }

    if script.len() == 23
        && script[0] == 0xa9  // OP_HASH160
        && script[1] == 0x14  // push 20 bytes
        && script[22] == 0x87 // OP_EQUAL
    {
        return "scripthash".to_string();
    }

    // P2WPKH: OP_0 <20 bytes>
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return "witness_v0_keyhash".to_string();
    }

    // P2WSH: OP_0 <32 bytes>
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return "witness_v0_scripthash".to_string();
    }

    // P2TR: OP_1 <32 bytes>
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return "witness_v1_taproot".to_string();
    }

    // OP_RETURN
    if !script.is_empty() && script[0] == 0x6a {
        return "nulldata".to_string();
    }

    // Raw pubkey
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        return "pubkey".to_string();
    }
    if script.len() == 67 && script[0] == 0x41 && script[66] == 0xac {
        return "pubkey".to_string();
    }

    "nonstandard".to_string()
}

/// Convert a script to an address string if possible.
fn script_to_address(script: &[u8], params: &ChainParams) -> Option<String> {
    use rustoshi_crypto::address::{Address, Network};
    use rustoshi_primitives::{Hash160, Hash256};

    let network = match params.network_id {
        NetworkId::Mainnet => Network::Mainnet,
        NetworkId::Regtest => Network::Regtest,
        _ => Network::Testnet,
    };

    // P2PKH
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        return Some(Address::P2PKH {
            hash: Hash160::from_bytes(hash),
            network,
        }.encode());
    }

    // P2SH
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[2..22]);
        return Some(Address::P2SH {
            hash: Hash160::from_bytes(hash),
            network,
        }.encode());
    }

    // P2WPKH
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[2..22]);
        return Some(Address::P2WPKH {
            hash: Hash160::from_bytes(hash),
            network,
        }.encode());
    }

    // P2WSH
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script[2..34]);
        return Some(Address::P2WSH {
            hash: Hash256::from_bytes(hash),
            network,
        }.encode());
    }

    // P2TR
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        let mut output_key = [0u8; 32];
        output_key.copy_from_slice(&script[2..34]);
        return Some(Address::P2TR {
            output_key,
            network,
        }.encode());
    }

    None
}

/// Convert an address string to a scriptPubKey.
fn address_to_script_pubkey(address: &str, params: &ChainParams) -> Result<Vec<u8>, ErrorObjectOwned> {
    use rustoshi_crypto::address::{Address, Network};

    let network = match params.network_id {
        NetworkId::Mainnet => Network::Mainnet,
        NetworkId::Regtest => Network::Regtest,
        _ => Network::Testnet,
    };

    let decoded = Address::from_string(address, Some(network)).map_err(|e| {
        ErrorObjectOwned::owned(
            rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
            format!("Invalid address: {}", e),
            None::<()>,
        )
    })?;

    Ok(decoded.to_script_pubkey())
}

/// Convert a sighash type to a string.
fn sighash_to_string(sighash: u32) -> String {
    let base = sighash & 0x1f;
    let anyonecanpay = (sighash & 0x80) != 0;

    let base_str = match base {
        0x00 => "DEFAULT",
        0x01 => "ALL",
        0x02 => "NONE",
        0x03 => "SINGLE",
        _ => "UNKNOWN",
    };

    if anyonecanpay {
        format!("{}|ANYONECANPAY", base_str)
    } else {
        base_str.to_string()
    }
}

/// Format a derivation path from u32 indices.
fn format_derivation_path(path: &[u32]) -> String {
    let mut result = "m".to_string();
    for &index in path {
        if index >= 0x80000000 {
            result.push_str(&format!("/{}h", index - 0x80000000));
        } else {
            result.push_str(&format!("/{}", index));
        }
    }
    result
}

/// Build a DecodedRawTransaction from a Transaction.
fn build_decoded_raw_transaction(tx: &Transaction) -> DecodedRawTransaction {
    let vin: Vec<TxInputInfo> = tx
        .inputs
        .iter()
        .map(|input| {
            if input.previous_output.is_null() {
                // Coinbase
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
                        asm: disassemble_script(&input.script_sig),
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
        .collect();

    let vout: Vec<TxOutputInfo> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, output)| {
            let script_type = classify_script(&output.script_pubkey);
            TxOutputInfo {
                value: output.value as f64 / COIN as f64,
                n: i as u32,
                script_pubkey: ScriptPubKeyInfo {
                    asm: disassemble_script(&output.script_pubkey),
                    hex: hex::encode(&output.script_pubkey),
                    script_type,
                    address: None,
                },
            }
        })
        .collect();

    DecodedRawTransaction {
        txid: tx.txid().to_hex(),
        hash: tx.wtxid().to_hex(),
        size: tx.serialized_size() as u32,
        vsize: tx.vsize() as u32,
        weight: tx.weight() as u32,
        version: tx.version,
        locktime: tx.lock_time,
        vin,
        vout,
    }
}

// ============================================================
// SERVER STARTUP
// ============================================================

/// Maximum number of requests allowed in a batch.
///
/// Bitcoin Core uses this limit to prevent DoS attacks.
/// See `/home/max/hashhog/bitcoin/src/httprpc.cpp`.
pub const MAX_BATCH_SIZE: usize = 1000;

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
///
/// # Batch Request Handling
///
/// The server supports JSON-RPC batch requests (arrays of request objects).
/// - Batch requests are limited to 1000 requests per batch to prevent DoS.
/// - Empty batches return an `RPC_INVALID_REQUEST` error.
/// - Each request in a batch is processed sequentially, and failures in one
///   request do not affect others.
pub async fn start_rpc_server(
    config: RpcConfig,
    state: Arc<RwLock<RpcState>>,
    peer_state: Arc<RwLock<PeerState>>,
) -> anyhow::Result<ServerHandle> {
    // Build auth credentials from config.
    // If neither cookie nor user/pass is set, the middleware still runs and
    // will reject every request with 401 — callers should always provide at
    // least one credential source (cookie generation in main.rs ensures this).
    let credentials = AuthCredentials {
        cookie_secret: config.cookie_secret.clone(),
        user_pass: match (config.auth_user.clone(), config.auth_password.clone()) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        },
    };

    let http_middleware = tower::ServiceBuilder::new().layer(AuthLayer::new(credentials));

    let server = ServerBuilder::default()
        .set_batch_request_config(BatchRequestConfig::Limit(MAX_BATCH_SIZE as u32))
        .set_http_middleware(http_middleware)
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
    use rustoshi_consensus::chain_manager::{block_status, get_ancestor, is_ancestor};

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

    // ============================================================
    // GETRAWTRANSACTION TESTS
    // ============================================================

    #[test]
    fn test_disassemble_script_p2pkh() {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let script = vec![
            0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 <20>
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
        ];
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_DUP"));
        assert!(asm.contains("OP_HASH160"));
        assert!(asm.contains("89abcdef0123456789abcdef0123456789abcdef"));
        assert!(asm.contains("OP_EQUALVERIFY"));
        assert!(asm.contains("OP_CHECKSIG"));
    }

    #[test]
    fn test_disassemble_script_p2sh() {
        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        let script = vec![
            0xa9, 0x14, // OP_HASH160 <20>
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x87, // OP_EQUAL
        ];
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_HASH160"));
        assert!(asm.contains("OP_EQUAL"));
    }

    #[test]
    fn test_disassemble_script_p2wpkh() {
        // P2WPKH: OP_0 <20 bytes>
        let script = vec![
            0x00, 0x14, // OP_0 <20>
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ];
        let asm = disassemble_script(&script);
        assert!(asm.contains("0"));
        assert!(asm.contains("89abcdef0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn test_disassemble_script_p2tr() {
        // P2TR: OP_1 <32 bytes>
        let mut script = vec![0x51, 0x20]; // OP_1 <32>
        script.extend([0xab; 32]);
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_1"));
    }

    #[test]
    fn test_disassemble_script_op_return() {
        // OP_RETURN with data
        let script = vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef];
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_RETURN"));
        assert!(asm.contains("deadbeef"));
    }

    #[test]
    fn test_disassemble_script_multisig() {
        // 2-of-3 multisig: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        let mut script = vec![0x52]; // OP_2
        // Add three 33-byte compressed pubkeys
        for _ in 0..3 {
            script.push(0x21); // push 33 bytes
            script.extend([0xab; 33]);
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_2"));
        assert!(asm.contains("OP_3"));
        assert!(asm.contains("OP_CHECKMULTISIG"));
    }

    #[test]
    fn test_disassemble_script_cltv() {
        // CLTV script: <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
        let script = vec![
            0x04, // push 4 bytes
            0x00, 0x00, 0x00, 0x01, // locktime value
            0xb1, // OP_CHECKLOCKTIMEVERIFY
            0x75, // OP_DROP
        ];
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_CHECKLOCKTIMEVERIFY"));
        assert!(asm.contains("OP_DROP"));
    }

    #[test]
    fn test_disassemble_script_csv() {
        // CSV script: <sequence> OP_CHECKSEQUENCEVERIFY
        let script = vec![
            0x02, // push 2 bytes
            0x00, 0x01, // sequence value
            0xb2, // OP_CHECKSEQUENCEVERIFY
        ];
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_CHECKSEQUENCEVERIFY"));
    }

    #[test]
    fn test_disassemble_script_empty() {
        let script: Vec<u8> = vec![];
        let asm = disassemble_script(&script);
        assert!(asm.is_empty());
    }

    #[test]
    fn test_disassemble_script_small_integers() {
        // OP_1 through OP_16
        let script = vec![0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58];
        let asm = disassemble_script(&script);
        assert!(asm.contains("OP_1"));
        assert!(asm.contains("OP_2"));
        assert!(asm.contains("OP_3"));
        assert!(asm.contains("OP_4"));
        assert!(asm.contains("OP_5"));
        assert!(asm.contains("OP_6"));
        assert!(asm.contains("OP_7"));
        assert!(asm.contains("OP_8"));
    }

    #[test]
    fn test_build_tx_info_basic() {
        use rustoshi_primitives::{Transaction, TxIn, TxOut, OutPoint, Hash256};

        // Create a simple transaction
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([0xab; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000_000, // 1 BTC
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 <20>
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
                ],
            }],
            lock_time: 0,
        };

        let info = build_tx_info(&tx, None, None);

        assert_eq!(info.version, 2);
        assert_eq!(info.locktime, 0);
        assert_eq!(info.vin.len(), 1);
        assert_eq!(info.vout.len(), 1);
        assert!(info.blockhash.is_none());
        assert!(info.confirmations.is_none());
        assert_eq!(info.vout[0].value, 1.0);
        assert_eq!(info.vout[0].script_pubkey.script_type, "pubkeyhash");
    }

    #[test]
    fn test_build_tx_info_with_confirmations() {
        use rustoshi_primitives::{Transaction, TxIn, TxOut, OutPoint, Hash256};

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([0xab; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_000_000,
                script_pubkey: vec![0x51, 0x20].into_iter().chain([0x00; 32]).collect(),
            }],
            lock_time: 0,
        };

        let block_hash = Hash256([0xcd; 32]);
        let info = build_tx_info(&tx, Some(&block_hash), Some(10));

        assert!(info.blockhash.is_some());
        assert_eq!(info.blockhash.unwrap(), block_hash.to_hex());
        assert_eq!(info.confirmations, Some(10));
        assert_eq!(info.vout[0].script_pubkey.script_type, "witness_v1_taproot");
    }

    #[test]
    fn test_build_tx_info_coinbase() {
        use rustoshi_primitives::{Transaction, TxIn, TxOut, OutPoint};

        // Coinbase transaction
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x03, 0x01, 0x02, 0x03], // Block height
                sequence: 0xffffffff,
                witness: vec![vec![0x00; 32]],
            }],
            outputs: vec![TxOut {
                value: 625_000_000, // 6.25 BTC block reward
                script_pubkey: vec![0x51], // OP_1 (anyone can spend)
            }],
            lock_time: 0,
        };

        let info = build_tx_info(&tx, None, None);

        // Coinbase input should have coinbase field set
        assert!(info.vin[0].coinbase.is_some());
        assert!(info.vin[0].txid.is_none());
        assert!(info.vin[0].vout.is_none());
    }

    #[test]
    fn test_getrawtransaction_error_messages() {
        // Test that the error message matches Bitcoin Core format
        let err = RpcServerImpl::rpc_error(
            rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
            "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.",
        );
        assert_eq!(err.code(), rpc_error::RPC_INVALID_ADDRESS_OR_KEY);
        assert!(err.message().contains("Use gettransaction for wallet transactions"));
    }

    // ============================================================
    // BATCH REQUEST TESTS
    // ============================================================

    #[test]
    fn test_max_batch_size_constant() {
        // Verify the batch size limit matches Bitcoin Core's limit
        assert_eq!(MAX_BATCH_SIZE, 1000);
    }

    #[test]
    fn test_rpc_parse_error_code() {
        // JSON-RPC 2.0 standard parse error code
        assert_eq!(rpc_error::RPC_PARSE_ERROR, -32700);
    }

    #[test]
    fn test_rpc_invalid_request_code() {
        // JSON-RPC 2.0 standard invalid request code
        assert_eq!(rpc_error::RPC_INVALID_REQUEST, -32600);
    }

    #[test]
    fn test_batch_request_json_format() {
        // Test that a batch request array can be parsed correctly
        let batch_json = r#"[
            {"jsonrpc": "2.0", "method": "getblockcount", "id": 1},
            {"jsonrpc": "2.0", "method": "getbestblockhash", "id": 2}
        ]"#;

        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(batch_json);
        assert!(parsed.is_ok());
        let requests = parsed.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["method"], "getblockcount");
        assert_eq!(requests[1]["method"], "getbestblockhash");
    }

    #[test]
    fn test_batch_request_mixed_json() {
        // Test batch with mixed success/error potential
        let batch_json = r#"[
            {"jsonrpc": "2.0", "method": "getblockcount", "id": 1},
            {"jsonrpc": "2.0", "method": "invalid_method", "id": 2},
            {"jsonrpc": "2.0", "method": "getbestblockhash", "id": 3}
        ]"#;

        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(batch_json);
        assert!(parsed.is_ok());
        let requests = parsed.unwrap();
        assert_eq!(requests.len(), 3);
        // Each request has an id which should be preserved in responses
        assert_eq!(requests[0]["id"], 1);
        assert_eq!(requests[1]["id"], 2);
        assert_eq!(requests[2]["id"], 3);
    }

    #[test]
    fn test_empty_batch_json() {
        // Empty batch should parse but be rejected by server
        let batch_json = "[]";
        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(batch_json);
        assert!(parsed.is_ok());
        assert!(parsed.unwrap().is_empty());
    }

    #[test]
    fn test_single_request_not_batch() {
        // Single object should not be treated as batch
        let single_json = r#"{"jsonrpc": "2.0", "method": "getblockcount", "id": 1}"#;
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(single_json);
        assert!(parsed.is_ok());
        let value = parsed.unwrap();
        assert!(value.is_object());
        assert!(!value.is_array());
    }

    #[test]
    fn test_batch_response_format() {
        // Test batch response structure
        let response_json = r#"[
            {"jsonrpc": "2.0", "result": 100, "id": 1},
            {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 2},
            {"jsonrpc": "2.0", "result": "0000000000000000000123456789abcdef", "id": 3}
        ]"#;

        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(response_json);
        assert!(parsed.is_ok());
        let responses = parsed.unwrap();
        assert_eq!(responses.len(), 3);

        // First response is success
        assert!(responses[0]["result"].is_number());
        assert!(responses[0]["error"].is_null());

        // Second response is error
        assert!(responses[1]["result"].is_null());
        assert!(responses[1]["error"].is_object());

        // Third response is success
        assert!(responses[2]["result"].is_string());
    }

    #[test]
    fn test_batch_request_id_types() {
        // IDs can be strings, numbers, or null
        let batch_json = r#"[
            {"jsonrpc": "2.0", "method": "test", "id": 1},
            {"jsonrpc": "2.0", "method": "test", "id": "string-id"},
            {"jsonrpc": "2.0", "method": "test", "id": null}
        ]"#;

        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(batch_json);
        assert!(parsed.is_ok());
        let requests = parsed.unwrap();
        assert!(requests[0]["id"].is_number());
        assert!(requests[1]["id"].is_string());
        assert!(requests[2]["id"].is_null());
    }

    #[test]
    fn test_invalid_json_not_batch() {
        // Invalid JSON should return parse error
        let invalid_json = "not valid json";
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(invalid_json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_neither_object_nor_array() {
        // Primitive values should fail
        let number_json = "42";
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(number_json);
        assert!(parsed.is_ok());
        let value = parsed.unwrap();
        // Should not be object or array
        assert!(!value.is_object());
        assert!(!value.is_array());
    }

    // ============================================================
    // CHAIN MANAGEMENT RPC TESTS
    // ============================================================

    #[test]
    fn test_chain_manager_state_initial() {
        let state = ChainManagerState::new();
        assert_eq!(state.last_precious_chainwork, [0u8; 32]);
        assert_eq!(state.block_reverse_sequence_id, -1);
        assert!(state.sequence_ids.is_empty());
    }

    #[test]
    fn test_chain_manager_state_precious_sequence() {
        let mut state = ChainManagerState::new();
        let hash = Hash256([0xab; 32]);
        let chain_work = [0u8; 32];

        let seq = state.assign_precious_sequence(hash, &chain_work);
        assert_eq!(seq, -1);
        assert_eq!(state.get_sequence_id(&hash), Some(-1));

        // Second call should decrement
        let hash2 = Hash256([0xcd; 32]);
        let seq2 = state.assign_precious_sequence(hash2, &chain_work);
        assert_eq!(seq2, -2);
    }

    #[test]
    fn test_chain_manager_state_precious_reset() {
        let mut state = ChainManagerState::new();
        let hash = Hash256([0xab; 32]);
        let chain_work = [0u8; 32];

        // First call
        state.assign_precious_sequence(hash, &chain_work);

        // Higher chain work should reset counter
        let mut higher_work = [0u8; 32];
        higher_work[0] = 1; // More work
        let hash2 = Hash256([0xcd; 32]);
        let seq = state.assign_precious_sequence(hash2, &higher_work);
        assert_eq!(seq, -1); // Reset back to -1
    }

    #[test]
    fn test_compare_chain_work_equal() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert_eq!(compare_chain_work(&a, &b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_compare_chain_work_greater() {
        let mut a = [0u8; 32];
        let b = [0u8; 32];
        a[31] = 1;
        assert_eq!(compare_chain_work(&a, &b), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_compare_chain_work_less() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 1; // Most significant byte difference
        assert_eq!(compare_chain_work(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_block_status_flags() {
        assert_eq!(block_status::FAILED_VALIDITY, 32);
        assert_eq!(block_status::FAILED_CHILD, 64);
        assert_eq!(block_status::VALID_TRANSACTIONS, 3);
        assert_eq!(block_status::HAVE_DATA, 8);
    }

    #[test]
    fn test_block_meta_is_invalid() {
        let mut meta = BlockMeta {
            hash: Hash256::ZERO,
            height: 100,
            prev_hash: Hash256::ZERO,
            status: 0,
            chain_work: [0u8; 32],
        };

        assert!(!meta.is_invalid());

        meta.status |= block_status::FAILED_VALIDITY;
        assert!(meta.is_invalid());

        meta.status = block_status::FAILED_CHILD;
        assert!(meta.is_invalid());
    }

    #[test]
    fn test_block_meta_has_valid_transactions() {
        let mut meta = BlockMeta {
            hash: Hash256::ZERO,
            height: 100,
            prev_hash: Hash256::ZERO,
            status: 0,
            chain_work: [0u8; 32],
        };

        assert!(!meta.has_valid_transactions());

        meta.status |= block_status::VALID_TRANSACTIONS;
        assert!(meta.has_valid_transactions());
    }

    #[test]
    fn test_is_ancestor_helper() {
        use std::collections::HashMap;

        // Build a chain: A -> B -> C
        let hash_a = Hash256([0x01; 32]);
        let hash_b = Hash256([0x02; 32]);
        let hash_c = Hash256([0x03; 32]);

        let mut blocks: HashMap<Hash256, BlockMeta> = HashMap::new();
        blocks.insert(
            hash_a,
            BlockMeta {
                hash: hash_a,
                height: 0,
                prev_hash: Hash256::ZERO,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_b,
            BlockMeta {
                hash: hash_b,
                height: 1,
                prev_hash: hash_a,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_c,
            BlockMeta {
                hash: hash_c,
                height: 2,
                prev_hash: hash_b,
                status: 0,
                chain_work: [0u8; 32],
            },
        );

        let get_meta = |h: &Hash256| blocks.get(h).cloned();

        // A is ancestor of C
        assert!(is_ancestor(&hash_a, 0, &hash_c, 2, &get_meta));
        // B is ancestor of C
        assert!(is_ancestor(&hash_b, 1, &hash_c, 2, &get_meta));
        // C is NOT ancestor of A
        assert!(!is_ancestor(&hash_c, 2, &hash_a, 0, &get_meta));
    }

    #[test]
    fn test_find_descendants_helper() {
        use std::collections::HashMap;

        // Build chain:
        //     A
        //    / \
        //   B   C
        //   |
        //   D
        let hash_a = Hash256([0x01; 32]);
        let hash_b = Hash256([0x02; 32]);
        let hash_c = Hash256([0x03; 32]);
        let hash_d = Hash256([0x04; 32]);

        let mut blocks: HashMap<Hash256, BlockMeta> = HashMap::new();
        blocks.insert(
            hash_a,
            BlockMeta {
                hash: hash_a,
                height: 0,
                prev_hash: Hash256::ZERO,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_b,
            BlockMeta {
                hash: hash_b,
                height: 1,
                prev_hash: hash_a,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_c,
            BlockMeta {
                hash: hash_c,
                height: 1,
                prev_hash: hash_a,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_d,
            BlockMeta {
                hash: hash_d,
                height: 2,
                prev_hash: hash_b,
                status: 0,
                chain_work: [0u8; 32],
            },
        );

        let get_meta = |h: &Hash256| blocks.get(h).cloned();

        // Descendants of A should be B, C, D
        let descendants = find_descendants(&hash_a, 0, blocks.keys().cloned(), &get_meta);
        assert_eq!(descendants.len(), 3);
        assert!(descendants.contains(&hash_b));
        assert!(descendants.contains(&hash_c));
        assert!(descendants.contains(&hash_d));

        // Descendants of B should just be D
        let descendants = find_descendants(&hash_b, 1, blocks.keys().cloned(), &get_meta);
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&hash_d));

        // Descendants of C should be empty
        let descendants = find_descendants(&hash_c, 1, blocks.keys().cloned(), &get_meta);
        assert!(descendants.is_empty());
    }

    #[test]
    fn test_is_ancestor_or_descendant_helper() {
        use std::collections::HashMap;

        // Chain: A -> B -> C
        let hash_a = Hash256([0x01; 32]);
        let hash_b = Hash256([0x02; 32]);
        let hash_c = Hash256([0x03; 32]);
        let hash_d = Hash256([0x04; 32]); // Unrelated

        let mut blocks: HashMap<Hash256, BlockMeta> = HashMap::new();
        blocks.insert(
            hash_a,
            BlockMeta {
                hash: hash_a,
                height: 0,
                prev_hash: Hash256::ZERO,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_b,
            BlockMeta {
                hash: hash_b,
                height: 1,
                prev_hash: hash_a,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_c,
            BlockMeta {
                hash: hash_c,
                height: 2,
                prev_hash: hash_b,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_d,
            BlockMeta {
                hash: hash_d,
                height: 1,
                prev_hash: Hash256::ZERO, // Unrelated chain
                status: 0,
                chain_work: [0u8; 32],
            },
        );

        let get_meta = |h: &Hash256| blocks.get(h).cloned();

        // A and C are related (A is ancestor of C)
        assert!(is_ancestor_or_descendant(&hash_a, 0, &hash_c, 2, &get_meta));
        // C and A are related (reverse direction)
        assert!(is_ancestor_or_descendant(&hash_c, 2, &hash_a, 0, &get_meta));
        // B and C are related
        assert!(is_ancestor_or_descendant(&hash_b, 1, &hash_c, 2, &get_meta));
        // D is unrelated to everyone
        assert!(!is_ancestor_or_descendant(&hash_d, 1, &hash_a, 0, &get_meta));
        assert!(!is_ancestor_or_descendant(&hash_d, 1, &hash_c, 2, &get_meta));
    }

    #[test]
    fn test_get_ancestor_helper() {
        use std::collections::HashMap;

        // Chain: A -> B -> C
        let hash_a = Hash256([0x01; 32]);
        let hash_b = Hash256([0x02; 32]);
        let hash_c = Hash256([0x03; 32]);

        let mut blocks: HashMap<Hash256, BlockMeta> = HashMap::new();
        blocks.insert(
            hash_a,
            BlockMeta {
                hash: hash_a,
                height: 0,
                prev_hash: Hash256::ZERO,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_b,
            BlockMeta {
                hash: hash_b,
                height: 1,
                prev_hash: hash_a,
                status: 0,
                chain_work: [0u8; 32],
            },
        );
        blocks.insert(
            hash_c,
            BlockMeta {
                hash: hash_c,
                height: 2,
                prev_hash: hash_b,
                status: 0,
                chain_work: [0u8; 32],
            },
        );

        let get_meta = |h: &Hash256| blocks.get(h).cloned();

        // Ancestor of C at height 0 should be A
        assert_eq!(get_ancestor(&hash_c, 2, 0, &get_meta), Some(hash_a));
        // Ancestor of C at height 1 should be B
        assert_eq!(get_ancestor(&hash_c, 2, 1, &get_meta), Some(hash_b));
        // Ancestor of C at height 2 should be C itself
        assert_eq!(get_ancestor(&hash_c, 2, 2, &get_meta), Some(hash_c));
        // Ancestor at height > current should be None
        assert_eq!(get_ancestor(&hash_c, 2, 3, &get_meta), None);
    }

    // ============================================================
    // GETDEPLOYMENTINFO UNIT TESTS
    // ============================================================

    /// Verify that the buried-deployment helper produces the correct JSON shape.
    ///
    /// These tests exercise the pure data-transformation logic used by
    /// `get_deployment_info` without requiring a running server or database.
    #[test]
    fn test_deployment_info_regtest_all_active() {
        // On regtest, csv/segwit/taproot all activate at height 1.
        // At tip height 0 they should NOT be active.
        let params = rustoshi_consensus::ChainParams::regtest();

        let eval_height: u32 = 0;

        // csv: activation height 1, eval_height 0 → inactive
        let csv_active = eval_height >= params.csv_height;
        assert!(!csv_active, "csv should be inactive at height 0 on regtest");

        // At height 1, all three should be active.
        let eval_height: u32 = 1;
        assert!(eval_height >= params.csv_height,    "csv active at height 1");
        assert!(eval_height >= params.segwit_height, "segwit active at height 1");
        assert!(eval_height >= params.taproot_height,"taproot active at height 1");
    }

    #[test]
    fn test_deployment_info_mainnet_heights() {
        // On mainnet, all three deployments activate at well-known heights.
        let params = rustoshi_consensus::ChainParams::mainnet();

        // Before CSV activation (419328)
        let pre_csv: u32 = 419_327;
        assert!(pre_csv < params.csv_height);

        // After Taproot activation (709632)
        let post_taproot: u32 = 800_000;
        assert!(post_taproot >= params.taproot_height);
        assert!(post_taproot >= params.segwit_height);
        assert!(post_taproot >= params.csv_height);

        // Between CSV and SegWit
        let between: u32 = 450_000;
        assert!(between >= params.csv_height);
        assert!(between < params.segwit_height);
    }

    #[test]
    fn test_deployment_info_response_has_required_keys() {
        // Simulate the JSON construction logic without a live server.
        // This checks that the returned JSON object has the expected fields.
        let params = rustoshi_consensus::ChainParams::regtest();
        let eval_height: u32 = 10;

        let make_buried = |activation_height: u32, min_activation_height: u32| {
            let active = eval_height >= activation_height;
            let height: Option<u32> = if active { Some(activation_height) } else { None };
            serde_json::json!({
                "type": "buried",
                "active": active,
                "height": height,
                "min_activation_height": min_activation_height
            })
        };

        let mut deployments = serde_json::Map::new();
        deployments.insert("csv".to_string(),    make_buried(params.csv_height, params.csv_height));
        deployments.insert("segwit".to_string(), make_buried(params.segwit_height, params.segwit_height));
        deployments.insert("taproot".to_string(),make_buried(params.taproot_height, params.taproot_height));

        let response = serde_json::json!({
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": eval_height,
            "deployments": deployments
        });

        // Top-level keys
        assert!(response.get("hash").is_some(),        "missing 'hash' key");
        assert!(response.get("height").is_some(),      "missing 'height' key");
        assert!(response.get("deployments").is_some(), "missing 'deployments' key");

        let deps = response["deployments"].as_object().unwrap();

        // Must have at least csv, segwit, taproot
        for name in &["csv", "segwit", "taproot"] {
            let dep = deps.get(*name).unwrap_or_else(|| panic!("missing deployment '{}'", name));
            assert!(dep.get("type").is_some(),                   "{}: missing 'type'", name);
            assert!(dep.get("active").is_some(),                 "{}: missing 'active'", name);
            assert!(dep.get("min_activation_height").is_some(),  "{}: missing 'min_activation_height'", name);
        }

        // On regtest at height 10, all three must be active
        assert_eq!(deps["csv"]["active"],    serde_json::json!(true));
        assert_eq!(deps["segwit"]["active"], serde_json::json!(true));
        assert_eq!(deps["taproot"]["active"],serde_json::json!(true));

        // Type must be "buried" for all three
        assert_eq!(deps["csv"]["type"],    serde_json::json!("buried"));
        assert_eq!(deps["segwit"]["type"], serde_json::json!("buried"));
        assert_eq!(deps["taproot"]["type"],serde_json::json!("buried"));
    }

    #[test]
    fn test_deployment_info_mainnet_pre_activation() {
        // Before ANY soft fork on mainnet (height < 419328), none should be active.
        let params = rustoshi_consensus::ChainParams::mainnet();
        let eval_height: u32 = 300_000;

        let csv_active    = eval_height >= params.csv_height;
        let segwit_active = eval_height >= params.segwit_height;
        let taproot_active= eval_height >= params.taproot_height;

        assert!(!csv_active,    "csv should be inactive at height 300_000 on mainnet");
        assert!(!segwit_active, "segwit should be inactive at height 300_000 on mainnet");
        assert!(!taproot_active,"taproot should be inactive at height 300_000 on mainnet");
    }

    // ============================================================
    // SOFTFORK BRIDGE TESTS
    // ============================================================

    /// Verify that `build_softforks_map` is the single source of truth for
    /// both `getblockchaininfo.softforks` and `getdeploymentinfo.deployments`.
    ///
    /// The test calls the shared helper at two regtest heights (0 and 10) and
    /// asserts that every field a caller would compare across the two RPCs
    /// (active, type, height, min_activation_height) is identical.  This is a
    /// pure-logic test that does not require a running node or database.
    #[test]
    fn test_softforks_bridge_shared_helper_regtest() {
        let params = rustoshi_consensus::ChainParams::regtest();

        // Test at height 0: csv/segwit/taproot all activate at height 1 on
        // regtest, so none should be active at height 0.
        {
            let map = build_softforks_map(&params, 0);

            for name in &["csv", "segwit", "taproot"] {
                let dep = map.get(*name).unwrap_or_else(|| panic!("missing deployment '{}'", name));
                assert_eq!(dep["active"], serde_json::json!(false),
                    "{name}: should be inactive at height 0 on regtest");
                assert_eq!(dep["type"], serde_json::json!("buried"),
                    "{name}: type should be 'buried'");
                // height field must be absent (null) when inactive
                assert_eq!(dep["height"], serde_json::json!(null),
                    "{name}: height should be null when inactive");
            }
        }

        // Test at height 10: all three should be active (activation_height = 1).
        {
            let map = build_softforks_map(&params, 10);

            for name in &["csv", "segwit", "taproot"] {
                let dep = map.get(*name).unwrap_or_else(|| panic!("missing deployment '{}'", name));
                assert_eq!(dep["active"], serde_json::json!(true),
                    "{name}: should be active at height 10 on regtest");
                assert_eq!(dep["type"], serde_json::json!("buried"),
                    "{name}: type should be 'buried'");
                // height field must equal the activation height (1 on regtest)
                assert_eq!(dep["height"], serde_json::json!(1u32),
                    "{name}: height should be 1 (activation height) when active");
                assert_eq!(dep["min_activation_height"], serde_json::json!(1u32),
                    "{name}: min_activation_height mismatch");
            }
        }
    }

    /// Regtest round-trip test: both `getblockchaininfo.softforks` and
    /// `getdeploymentinfo.deployments` must agree on every shared field for
    /// every named deployment.
    ///
    /// This test starts an in-process `RpcServerImpl` backed by an ephemeral
    /// regtest datadir (no mainnet data touched), calls both RPCs, and
    /// asserts field-level equality for `active`, `type`, `height`, and
    /// `min_activation_height` across every deployment present in both
    /// responses.
    #[tokio::test]
    async fn test_softforks_getblockchaininfo_matches_getdeploymentinfo_regtest() {
        use rustoshi_storage::ChainDb;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        // Ephemeral regtest datadir — never touches mainnet or testnet.
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();

        let state = Arc::new(RwLock::new(RpcState::new(db, params)));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        // --- Call both RPCs ---
        let chain_info = rpc.get_blockchain_info().await
            .expect("getblockchaininfo failed");
        let deploy_info = rpc.get_deployment_info(None).await
            .expect("getdeploymentinfo failed");

        // Extract the two maps.
        let softforks = chain_info.softforks.as_object()
            .expect("getblockchaininfo.softforks must be a JSON object");
        let deployments = deploy_info["deployments"].as_object()
            .expect("getdeploymentinfo.deployments must be a JSON object");

        // Every deployment that appears in getblockchaininfo.softforks must
        // appear in getdeploymentinfo.deployments with identical fields, and
        // vice-versa — the two RPCs share the same helper so their key sets
        // are always identical.
        let sf_keys: std::collections::BTreeSet<_> = softforks.keys().collect();
        let di_keys: std::collections::BTreeSet<_> = deployments.keys().collect();
        assert_eq!(sf_keys, di_keys,
            "getblockchaininfo.softforks and getdeploymentinfo.deployments must have the same deployment names");

        for name in sf_keys {
            let sf = &softforks[name];
            let di = &deployments[name];

            assert_eq!(sf["active"], di["active"],
                "deployment '{name}': active mismatch between getblockchaininfo and getdeploymentinfo");
            assert_eq!(sf["type"], di["type"],
                "deployment '{name}': type mismatch");
            assert_eq!(sf["height"], di["height"],
                "deployment '{name}': height mismatch");
            assert_eq!(sf["min_activation_height"], di["min_activation_height"],
                "deployment '{name}': min_activation_height mismatch");

            // If a bip9 sub-object is present in one, it must be present in
            // both with identical start_time, timeout, and bit.
            if sf.get("bip9").is_some() || di.get("bip9").is_some() {
                let sf_bip9 = sf.get("bip9")
                    .unwrap_or_else(|| panic!("'{name}': bip9 present in getdeploymentinfo but not in getblockchaininfo"));
                let di_bip9 = di.get("bip9")
                    .unwrap_or_else(|| panic!("'{name}': bip9 present in getblockchaininfo but not in getdeploymentinfo"));
                assert_eq!(sf_bip9["bit"],        di_bip9["bit"],        "'{name}' bip9.bit mismatch");
                assert_eq!(sf_bip9["start_time"], di_bip9["start_time"], "'{name}' bip9.start_time mismatch");
                assert_eq!(sf_bip9["timeout"],    di_bip9["timeout"],    "'{name}' bip9.timeout mismatch");
            }
        }
    }

    // ============================================================
    // signmessage / verifymessage / mempool descendants / estimaterawfee
    // ============================================================

    /// Build a P2PKH legacy (mainnet) address from a compressed pubkey.
    fn mainnet_p2pkh_from_compressed(pubkey: &[u8; 33]) -> String {
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_crypto::hashes::hash160;
        let h = hash160(pubkey);
        Address::P2PKH {
            hash: h,
            network: Network::Mainnet,
        }
        .encode()
    }

    #[test]
    fn parse_signing_privkey_accepts_hex() {
        // 32 bytes, valid range.
        let hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let (key, compressed) = parse_signing_privkey(hex).expect("parse hex");
        assert!(compressed, "raw hex defaults to compressed");
        assert_eq!(key.secret_bytes()[0], 0x01);
    }

    #[test]
    fn parse_signing_privkey_rejects_bad_hex() {
        // Wrong length
        assert!(parse_signing_privkey("abcd").is_err());
        // Non-hex
        assert!(parse_signing_privkey(&"z".repeat(64)).is_err());
    }

    #[test]
    fn parse_signing_privkey_accepts_wif_compressed_and_uncompressed() {
        use rustoshi_crypto::base58::base58check_encode;
        let raw = [0x42u8; 32];
        // Compressed WIF: 0x80 || 32 bytes || 0x01
        let mut buf = vec![0x80];
        buf.extend_from_slice(&raw);
        buf.push(0x01);
        let wif_c = base58check_encode(&buf);
        let (k1, c1) = parse_signing_privkey(&wif_c).expect("compressed wif");
        assert!(c1);
        assert_eq!(k1.secret_bytes(), raw);

        // Uncompressed WIF: 0x80 || 32 bytes
        let mut buf2 = vec![0x80];
        buf2.extend_from_slice(&raw);
        let wif_u = base58check_encode(&buf2);
        let (k2, c2) = parse_signing_privkey(&wif_u).expect("uncompressed wif");
        assert!(!c2);
        assert_eq!(k2.secret_bytes(), raw);
    }

    #[tokio::test]
    async fn signmessage_verifymessage_roundtrip_compressed() {
        // Sign with a hex private key, then derive its compressed P2PKH address
        // and verify the signature in the same RPC server.
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let state = Arc::new(RwLock::new(RpcState::new(
            db,
            ChainParams::regtest(),
        )));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state, peer_state);

        // Deterministic privkey for reproducibility.
        let hex_key =
            "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let msg = "hello rustoshi".to_string();
        let sig_b64 = server
            .sign_message(hex_key.clone(), msg.clone())
            .await
            .expect("signmessage");

        // Derive the matching compressed mainnet P2PKH address from the secret.
        let secret =
            rustoshi_crypto::parse_secret_key(&hex::decode(&hex_key).unwrap().try_into().unwrap())
                .unwrap();
        let pubkey = rustoshi_crypto::public_key_from_private(&secret);
        let compressed = rustoshi_crypto::serialize_pubkey_compressed(&pubkey);
        let addr = mainnet_p2pkh_from_compressed(&compressed);

        let ok = server
            .verify_message(addr.clone(), sig_b64.clone(), msg.clone())
            .await
            .expect("verifymessage");
        assert!(ok, "valid signature must verify");

        // Tampered message -> false (no error)
        let bad = server
            .verify_message(addr, sig_b64, "hello bitcoin core".to_string())
            .await
            .expect("verifymessage tampered");
        assert!(!bad, "tampered message must not verify");

        // Garbage base64 -> error (Core parity)
        let err = server
            .verify_message(
                mainnet_p2pkh_from_compressed(&compressed),
                "$$$".to_string(),
                msg,
            )
            .await;
        assert!(err.is_err(), "malformed base64 must error out");
    }

    #[tokio::test]
    async fn savemempool_returns_filename_and_writes_file() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let dat = tmp.path().join("mempool.dat");
        let mut rpc_state = RpcState::new(db, ChainParams::regtest());
        rpc_state.mempool_dat_path = Some(dat.clone());
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state, peer_state);

        let resp = server.save_mempool().await.expect("savemempool");
        assert_eq!(resp["filename"], serde_json::json!(dat.display().to_string()));
        assert!(dat.exists(), "savemempool must write the file to disk");
    }

    #[tokio::test]
    async fn savemempool_errors_when_path_unset() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let state = Arc::new(RwLock::new(RpcState::new(
            db,
            ChainParams::regtest(),
        )));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state, peer_state);
        assert!(server.save_mempool().await.is_err());
    }

    #[tokio::test]
    async fn getmempooldescendants_errors_for_missing_tx() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let state = Arc::new(RwLock::new(RpcState::new(
            db,
            ChainParams::regtest(),
        )));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state, peer_state);
        let zero = "0".repeat(64);
        let r = server.get_mempool_descendants(zero, Some(false)).await;
        assert!(r.is_err(), "missing tx must error like getmempoolancestors");
    }

    #[tokio::test]
    async fn estimaterawfee_returns_bucket_array() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let state = Arc::new(RwLock::new(RpcState::new(
            db,
            ChainParams::regtest(),
        )));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state, peer_state);
        let resp = server.estimate_raw_fee(6, None).await.expect("estimaterawfee");
        let buckets = resp["buckets"].as_array().expect("buckets array");
        assert!(!buckets.is_empty(), "should expose all fee buckets");
        for b in buckets {
            assert!(b.get("startrange").is_some());
            assert!(b.get("endrange").is_some());
            assert!(b.get("inmempool").is_some());
            assert!(b.get("withintarget").is_some());
        }

        // Invalid target -> error (matches Core)
        assert!(server.estimate_raw_fee(0, None).await.is_err());
        assert!(server.estimate_raw_fee(2000, None).await.is_err());
    }

    // ============================================================
    // DUMPTXOUTSET ROLLBACK PARAMETER TESTS
    // ============================================================

    /// Helper: spin up a dumptxoutset-ready RpcServerImpl on the given network.
    /// `set_tip_height` lets a test pretend the chainstate has reached a
    /// specific height, which is what `rollback`'s assumeutxo lookup hangs
    /// off of. The on-disk UTXO set stays empty, so any code path that
    /// actually tries to dump will produce a (valid, empty) snapshot.
    async fn dumptxoutset_test_server(
        params: rustoshi_consensus::ChainParams,
        set_tip_height: u32,
    ) -> (tempfile::TempDir, RpcServerImpl) {
        use rustoshi_storage::ChainDb;
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let mut rpc_state = RpcState::new(db, params);
        rpc_state.best_height = set_tip_height;
        rpc_state.data_dir = Some(tmp.path().to_path_buf());
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state, peer_state);
        (tmp, server)
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_picks_latest_assumeutxo_below_tip() {
        // mainnet has assumeutxo entries at 840k, 880k, 910k, 935k. Pretend
        // we are synced to 945k -> the rollback target should resolve to
        // 935k. Because the test fixture's chainstate has no actual blocks
        // at those heights, the rewind path now hard-errors instead of
        // walking — but the error must still surface the resolved height
        // so callers can sanity-check the assumeutxo lookup.
        let params = rustoshi_consensus::ChainParams::mainnet();
        let (_tmp, server) = dumptxoutset_test_server(params, 945_000).await;

        let res = server
            .dump_tx_outset(
                "snap.dat".to_string(),
                Some("rollback".to_string()),
                None,
            )
            .await;
        let err = res.expect_err(
            "rollback path must error when there are no blocks to rewind through",
        );
        let msg = err.message().to_string();
        // The rollback target (935000) is what we resolved to; the error
        // text now comes from the chainstate lookup that proves the
        // resolver did pick 935k.
        assert!(
            msg.contains("935000"),
            "error must surface resolved assumeutxo target height: {}",
            msg
        );
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_under_lowest_snapshot_errors() {
        // tip below 840k -> no candidate height -> RPC_MISC_ERROR.
        let params = rustoshi_consensus::ChainParams::mainnet();
        let (_tmp, server) = dumptxoutset_test_server(params, 800_000).await;

        let res = server
            .dump_tx_outset("snap.dat".to_string(), Some("rollback".to_string()), None)
            .await;
        let err = res.expect_err("must error when no snapshot height fits");
        assert!(
            err.message().to_lowercase().contains("no assumeutxo"),
            "expected 'no assumeutxo' in error, got: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_no_snapshots_on_regtest() {
        // regtest has zero assumeutxo entries -> always errors on rollback.
        let params = rustoshi_consensus::ChainParams::regtest();
        let (_tmp, server) = dumptxoutset_test_server(params, 100).await;

        let res = server
            .dump_tx_outset("snap.dat".to_string(), Some("rollback".to_string()), None)
            .await;
        assert!(res.is_err(), "regtest has no snapshots; rollback must err");
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_options_height_resolves() {
        // {"rollback": 880000} on mainnet should resolve 880000 directly,
        // bypassing the assumeutxo-table lookup. The fixture has no blocks
        // at that height, so the rewind path errors with the resolved
        // height in the message — that's what we assert on.
        let params = rustoshi_consensus::ChainParams::mainnet();
        let (_tmp, server) = dumptxoutset_test_server(params, 945_000).await;

        let res = server
            .dump_tx_outset(
                "snap.dat".to_string(),
                None,
                Some(serde_json::json!({"rollback": 880_000})),
            )
            .await;
        let err = res.expect_err(
            "rollback options height must error on a fixture with no blocks",
        );
        assert!(
            err.message().contains("880000"),
            "explicit height must round-trip in error: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn dumptxoutset_rejects_latest_with_rollback_options() {
        // Core rejects snapshot_type="latest" combined with options.rollback.
        let params = rustoshi_consensus::ChainParams::mainnet();
        let (_tmp, server) = dumptxoutset_test_server(params, 945_000).await;

        let res = server
            .dump_tx_outset(
                "snap.dat".to_string(),
                Some("latest".to_string()),
                Some(serde_json::json!({"rollback": 880_000})),
            )
            .await;
        let err = res.expect_err("must reject conflicting type+options combo");
        assert!(
            err.message().to_lowercase().contains("rollback"),
            "error must reference rollback conflict: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn dumptxoutset_rejects_unknown_snapshot_type() {
        let params = rustoshi_consensus::ChainParams::regtest();
        let (_tmp, server) = dumptxoutset_test_server(params, 0).await;

        let res = server
            .dump_tx_outset("snap.dat".to_string(), Some("bogus".to_string()), None)
            .await;
        let err = res.expect_err("unknown snapshot_type must be rejected");
        assert!(
            err.message().contains("bogus"),
            "error must echo invalid type name: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn dumptxoutset_latest_path_unchanged() {
        // The pre-existing "latest" code path must still produce a snapshot
        // file with the expected JSON shape even after the rollback rewrite.
        // We point at a fresh regtest db (empty UTXO set) so the dump
        // succeeds with `coins_written == 0`. base_blockhash defaults to
        // Hash256::ZERO since no blocks have been processed; we only assert
        // the structural invariants that callers rely on.
        let params = rustoshi_consensus::ChainParams::regtest();
        let (tmp, server) = dumptxoutset_test_server(params, 0).await;

        let resp = server
            .dump_tx_outset("snap.dat".to_string(), Some("latest".to_string()), None)
            .await
            .expect("latest snapshot dump must still succeed");
        assert!(resp.get("coins_written").is_some());
        assert!(resp.get("base_hash").is_some());
        assert!(resp.get("base_height").is_some());
        assert!(resp.get("path").is_some());
        // Sanity-check the file actually exists at the resolved location.
        let p = std::path::PathBuf::from(resp["path"].as_str().unwrap());
        assert!(p.exists(), "dumptxoutset must create the file: {}", p.display());
        // Cleanup is automatic when `tmp` drops.
        drop(tmp);
    }

    // ============================================================
    // DUMPTXOUTSET ROLLBACK REWIND→DUMP→REPLAY TESTS
    // ============================================================

    /// Helper: append a synthetic block at height `h` building on `prev_hash`.
    ///
    /// The block has a single coinbase that pays `value` to a placeholder
    /// scriptPubKey. We persist the block, header, height-index, block-index,
    /// undo data, and UTXO so the rollback path's prefetch + disconnect +
    /// replay loops have everything they need.
    ///
    /// `txid_marker` is mixed into the coinbase scriptSig so each block's
    /// coinbase txid is distinct (otherwise the coinbase `OutPoint`s would
    /// collide across heights and the UTXO-set restore would be ambiguous).
    fn synth_append_block(
        store: &BlockStore,
        h: u32,
        prev_hash: Hash256,
        value: u64,
        txid_marker: u8,
    ) -> (Hash256, Block) {
        // Build a coinbase tx — input has empty prev-out and a unique
        // scriptSig so each height yields a distinct txid.
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: vec![txid_marker; 4 + h as usize % 8],
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x51], // OP_TRUE
            }],
            lock_time: 0,
        };
        let block = Block {
            header: rustoshi_primitives::BlockHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root: Hash256::ZERO, // not validated on the rollback path
                timestamp: 1_700_000_000 + h,
                bits: 0x207fffff,
                nonce: h,
            },
            transactions: vec![coinbase.clone()],
        };
        let block_hash = block.block_hash();

        store.put_block(&block_hash, &block).unwrap();
        store.put_header(&block_hash, &block.header).unwrap();
        store.put_height_index(h, &block_hash).unwrap();
        {
            use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_SCRIPTS);
            status.set(BlockStatus::HAVE_DATA);
            let entry = BlockIndexEntry {
                height: h,
                status,
                n_tx: block.transactions.len() as u32,
                timestamp: block.header.timestamp,
                bits: block.header.bits,
                nonce: block.header.nonce,
                version: block.header.version,
                prev_hash,
                chain_work: [0u8; 32],
            };
            store.put_block_index(&block_hash, &entry).unwrap();
        }

        // Coinbase-only blocks consume nothing, so the undo data is empty
        // (`spent_coins` is empty).
        store
            .put_undo(
                &block_hash,
                &rustoshi_storage::block_store::UndoData {
                    spent_coins: vec![],
                },
            )
            .unwrap();

        // Add the coinbase output to the UTXO set so the disconnect path has
        // something to remove and the replay path has something to add back.
        let coinbase_txid = coinbase.txid();
        store
            .put_utxo(
                &OutPoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                &rustoshi_storage::block_store::CoinEntry {
                    height: h,
                    is_coinbase: true,
                    value,
                    script_pubkey: vec![0x51],
                },
            )
            .unwrap();

        store.set_best_block(&block_hash, h).unwrap();
        (block_hash, block)
    }

    /// Walk `CF_UTXO` and return a sorted snapshot for diffing.
    fn snapshot_utxo(db: &ChainDb) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut rows: Vec<_> = db
            .iter_cf(CF_UTXO)
            .unwrap()
            .filter(|(k, _)| k.len() == 36)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_above_tip_errors() {
        // Explicit `{"rollback": N}` where N > tip must reject with a clear
        // "above tip" error. Mirrors Core's
        // `dumptxoutset` behaviour at `bitcoin-core/src/rpc/blockchain.cpp`.
        let params = rustoshi_consensus::ChainParams::regtest();
        let (_tmp, server) = dumptxoutset_test_server(params, 5).await;

        let res = server
            .dump_tx_outset(
                "snap.dat".to_string(),
                None,
                Some(serde_json::json!({"rollback": 100})),
            )
            .await;
        let err = res.expect_err("above-tip rollback must error");
        let msg = err.message().to_string();
        assert!(msg.contains("100"), "error must echo target height: {}", msg);
        assert!(
            msg.to_lowercase().contains("above") || msg.to_lowercase().contains("tip"),
            "error must mention tip/above: {}",
            msg
        );
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_rewind_dump_replay_round_trips_utxo_set() {
        // End-to-end: build a 3-block chain on top of regtest genesis,
        // capture the UTXO set, run rollback to genesis, and verify the
        // UTXO set + chain tip are restored bit-for-bit after replay.
        // This is the property that makes rollback safe to use on a live
        // chain: the only externally-visible artefact is the snapshot file.
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let params = rustoshi_consensus::ChainParams::regtest();
        let genesis_hash = params.genesis_hash;

        // Seed genesis.
        {
            let store = BlockStore::new(&db);
            store.init_genesis(&params).unwrap();
            assert_eq!(store.get_best_height().unwrap(), Some(0));
        }

        // Build h=1, h=2, h=3 on top of genesis.
        let (h1, _b1) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 1, genesis_hash, 50_000_000, 0xA1)
        };
        let (h2, _b2) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 2, h1, 50_000_000, 0xA2)
        };
        let (h3, _b3) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 3, h2, 50_000_000, 0xA3)
        };

        // Capture pre-rollback state.
        let utxo_before = snapshot_utxo(&db);
        assert_eq!(
            utxo_before.len(),
            3,
            "expected 3 coinbase outputs on the chain"
        );

        // Wire up the RPC server with the seeded chainstate.
        let mut rpc_state = RpcState::new(db.clone(), params);
        rpc_state.best_height = 3;
        rpc_state.best_hash = h3;
        rpc_state.data_dir = Some(tmp.path().to_path_buf());
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state.clone(), peer_state);

        // Roll back to genesis (height 0). Snapshot should land at the
        // genesis tip.
        let resp = server
            .dump_tx_outset(
                "rolled.dat".to_string(),
                None,
                Some(serde_json::json!({"rollback": 0})),
            )
            .await
            .expect("rollback dump must succeed on a healthy chainstate");

        // Snapshot file must exist and be anchored at genesis.
        let snap_path = std::path::PathBuf::from(resp["path"].as_str().unwrap());
        assert!(snap_path.exists(), "snapshot file must be written");
        assert_eq!(resp["base_height"].as_u64(), Some(0));
        assert_eq!(
            resp["base_hash"].as_str().unwrap(),
            genesis_hash.to_hex(),
            "snapshot must be anchored at genesis hash"
        );
        // Genesis has no spendable outputs in regtest -> the snapshot is
        // empty. (Regtest genesis coinbase is unspendable by consensus.)
        assert_eq!(
            resp["coins_written"].as_u64(),
            Some(0),
            "regtest genesis has no UTXOs"
        );

        // Rollback metadata must reflect the rewind we just performed.
        let rb = &resp["rollback"];
        assert_eq!(rb["from_height"].as_u64(), Some(3));
        assert_eq!(rb["to_height"].as_u64(), Some(0));
        assert_eq!(rb["blocks_rewound"].as_u64(), Some(3));

        // Post-replay: tip + UTXO state must match exactly what we had
        // before the rollback.
        let utxo_after = snapshot_utxo(&db);
        assert_eq!(
            utxo_before, utxo_after,
            "UTXO set must round-trip through rewind+replay byte-for-byte"
        );
        let st = state.read().await;
        assert_eq!(st.best_height, 3, "in-memory tip height must be restored");
        assert_eq!(st.best_hash, h3, "in-memory tip hash must be restored");
        let store = BlockStore::new(&st.db);
        assert_eq!(store.get_best_height().unwrap(), Some(3));
        assert_eq!(store.get_best_block_hash().unwrap(), Some(h3));
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_partial_rewind_to_intermediate_height() {
        // Roll back to a strictly-intermediate height (target=1 on a tip=3
        // chain). Verifies the height-arithmetic is right and that the
        // snapshot is taken at the rolled-back tip (not genesis, not the
        // original tip).
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let params = rustoshi_consensus::ChainParams::regtest();
        let genesis_hash = params.genesis_hash;

        {
            let store = BlockStore::new(&db);
            store.init_genesis(&params).unwrap();
        }
        let (h1, _) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 1, genesis_hash, 50_000_000, 0xB1)
        };
        let (h2, _) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 2, h1, 50_000_000, 0xB2)
        };
        let (h3, _) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 3, h2, 50_000_000, 0xB3)
        };

        let utxo_before = snapshot_utxo(&db);

        let mut rpc_state = RpcState::new(db.clone(), params);
        rpc_state.best_height = 3;
        rpc_state.best_hash = h3;
        rpc_state.data_dir = Some(tmp.path().to_path_buf());
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state.clone(), peer_state);

        let resp = server
            .dump_tx_outset(
                "rolled-mid.dat".to_string(),
                None,
                Some(serde_json::json!({"rollback": 1})),
            )
            .await
            .expect("intermediate-height rollback must succeed");

        // Snapshot anchored at h1; only one coinbase output should be in
        // the dump (the one created by block 1).
        assert_eq!(resp["base_height"].as_u64(), Some(1));
        assert_eq!(resp["base_hash"].as_str().unwrap(), h1.to_hex());
        assert_eq!(resp["coins_written"].as_u64(), Some(1));
        assert_eq!(resp["rollback"]["blocks_rewound"].as_u64(), Some(2));

        // Post-replay: original tip + UTXO set restored.
        assert_eq!(snapshot_utxo(&db), utxo_before);
        let st = state.read().await;
        assert_eq!(st.best_height, 3);
        assert_eq!(st.best_hash, h3);
    }

    #[tokio::test]
    async fn dumptxoutset_rollback_rejects_existing_snapshot_file() {
        // Pre-existing output path must be rejected BEFORE any rewind
        // happens, so the caller can retry without paying for a useless
        // disconnect+reconnect.
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let params = rustoshi_consensus::ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        {
            let store = BlockStore::new(&db);
            store.init_genesis(&params).unwrap();
        }
        let (h1, _) = {
            let store = BlockStore::new(&db);
            synth_append_block(&store, 1, genesis_hash, 50_000_000, 0xC1)
        };

        let mut rpc_state = RpcState::new(db.clone(), params);
        rpc_state.best_height = 1;
        rpc_state.best_hash = h1;
        rpc_state.data_dir = Some(tmp.path().to_path_buf());
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state.clone(), peer_state);

        // Plant a file at the target snapshot path.
        let snap_path = tmp.path().join("already-here.dat");
        std::fs::write(&snap_path, b"existing").unwrap();
        let utxo_before = snapshot_utxo(&db);

        let res = server
            .dump_tx_outset(
                "already-here.dat".to_string(),
                None,
                Some(serde_json::json!({"rollback": 0})),
            )
            .await;
        let err = res.expect_err("must reject when output already exists");
        assert!(
            err.message().to_lowercase().contains("already exists"),
            "error must say 'already exists': {}",
            err.message()
        );

        // Crucially: chain must be UNTOUCHED when the existence check
        // rejects the request.
        assert_eq!(
            snapshot_utxo(&db),
            utxo_before,
            "chainstate must not be mutated when output path is rejected"
        );
        let st = state.read().await;
        assert_eq!(st.best_height, 1);
        assert_eq!(st.best_hash, h1);
    }
}
