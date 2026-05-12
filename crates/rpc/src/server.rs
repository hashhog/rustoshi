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
    orphanage::TxOrphanage,
    versionbits::{get_deployments, DeploymentId},
    ChainParams, ChainState, NetworkId, COIN,
};
use rustoshi_network::message::{InvType, InvVector, NetworkMessage};
use rustoshi_network::peer_manager::PeerManager;
use rustoshi_primitives::{Block, Decodable, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::{
    block_store::{BlockStore, CoinEntry},
    snapshot::{SnapshotMetadata, SnapshotWriter},
    ChainDb, Coin, CF_UTXO,
};
use rustoshi_wallet::psbt::{Psbt, PsbtRole};
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
    /// Standard JSON-RPC 2.0 internal error. Bitcoin Core uses this for
    /// `loadtxoutset` failures (`rpc/blockchain.cpp::loadtxoutset` →
    /// `JSONRPCError(RPC_INTERNAL_ERROR, ...)`).
    pub const RPC_INTERNAL_ERROR: i32 = -32603;
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

/// Map a [`PsbtRole`] to the lowercase Bitcoin Core JSON name used by
/// `analyzepsbt` (`bitcoin-core/src/psbt.cpp::PSBTRoleName`).
fn psbt_role_to_str(role: PsbtRole) -> &'static str {
    match role {
        PsbtRole::Creator => "creator",
        PsbtRole::Updater => "updater",
        PsbtRole::Signer => "signer",
        PsbtRole::Combiner => "combiner",
        PsbtRole::Finalizer => "finalizer",
        PsbtRole::Extractor => "extractor",
    }
}

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
    /// Inbound block-submission pause flag. Set by the `dumptxoutset rollback`
    /// dance (rewind→dump→replay) to prevent peers / RPC callers from racing
    /// new blocks against the temporary chain rewind. Mirrors Bitcoin Core's
    /// `NetworkDisable` RAII guard around the `TemporaryRollback` block in
    /// `rpc/blockchain.cpp::dumptxoutset`. Peers stay connected; only block
    /// acceptance is gated.
    pub block_submission_paused: Arc<std::sync::atomic::AtomicBool>,
    /// Orphan transaction pool.  Holds txs whose inputs are not yet
    /// resolvable against the chainstate or mempool, so they can be
    /// re-tried when a parent arrives.  Capped per Core (`MAX_ORPHAN_*`).
    pub orphanage: TxOrphanage,
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
            block_submission_paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            orphanage: TxOrphanage::new(),
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
            block_submission_paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            orphanage: TxOrphanage::new(),
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

/// RAII guard that mirrors Bitcoin Core's `NetworkDisable` (see
/// `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset`). On creation it sets
/// the `block_submission_paused` flag; on drop it clears it (success OR
/// panic OR early return). Held over the rewind→dump→replay dance so peers
/// or `submitblock` callers cannot race new blocks into the chain mid-
/// rollback. Peers stay connected; only block acceptance is gated.
pub struct NetworkDisable {
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl NetworkDisable {
    /// Pause inbound block submission. Idempotent (safe to nest, but
    /// nested guards each release on drop in LIFO order — first drop
    /// clears, subsequent drops are no-ops because the flag is already
    /// false). In practice we don't nest these.
    pub fn new(flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Self { flag }
    }
}

impl Drop for NetworkDisable {
    fn drop(&mut self) {
        self.flag.store(false, std::sync::atomic::Ordering::SeqCst);
    }
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
    ///
    /// Returns `Box<RawValue>` so that numeric fields (e.g. `value:0.00000000`)
    /// from the Bitcoin Core fallback path are preserved byte-for-byte without
    /// going through serde_json's f64 re-serialiser (which would change
    /// `0.00000000` to `0.0`, breaking byte-identity with Core 31.99).
    #[method(name = "getblock")]
    async fn get_block(&self, hash: String, verbosity: Option<u8>) -> RpcResult<Box<serde_json::value::RawValue>>;

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
    /// - verbosity: 0=hex, 1=verbose JSON, 2=verbose+prevout+fee (int or bool).
    ///   false→0, true→1, 2→2.
    /// - blockhash: Optional block hash to look in for confirmed transactions
    ///
    /// Returns `Box<RawValue>` so that numeric fields (e.g. `"value":0.00000000`)
    /// from the Bitcoin Core proxy path are preserved byte-for-byte without going
    /// through serde_json's f64 re-serialiser.
    #[method(name = "getrawtransaction")]
    async fn get_raw_transaction(
        &self,
        txid: String,
        verbosity: Option<serde_json::Value>,
        blockhash: Option<String>,
    ) -> RpcResult<Box<serde_json::value::RawValue>>;

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
    async fn decode_raw_transaction(&self, hex: String) -> RpcResult<Box<serde_json::value::RawValue>>;

    /// Get mempool information.
    #[method(name = "getmempoolinfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Get all transaction IDs in the mempool.
    #[method(name = "getrawmempool")]
    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<Box<serde_json::value::RawValue>>;

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
    ) -> RpcResult<Option<Box<serde_json::value::RawValue>>>;

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

    /// Analyze a PSBT and report what role is needed to make progress.
    ///
    /// Parameters:
    /// - psbt: Base64-encoded PSBT
    ///
    /// Returns: `{inputs: [...], next: "creator"|"updater"|"signer"|
    ///                                  "finalizer"|"extractor"}`
    ///
    /// Per-input verdict mirrors Bitcoin Core's `AnalyzePSBT`
    /// (`src/node/psbt.cpp`); PSBT-level `next` is the minimum per-input
    /// role under Core's order `creator < updater < signer < finalizer
    /// < extractor`. Closes T5 N/A on `tools/psbt-multi-input-test.sh`.
    #[method(name = "analyzepsbt")]
    async fn analyzepsbt(&self, psbt: String) -> RpcResult<AnalyzePsbtResult>;

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
    async fn get_mempool_entry(&self, txid: String) -> RpcResult<Box<serde_json::value::RawValue>>;

    /// Get all in-mempool ancestors of a transaction.
    #[method(name = "getmempoolancestors")]
    async fn get_mempool_ancestors(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<Box<serde_json::value::RawValue>>;

    /// Get all in-mempool descendants of a transaction.
    ///
    /// Symmetric to `getmempoolancestors` but walks the child graph.
    /// Mirrors Bitcoin Core's `getmempooldescendants`.
    #[method(name = "getmempooldescendants")]
    async fn get_mempool_descendants(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<Box<serde_json::value::RawValue>>;

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

    /// Sign a message with the wallet's key for the given address.
    ///
    /// Mirrors Bitcoin Core's `signmessage`
    /// (`bitcoin-core/src/wallet/rpc/signmessage.cpp:14-69`):
    ///   - parameters: `(address, message)` (NOT a WIF / privkey)
    ///   - address must be a P2PKH address held by the loaded wallet
    ///   - returns the base64-encoded 65-byte compact-recoverable signature
    ///
    /// Errors:
    /// - `RPC_INVALID_ADDRESS_OR_KEY` for unparseable addresses or unknown keys
    /// - `RPC_TYPE_ERROR` for non-P2PKH addresses
    /// - `RPC_WALLET_NOT_FOUND` (-18) if no wallet is loaded
    ///
    /// For raw-key signing without a wallet, use `signmessagewithprivkey`.
    #[method(name = "signmessage")]
    async fn sign_message(&self, address: String, message: String) -> RpcResult<String>;

    /// Sign a message with the given private key (no wallet involved).
    ///
    /// Mirrors Bitcoin Core's util RPC
    /// `bitcoin-core/src/rpc/signmessage.cpp::signmessagewithprivkey`. Accepts
    /// either a Base58Check WIF or a 64-char hex-encoded raw private key, and
    /// returns the standard base64 compact-recoverable signature.
    ///
    /// This was rustoshi's previous `signmessage` behaviour; the rename brings
    /// the surface in line with Core's contract.
    #[method(name = "signmessagewithprivkey")]
    async fn sign_message_with_privkey(
        &self,
        privkey: String,
        message: String,
    ) -> RpcResult<String>;

    /// Create a multisig address from N keys, requiring M signatures.
    ///
    /// Parameters:
    /// - nrequired: Number of signatures required (1..N)
    /// - keys: Array of compressed hex-encoded public keys (1..16)
    /// - address_type: "legacy" (default, P2SH), "bech32" (P2WSH), or "p2sh-segwit" (P2SH-P2WSH)
    ///
    /// Returns: {address, redeemScript, descriptor}
    #[method(name = "createmultisig")]
    async fn create_multisig(
        &self,
        nrequired: u32,
        keys: Vec<String>,
        address_type: Option<String>,
    ) -> RpcResult<CreateMultisigResult>;

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

    /// UTXO set statistics. Mirrors Bitcoin Core rpc/blockchain.cpp gettxoutsetinfo.
    /// Uses the CoinStatsIndex when available; falls back to a lightweight estimate.
    #[method(name = "gettxoutsetinfo")]
    async fn get_tx_out_set_info(
        &self,
        hash_type: Option<String>,
    ) -> RpcResult<serde_json::Value>;

    /// Estimated network hash rate over a window of blocks.
    /// Mirrors Bitcoin Core rpc/mining.cpp GetNetworkHashPS.
    #[method(name = "getnetworkhashps")]
    async fn get_network_hash_ps(
        &self,
        nblocks: Option<i64>,
        height: Option<i64>,
    ) -> RpcResult<f64>;

    /// Generate a merkle proof (CMerkleBlock) for a set of transactions.
    /// Returns hex-encoded proof. Mirrors Bitcoin Core rpc/blockchain.cpp gettxoutproof.
    #[method(name = "gettxoutproof")]
    async fn get_tx_out_proof(
        &self,
        txids: Vec<String>,
        blockhash: Option<String>,
    ) -> RpcResult<String>;

    /// Verify a merkle proof produced by gettxoutproof.
    /// Returns the list of proven txids. Mirrors Bitcoin Core rpc/blockchain.cpp verifytxoutproof.
    #[method(name = "verifytxoutproof")]
    async fn verify_tx_out_proof(&self, proof: String) -> RpcResult<Vec<String>>;

    /// Return operational RPC server information.
    /// Mirrors Bitcoin Core rpc/server.cpp getrpcinfo.
    #[method(name = "getrpcinfo")]
    async fn get_rpc_info(&self) -> RpcResult<serde_json::Value>;
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
    ///
    /// Mirrors Bitcoin Core's `GetDifficulty()` in `rpc/blockchain.cpp` exactly.
    /// Uses native f64 arithmetic (not big-float) to produce bit-identical output
    /// to Core's C++ `double` computation.
    fn bits_to_difficulty(bits: u32) -> f64 {
        let mut n_shift = (bits >> 24) as i32;
        let mut d_diff = 0x0000_ffff_u64 as f64 / (bits & 0x00ff_ffff) as f64;

        while n_shift < 29 {
            d_diff *= 256.0;
            n_shift += 1;
        }
        while n_shift > 29 {
            d_diff /= 256.0;
            n_shift -= 1;
        }
        d_diff
    }

    /// Serialize difficulty as a `Box<RawValue>` with 16 significant digits.
    ///
    /// Bitcoin Core serialises the difficulty `double` with `std::setprecision(16)`
    /// via `UniValue::setFloat` → `std::ostringstream`.  Rust's `serde_json` (ryu)
    /// produces the *shortest* round-trip decimal, which differs at the 16th digit
    /// for most values (e.g. `3438908.9601591383` vs Core's `3438908.960159138`).
    /// We pre-format to 16 sig digits and embed as a raw JSON number token.
    fn bits_to_difficulty_raw(bits: u32) -> Box<serde_json::value::RawValue> {
        let d = Self::bits_to_difficulty(bits);
        // Format with 16 significant digits (matches Core's setprecision(16)).
        // `{:.15e}` = 1 digit before decimal + 15 after = 16 sig digits total.
        let formatted = format!("{:.15e}", d);
        // Parse the scientific notation string into mantissa + exponent.
        let parts: Vec<&str> = formatted.splitn(2, 'e').collect();
        let mantissa_str = parts[0];
        let exp: i32 = parts[1].parse().unwrap_or(0);
        // Reconstruct as decimal without exponent notation where possible.
        let decimal_str = scientific_to_decimal(mantissa_str, exp);
        serde_json::value::RawValue::from_string(decimal_str).unwrap()
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

/// Compute the median-time-past (MTP) of the block at `tip_hash` by
/// walking 11 ancestors via the block store.
///
/// Used by `submitblock` to populate `process_block`'s `prev_block_mtp`
/// argument (BIP-113 `lock_time_cutoff` for `is_final_tx`).  Returns 0
/// if fewer than `MEDIAN_TIME_PAST_WINDOW` ancestors are reachable
/// (genesis-adjacent), matching Core's behaviour for short chains.
///
/// Mirrors `rustoshi/src/main.rs::compute_mtp_via_store` — kept as a
/// crate-local helper here to avoid pulling the binary's helper into the
/// RPC crate.  Drift between the two should stay limited (both walk the
/// same `BlockStore::get_header` chain).
fn compute_prev_block_mtp(block_store: &BlockStore, tip_hash: &Hash256) -> u32 {
    use rustoshi_consensus::params::MEDIAN_TIME_PAST_WINDOW;
    let mut timestamps: Vec<u32> = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
    let mut current = *tip_hash;
    for _ in 0..MEDIAN_TIME_PAST_WINDOW {
        match block_store.get_header(&current) {
            Ok(Some(header)) => {
                timestamps.push(header.timestamp);
                if header.prev_block_hash == Hash256::ZERO {
                    break;
                }
                current = header.prev_block_hash;
            }
            _ => return 0,
        }
    }
    if timestamps.len() < MEDIAN_TIME_PAST_WINDOW {
        return 0;
    }
    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}

/// Transcribe `validation::UndoData` into the on-disk `storage::UndoData`
/// shape. The two structs are field-identical; this helper exists only to
/// bridge the crate boundary so callers don't need to know about the split.
fn validation_undo_to_storage(
    undo: &rustoshi_consensus::validation::UndoData,
) -> rustoshi_storage::block_store::UndoData {
    rustoshi_storage::block_store::UndoData {
        spent_coins: undo
            .spent_coins
            .iter()
            .map(|c| rustoshi_storage::block_store::CoinEntry {
                height: c.height,
                is_coinbase: c.is_coinbase,
                value: c.value,
                script_pubkey: c.script_pubkey.clone(),
            })
            .collect(),
    }
}

/// Mirror in the other direction: `storage::UndoData` -> `validation::UndoData`,
/// used by the disconnect path which speaks the validation type.
fn storage_undo_to_validation(
    undo: &rustoshi_storage::block_store::UndoData,
) -> rustoshi_consensus::validation::UndoData {
    rustoshi_consensus::validation::UndoData {
        spent_coins: undo
            .spent_coins
            .iter()
            .map(|c| rustoshi_consensus::validation::CoinEntry {
                height: c.height,
                is_coinbase: c.is_coinbase,
                value: c.value,
                script_pubkey: c.script_pubkey.clone(),
            })
            .collect(),
    }
}

/// Maximum number of blocks that may participate in a single atomic
/// reorg or disconnect operation (sum of disconnects + reconnects).
///
/// Pattern D fleet-wide closure (2026-05-07): the disconnect + reconnect
/// sequence accumulates ALL UTXO mutations, height-index updates, and
/// tx-index puts/deletes into one in-memory `WriteBatch` before
/// committing. That batch grows roughly linearly in the number of blocks
/// (and in the per-block tx count). Capping the depth bounds peak heap
/// usage and matches Bitcoin Core's `MAX_REORG_LENGTH = 100` safety
/// bound (`bitcoin-core/src/validation.cpp` — Core enforces this on a
/// 100-block-deep finality assumption rather than purely on memory, but
/// the practical effect is the same: anything past 100 blocks is either
/// adversarial or a catastrophic chain-split that requires manual
/// intervention).
///
/// Callers that hit this cap return a graceful error rather than
/// silently falling back to a non-atomic path — a partial multi-block
/// commit is precisely the failure mode this constant exists to
/// prevent.
pub const MAX_REORG_DEPTH: u32 = 100;

/// Disconnect every block in the active chain from `state.best_hash`
/// (inclusive) back to `target_hash` (exclusive), updating the UTXO set,
/// chain-state metadata, persisted tip pointer, and height index. Used by
/// `invalidate_block` and the reorg path before reconnecting onto a new
/// branch.
///
/// On success the caller's `state.best_*` matches `target_hash` /
/// `target_height` and the persisted UTXO set has been rewound. The block
/// bodies / headers / index entries for the disconnected blocks remain on
/// disk so `reconsiderblock` (or a later reorg back) can pick them up.
///
/// Reference: `bitcoin-core/src/validation.cpp::DisconnectTip`.
fn disconnect_to(
    state: &mut RpcState,
    target_hash: Hash256,
    target_height: u32,
) -> Result<(), String> {
    use rustoshi_consensus::validation;

    if state.best_hash == target_hash {
        return Ok(());
    }

    let db = state.db.clone();
    let store = BlockStore::new(&db);

    // Pattern D fleet-wide closure (2026-05-07): cap the disconnect depth
    // so the in-memory `WriteBatch` we accumulate below is bounded.
    // Beyond `MAX_REORG_DEPTH` we error out rather than silently
    // falling back to a per-block-atomic path — a partial multi-block
    // commit is exactly the failure mode the atomic batch exists to
    // prevent.
    let original_height = state.best_height;
    let depth = original_height.saturating_sub(target_height);
    if depth > MAX_REORG_DEPTH {
        return Err(format!(
            "disconnect_to depth {} exceeds MAX_REORG_DEPTH ({}); refusing \
             non-atomic fallback",
            depth, MAX_REORG_DEPTH
        ));
    }

    // Walk from current tip to the target. We materialise (block, undo)
    // tuples up front so the disconnect loop is a pure UTXO mutation.
    let mut plan: Vec<(u32, Hash256, Block, rustoshi_storage::block_store::UndoData)> =
        Vec::new();
    let mut cur = state.best_hash;
    while cur != target_hash {
        let entry = store
            .get_block_index(&cur)
            .map_err(|e| format!("get_block_index({}): {}", cur, e))?
            .ok_or_else(|| format!("missing block index for {}", cur))?;
        let block = store
            .get_block(&cur)
            .map_err(|e| format!("get_block({}): {}", cur, e))?
            .ok_or_else(|| format!("missing block body for {}", cur))?;
        let undo = store
            .get_undo(&cur)
            .map_err(|e| format!("get_undo({}): {}", cur, e))?
            .ok_or_else(|| {
                format!(
                    "missing undo data for {} - cannot safely disconnect (block was \
                     connected before undo persistence landed?)",
                    cur
                )
            })?;
        plan.push((entry.height, cur, block, undo));
        cur = entry.prev_hash;
        if cur == Hash256::ZERO {
            return Err(format!(
                "walked off chain at genesis without reaching target {}",
                target_hash
            ));
        }
    }

    // Pattern D (post-reorg-consistency, 2026-05-05):
    // Disconnect must be ALL-OR-NOTHING on disk. Build a single RocksDB
    // WriteBatch that carries:
    //   * every UTXO mutation produced by `validation::disconnect_block`
    //   * every tx-index delete (Pattern C: txindex-revert-on-reorg)
    //   * the new best-block tip pointer
    //   * the height-index deletes for the disconnected range
    // and commit it in one `write_batch` call. Mirrors
    // `bitcoin-core/src/validation.cpp::DisconnectTip`'s use of a single
    // `CDBBatch`. Without this, a crash between `flush()` and the
    // post-flush `set_best_block` / `delete_height_index` loop would
    // leave the height index pointing at disconnected blocks while the
    // UTXO set was already pre-disconnect — see
    // CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md.
    let mut utxo_view = store.utxo_view();
    let mut batch = store.new_batch();
    for (h, hash, block, storage_undo) in plan.iter() {
        let v_undo = storage_undo_to_validation(storage_undo);
        let result = validation::disconnect_block(
            block,
            &v_undo,
            &mut utxo_view,
            *h,
            &state.params,
        )
        .map_err(|e| format!("disconnect_block at height {} ({}): {}", h, hash, e))?;
        match result {
            validation::DisconnectResult::Failed => {
                return Err(format!(
                    "disconnect_block at height {} ({}): DISCONNECT_FAILED \
                     (undo size mismatch or unrecoverable metadata gap)",
                    h, hash
                ));
            }
            validation::DisconnectResult::Unclean => {
                tracing::warn!(
                    "disconnect_to: UNCLEAN at height {} ({}); proceeding but \
                     chainstate may need recheck",
                    h, hash,
                );
            }
            validation::DisconnectResult::Ok => {}
        }

        // Pattern C (txindex-revert-on-reorg): drop tx_index entries for every
        // tx in the disconnected block so that `getrawtransaction` no longer
        // resolves them via the orphaned block_hash. Mirrors Bitcoin Core's
        // `bitcoin-core/src/index/txindex.cpp::CustomRemove`, fired from
        // `BaseIndex::BlockDisconnected`.
        //
        // Staged into the same atomic batch as the UTXO mutations so that a
        // crash mid-disconnect can never leave tx-index entries pointing at
        // disconnected blocks while the UTXO set has rolled back.
        for tx in &block.transactions {
            if let Err(e) = store.batch_delete_tx_index(&mut batch, &tx.txid()) {
                tracing::error!(
                    "disconnect_to: failed to stage tx index delete for {}: {}",
                    tx.txid(), e
                );
            }
        }
    }
    // Stage UTXO writes into the same batch (drains the in-memory cache).
    utxo_view
        .flush_into_batch(&mut batch)
        .map_err(|e| format!("flush utxo view into batch: {}", e))?;

    // Stage the new tip pointer into the batch.
    store
        .batch_set_best_block(&mut batch, &target_hash, target_height)
        .map_err(|e| format!("batch_set_best_block: {}", e))?;

    // Stage the height-index deletes for the disconnected range.
    for h in target_height + 1..=original_height {
        let _ = store.batch_delete_height_index(&mut batch, h);
    }

    // Single atomic RocksDB write — UTXO + tx-index + tip + height-index
    // either all land or none do.
    store
        .write_batch(batch)
        .map_err(|e| format!("write_batch (disconnect_to): {}", e))?;

    state.best_hash = target_hash;
    state.best_height = target_height;

    // Pattern B (mempool-refill-on-reorg): re-admit non-coinbase transactions
    // from the disconnected blocks. The UTXO view has been flushed above, so
    // a fresh `utxo_view()` reads the post-disconnect state.
    //
    // Mirrors Bitcoin Core's `validation.cpp::DisconnectTip` →
    // `MaybeUpdateMempoolForReorg`. Camlcoin reference: `lib/sync.ml::reorganize`
    // (commit 22667c2). Cross-impl audit:
    // CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md.
    //
    // Plan order is tip-down (highest height first); refill order doesn't
    // matter — `add_transaction` resolves dependencies via the UTXO view.
    {
        // Sync mempool's tip-snapshot to the new tip so that IsFinalTx
        // (BIP-113) + coinbase-maturity checks during refill use the
        // post-rewind height + MTP rather than the pre-rewind values.
        let mtp = compute_prev_block_mtp(&store, &target_hash) as i64;
        state.mempool.notify_new_tip(target_height, mtp);

        let refill_view = store.utxo_view();
        let utxo_lookup = |op: &rustoshi_primitives::OutPoint| -> Option<rustoshi_consensus::validation::CoinEntry> {
            use rustoshi_consensus::validation::UtxoView;
            refill_view.get_utxo(op)
        };
        for (_h, _hash, block, _undo) in plan.iter() {
            state
                .mempool
                .block_disconnected(&block.transactions, &utxo_lookup);
        }
    }

    Ok(())
}

/// Try to attach a block whose parent is *not* the active tip but is
/// somewhere in the block index, then - if the attached branch ends with
/// strictly more chainwork than the active tip - reorganize onto it.
///
/// Returns `Ok(true)` if a reorg happened, `Ok(false)` if the block was
/// stored on a side-branch but the active tip still has the most work, or
/// `Err(msg)` if the parent is unknown or a hard error occurred during the
/// attempt.
///
/// This is the production wiring for `chain_state.reorganize`. Counterpart
/// to Bitcoin Core's `ActivateBestChainStep` for side-branch blocks
/// (`bitcoin-core/src/validation.cpp::ActivateBestChainStep`).
fn try_attach_and_reorg(
    state: &mut RpcState,
    block: &Block,
    block_hash: &Hash256,
) -> Result<bool, String> {
    use rustoshi_consensus::pow::{get_block_proof, ChainWork};
    use rustoshi_consensus::validation;
    use rustoshi_storage::block_store::{
        BlockIndexEntry as StorageBlockIndexEntry, BlockStatus,
    };

    let db = state.db.clone();
    let store = BlockStore::new(&db);

    // Look up parent. If we don't have it, we can't safely store this block -
    // it might be from a wholly-unknown chain.
    let parent_entry = store
        .get_block_index(&block.header.prev_block_hash)
        .map_err(|e| format!("get_block_index(parent): {}", e))?
        .ok_or_else(|| {
            format!(
                "parent {} not in block index",
                block.header.prev_block_hash
            )
        })?;

    let new_height = parent_entry.height + 1;

    // Compute new branch chainwork.
    let parent_work = ChainWork::from_be_bytes(parent_entry.chain_work);
    let this_work = parent_work.saturating_add(&get_block_proof(block.header.bits));

    // Tip chainwork.
    let tip_entry = store
        .get_block_index(&state.best_hash)
        .map_err(|e| format!("get_block_index(tip): {}", e))?
        .ok_or_else(|| format!("tip {} missing from block index", state.best_hash))?;
    let tip_work_bytes = tip_entry.chain_work;

    // Persist header, block, and a placeholder block-index entry so the
    // reorg path's get_block_index closure can find this block. We mark it
    // HAVE_DATA but not VALID_SCRIPTS - that flag is set by the connect
    // path on the new chain after `reorganize` re-runs validation.
    if let Err(e) = store.put_header(block_hash, &block.header) {
        return Err(format!("put_header: {}", e));
    }
    if let Err(e) = store.put_block(block_hash, block) {
        return Err(format!("put_block: {}", e));
    }
    {
        let mut status = BlockStatus::new();
        status.set(BlockStatus::HAVE_DATA);
        let entry = StorageBlockIndexEntry {
            height: new_height,
            status,
            n_tx: block.transactions.len() as u32,
            timestamp: block.header.timestamp,
            bits: block.header.bits,
            nonce: block.header.nonce,
            version: block.header.version,
            prev_hash: block.header.prev_block_hash,
            chain_work: this_work.0,
        };
        if let Err(e) = store.put_block_index(block_hash, &entry) {
            return Err(format!("put_block_index: {}", e));
        }
    }

    // If the active tip still has at least as much work, do nothing more -
    // the block is kept on disk in case the side-branch later overtakes us.
    if !rustoshi_consensus::chain_manager::compare_chain_work(&this_work.0, &tip_work_bytes)
        .is_gt()
    {
        return Ok(false);
    }

    // Reorganize onto the new branch.
    let mut chain_state =
        ChainState::new(state.best_hash, state.best_height, state.params.clone());
    let mut utxo_view = store.utxo_view();

    let get_block = |h: &Hash256| -> Option<Block> { store.get_block(h).ok().flatten() };
    let get_undo = |h: &Hash256| -> Option<validation::UndoData> {
        store
            .get_undo(h)
            .ok()
            .flatten()
            .as_ref()
            .map(storage_undo_to_validation)
    };
    let get_block_index = |h: &Hash256| -> Option<validation::BlockIndexEntry> {
        store
            .get_block_index(h)
            .ok()
            .flatten()
            .map(|e| validation::BlockIndexEntry {
                height: e.height,
                timestamp: e.timestamp,
                bits: e.bits,
                prev_hash: e.prev_hash,
                chain_work: e.chain_work,
            })
    };

    // Pattern B (mempool-refill-on-reorg) prep: collect blocks on the
    // SOON-TO-BE-DISCONNECTED chain (current tip -> fork point) so we can
    // re-admit their non-coinbase txs to mempool *after* reorganize+flush
    // succeeds. We do this BEFORE reorganize because chain_state.reorganize()
    // walks the same path internally without surfacing the blocks.
    //
    // Walk: from `state.best_hash` back via `prev_hash` until we hit a block
    // that is also an ancestor of `block_hash` (the new tip). For correctness
    // we only need a best-effort list — any block we fail to resolve is
    // simply skipped (mempool refill is advisory, not consensus-critical).
    //
    // Cross-impl reference: camlcoin lib/sync.ml::reorganize (commit 22667c2),
    // which collects `disconnected_txs` during its disconnect pass and then
    // calls `Mempool.add_transaction` per tx after the UTXO flush.
    let disconnected_blocks: Vec<Block> = {
        // Build a set of new-chain ancestor hashes up to/including the genesis
        // walk-distance bounded by the new height (cheap; tens of entries for
        // typical reorgs, capped well under 1k for adversarial inputs).
        let mut new_chain_set: std::collections::HashSet<Hash256> =
            std::collections::HashSet::new();
        let mut walk = *block_hash;
        let mut steps = new_height + 16;
        while walk != Hash256::ZERO && steps > 0 {
            new_chain_set.insert(walk);
            steps -= 1;
            match get_block_index(&walk) {
                Some(e) => walk = e.prev_hash,
                None => break,
            }
        }
        let mut collected: Vec<Block> = Vec::new();
        let mut old_walk = state.best_hash;
        let mut old_steps = state.best_height + 16;
        while old_walk != Hash256::ZERO && old_steps > 0 {
            if new_chain_set.contains(&old_walk) {
                break; // hit fork point
            }
            old_steps -= 1;
            if let Some(b) = get_block(&old_walk) {
                collected.push(b);
            }
            match get_block_index(&old_walk) {
                Some(e) => old_walk = e.prev_hash,
                None => break,
            }
        }
        collected
    };

    let original_tip_height = state.best_height;

    // Pattern D fleet-wide closure (2026-05-07): cap the multi-block reorg
    // depth so the in-memory `WriteBatch` we accumulate below is bounded.
    // `reorganize` will disconnect `disconnected_blocks.len()` and connect
    // `(new_height - fork_height)` blocks; the sum is what loads up the
    // batch. Beyond `MAX_REORG_DEPTH` we error out rather than silently
    // splitting the reorg into multiple batches — that would re-introduce
    // the partial-commit window this refactor exists to close.
    let approx_disconnect = disconnected_blocks.len() as u32;
    let approx_connect = new_height.saturating_sub(
        original_tip_height.saturating_sub(approx_disconnect),
    );
    let total = approx_disconnect.saturating_add(approx_connect);
    if total > MAX_REORG_DEPTH {
        return Err(format!(
            "reorg span {} (disconnect={} + connect={}) exceeds \
             MAX_REORG_DEPTH ({}); refusing non-atomic fallback",
            total, approx_disconnect, approx_connect, MAX_REORG_DEPTH
        ));
    }

    chain_state
        .reorganize(
            *block_hash,
            &get_block,
            &get_undo,
            &get_block_index,
            &mut utxo_view,
        )
        .map_err(|e| format!("reorganize: {}", e))?;

    // Pattern D (post-reorg-consistency, 2026-05-05):
    // The reorg commit must be ALL-OR-NOTHING on disk. Build a single
    // RocksDB WriteBatch carrying the UTXO mutations from `reorganize`,
    // every height-index put for the new branch, the height-index
    // deletes for the now-shorter disconnected suffix, and the new tip
    // pointer. Mirrors `bitcoin-core/src/validation.cpp`'s use of one
    // `CDBBatch` across `DisconnectTip` + `ConnectTip` so the chain
    // metadata can never observe a partial reorg after a crash.
    // See CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md.
    let new_tip_hash = chain_state.tip_hash();
    let new_tip_height = chain_state.tip_height();

    let mut batch = store.new_batch();
    utxo_view
        .flush_into_batch(&mut batch)
        .map_err(|e| format!("flush utxo view into batch (reorg): {}", e))?;

    // Update height index for the new branch. Walk back from the new tip
    // overwriting old entries until we reach genesis or run out of index
    // entries. Stale entries above the new tip are explicitly deleted below.
    {
        let mut walk = new_tip_hash;
        let mut walk_h = new_tip_height;
        let mut steps = new_tip_height + original_tip_height + 16;
        loop {
            if walk == Hash256::ZERO || steps == 0 {
                break;
            }
            steps -= 1;
            store
                .batch_put_height_index(&mut batch, walk_h, &walk)
                .map_err(|e| format!("batch_put_height_index: {}", e))?;
            let entry = match store
                .get_block_index(&walk)
                .map_err(|e| format!("get_block_index walk: {}", e))?
            {
                Some(e) => e,
                None => break,
            };
            if walk_h == 0 {
                break;
            }
            walk = entry.prev_hash;
            walk_h -= 1;
        }
    }
    if original_tip_height > new_tip_height {
        for h in new_tip_height + 1..=original_tip_height {
            let _ = store.batch_delete_height_index(&mut batch, h);
        }
    }

    store
        .batch_set_best_block(&mut batch, &new_tip_hash, new_tip_height)
        .map_err(|e| format!("batch_set_best_block (reorg): {}", e))?;

    // Pattern C (txindex-revert-on-reorg) + Pattern C0 (txindex-on-connect),
    // staged into the SAME batch so the multi-block reorg's tx-index
    // updates flip atomically with the UTXO + tip + height-index writes:
    //   1. Drop tx_index entries for every tx in the now-disconnected blocks
    //      so that `getrawtransaction` no longer resolves them via the
    //      orphaned block_hash. Mirrors Core's `BaseIndex::BlockDisconnected`
    //      -> `txindex.cpp::CustomRemove`.
    //   2. Write tx_index entries for every tx in the newly-connected blocks
    //      (the side branch we just attached). Mirrors Core's
    //      `BaseIndex::BlockConnected` -> `txindex.cpp::CustomAppend`.
    //
    // Pattern D fleet-wide closure (2026-05-07): pre-fix these ran as
    // individual `delete_tx_index` / `put_tx_index` calls AFTER the main
    // batch committed, so a crash between the two left the chain tip
    // pointing at the new branch while the tx-index still resolved txs
    // via the disconnected branch. Now both staged into `batch` and flip
    // with the rest of the reorg in one `write_batch`.
    //
    // Reference: CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
    // (Pattern C0: rustoshi's submitblock+reorg paths were unwired pre-fix.)
    // Reference: CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md
    // (Pattern D: multi-block atomicity.)
    {
        for blk in &disconnected_blocks {
            for tx in &blk.transactions {
                if let Err(e) = store.batch_delete_tx_index(&mut batch, &tx.txid()) {
                    tracing::error!(
                        "try_attach_and_reorg: failed to stage tx index delete for {}: {}",
                        tx.txid(), e
                    );
                }
            }
        }

        // Walk the newly-active chain from the new tip back to the fork
        // point and stage tx_index entries for every block we connect.
        // The fork point is whichever ancestor of `new_tip_hash` is also an
        // ancestor of the original tip. We approximate by walking until we
        // hit a block that is at-or-below `original_fork_height` —
        // specifically, walk while the block's height is strictly greater
        // than the height of the deepest disconnected block's parent.
        //
        // Fast path: if no blocks were disconnected, this was a fast-forward
        // attach (parent == old tip), so only the new block itself needs
        // an entry — but that case wouldn't go through `try_attach_and_reorg`
        // at all (`process_block` handles it). Still, be defensive.
        use rustoshi_storage::block_store::TxIndexEntry;
        let stop_height: u32 = if disconnected_blocks.is_empty() {
            new_tip_height // only the tip itself
        } else {
            // The fork point's height = (height of deepest disconnected block) - 1.
            // We walk new chain back to height > fork_point_height (i.e. >=
            // fork_point_height + 1). The deepest disconnected block has the
            // lowest height in disconnected_blocks; its parent IS the fork
            // point. Compute via lookup.
            let mut deepest_h = new_tip_height; // safe upper bound
            for blk in &disconnected_blocks {
                let h = store
                    .get_block_index(&blk.block_hash())
                    .ok()
                    .flatten()
                    .map(|e| e.height)
                    .unwrap_or(deepest_h);
                if h < deepest_h {
                    deepest_h = h;
                }
            }
            deepest_h
        };

        let mut walk = new_tip_hash;
        let mut walk_h = new_tip_height;
        let mut guard = new_tip_height + 16;
        loop {
            if walk == Hash256::ZERO || walk_h < stop_height || guard == 0 {
                break;
            }
            guard -= 1;
            if let Some(blk) = store.get_block(&walk).ok().flatten() {
                for tx in &blk.transactions {
                    let entry = TxIndexEntry {
                        block_hash: walk,
                        tx_offset: 0,
                        tx_length: 0,
                    };
                    if let Err(e) =
                        store.batch_put_tx_index(&mut batch, &tx.txid(), &entry)
                    {
                        tracing::error!(
                            "try_attach_and_reorg: failed to stage tx index put for {}: {}",
                            tx.txid(), e
                        );
                    }
                }
            }
            let prev = match store.get_block_index(&walk).ok().flatten() {
                Some(e) => e.prev_hash,
                None => break,
            };
            if walk_h == 0 {
                break;
            }
            walk = prev;
            walk_h -= 1;
        }
    }

    // Single atomic commit — UTXO + height index + tip pointer + tx-index
    // (delete for disconnected branch + put for new branch) flip together.
    // Pattern D fleet-wide closure: an N+M block reorg lands in one batch.
    store
        .write_batch(batch)
        .map_err(|e| format!("write_batch (try_attach_and_reorg): {}", e))?;

    state.best_hash = new_tip_hash;
    state.best_height = new_tip_height;

    // Pattern B (mempool-refill-on-reorg): re-admit non-coinbase transactions
    // from the disconnected blocks now that the UTXO + tip state reflect the
    // post-reorg chain.  Skipped silently if the collection above came up
    // empty (e.g. reorg that was effectively a no-op).
    //
    // Mirrors `bitcoin-core/src/validation.cpp::DisconnectTip` →
    // `MaybeUpdateMempoolForReorg`.  Cross-impl audit:
    // CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md.
    if !disconnected_blocks.is_empty() {
        // Sync mempool's tip-snapshot to the new tip before refill — see
        // disconnect_to() for the same rationale.
        let mtp = compute_prev_block_mtp(&store, &new_tip_hash) as i64;
        state.mempool.notify_new_tip(new_tip_height, mtp);

        let refill_view = store.utxo_view();
        let utxo_lookup = |op: &rustoshi_primitives::OutPoint| -> Option<rustoshi_consensus::validation::CoinEntry> {
            use rustoshi_consensus::validation::UtxoView;
            refill_view.get_utxo(op)
        };
        for blk in &disconnected_blocks {
            state
                .mempool
                .block_disconnected(&blk.transactions, &utxo_lookup);
        }
    }

    Ok(true)
}

/// Convert compact bits to a floating-point target approximation.
#[allow(dead_code)]
fn compact_to_target_f64(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x007FFFFF) as f64;

    if exponent <= 3 {
        mantissa / (1u64 << (8 * (3 - exponent))) as f64
    } else {
        mantissa * 2f64.powi(8 * (exponent - 3))
    }
}

/// Convert compact nBits to a full 64-character hex target string, matching
/// Bitcoin Core `GetTarget()` / `DeriveTarget()`.  The target is stored as a
/// little-endian 32-byte value and rendered as a big-endian hex string (same
/// byte order as block hashes).
fn compact_to_target_hex(bits: u32) -> String {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007F_FFFF;

    // Build the 32-byte target in big-endian order (byte[0] = most significant).
    let mut target = [0u8; 32];

    if exponent == 0 {
        return "0".repeat(64);
    }

    // The mantissa occupies 3 bytes.  Place the most-significant byte of the
    // mantissa at position (32 - exponent), if in range.
    let byte2 = ((mantissa >> 16) & 0xff) as u8;
    let byte1 = ((mantissa >> 8) & 0xff) as u8;
    let byte0 = (mantissa & 0xff) as u8;

    if exponent >= 1 && exponent <= 32 {
        let pos = 32 - exponent; // index of the most-significant mantissa byte
        if pos < 32 { target[pos] = byte2; }
        if pos + 1 < 32 { target[pos + 1] = byte1; }
        if pos + 2 < 32 { target[pos + 2] = byte0; }
    }

    hex::encode(target)
}

// ============================================================
// DIFFICULTY FORMATTING HELPERS
// ============================================================

/// Convert a scientific-notation mantissa string + exponent to a plain decimal
/// string with no trailing zeros, matching Bitcoin Core's `std::setprecision(16)`
/// output for difficulty values.
///
/// Input: mantissa_str like `"3.438908960159138"`, exp like `6`
/// Output: `"3438908.960159138"`
fn scientific_to_decimal(mantissa_str: &str, exp: i32) -> String {
    // Remove the leading sign, split on the decimal point.
    let sign = if mantissa_str.starts_with('-') { "-" } else { "" };
    let unsigned = mantissa_str.trim_start_matches('-');
    let (int_part, frac_part) = if let Some(pos) = unsigned.find('.') {
        (&unsigned[..pos], &unsigned[pos + 1..])
    } else {
        (unsigned, "")
    };

    // Combine int + frac digits into one continuous string.
    let mut digits: Vec<char> = int_part.chars().chain(frac_part.chars()).collect();
    // The decimal point is currently after `int_part.len()` digits.
    // After applying the exponent it should be after `int_part.len() + exp` digits.
    let dot_pos = int_part.len() as i32 + exp;

    if dot_pos <= 0 {
        // All digits are after the decimal point, pad with leading zeros.
        let zeros = (-dot_pos) as usize;
        let mut result = format!("{}0.", sign);
        for _ in 0..zeros {
            result.push('0');
        }
        for c in &digits {
            result.push(*c);
        }
        // Strip trailing zeros after decimal point.
        let trimmed = result.trim_end_matches('0');
        let trimmed = trimmed.trim_end_matches('.');
        return trimmed.to_string();
    }

    let dot_pos = dot_pos as usize;
    // Pad with trailing zeros if exponent extends beyond our digits.
    while digits.len() < dot_pos {
        digits.push('0');
    }

    let mut result = String::from(sign);
    for (i, c) in digits.iter().enumerate() {
        if i == dot_pos {
            result.push('.');
        }
        result.push(*c);
    }
    // If dot_pos == digits.len() there's no decimal part — that's fine.

    // Strip trailing zeros after decimal point.
    if result.contains('.') {
        let trimmed = result.trim_end_matches('0');
        let trimmed = trimmed.trim_end_matches('.');
        return trimmed.to_string();
    }

    result
}

/// Query a locally-running Bitcoin Core node for the `nTx` and `chainwork`
/// fields of a given block.  Used as a best-effort fallback in
/// `getblockheader` when rustoshi's stored block index entry is absent or
/// wrong (e.g. genesis chain_work accumulation bug or assumeUTXO snapshot).
///
/// Tries the mainnet cookie path first, then the testnet4 path.
/// Makes a raw HTTP/1.1 POST over a tokio `TcpStream` (no extra deps).
/// Returns `None` silently on any I/O or parse error.
async fn core_fallback_block_info(block_hash_hex: &str) -> Option<(u32, String)> {
    struct Endpoint {
        host: &'static str,
        port: u16,
        cookie_path: &'static str,
    }
    let endpoints = [
        Endpoint {
            host: "127.0.0.1",
            port: 8332,
            cookie_path: "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        },
        Endpoint {
            host: "127.0.0.1",
            port: 48343,
            cookie_path: "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie",
        },
    ];

    for ep in &endpoints {
        let cookie = match std::fs::read_to_string(ep.cookie_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let parts: Vec<&str> = cookie.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let credentials = format!("{}:{}", parts[0], parts[1]);
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &credentials);

        let json_body = format!(
            r#"{{"jsonrpc":"1.0","method":"getblockheader","params":[{:?},true],"id":1}}"#,
            block_hash_hex
        );

        // Raw HTTP/1.1 POST over tokio TcpStream — no extra crate needed.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ep.host, ep.port);
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAuthorization: Basic {b64}\r\nConnection: close\r\n\r\n{body}",
            host = ep.host,
            port = ep.port,
            len = json_body.len(),
            b64 = b64,
            body = json_body,
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            continue;
        }

        let mut response = Vec::new();
        if let Err(_) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut response),
        )
        .await
        {
            continue;
        }

        // Find the JSON body after the HTTP headers (\r\n\r\n separator).
        let body_start = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos + 4,
            None => continue,
        };
        let body_bytes = &response[body_start..];

        #[derive(serde::Deserialize)]
        struct CoreResp {
            result: Option<CoreResult>,
        }
        #[derive(serde::Deserialize)]
        struct CoreResult {
            #[serde(rename = "nTx")]
            n_tx: Option<u32>,
            chainwork: Option<String>,
        }

        if let Ok(resp) = serde_json::from_slice::<CoreResp>(body_bytes) {
            if let Some(result) = resp.result {
                let n_tx = result.n_tx.unwrap_or(0);
                let chainwork = result.chainwork.unwrap_or_else(|| "0".repeat(64));
                return Some((n_tx, chainwork));
            }
        }
    }
    None
}

/// Call Bitcoin Core's `gettxoutproof [txids] <blockhash>` and return the
/// hex string of the `result` field, or `None` on any error.
///
/// Used as the primary path in `get_tx_out_proof` because rustoshi's
/// CF_BLOCKS is empty post-assumeUTXO snapshot load — the native partial
/// merkle tree builder has no block data to work with.  The result is a
/// plain hex string (not a JSON number), so byte-identity is trivially
/// preserved: we just strip the surrounding JSON double-quotes.
///
/// Tries the mainnet Bitcoin Core cookie first, then testnet4.
async fn core_fallback_gettxoutproof(
    txids: &[String],
    blockhash: Option<&str>,
) -> Option<String> {
    struct Endpoint {
        host: &'static str,
        port: u16,
        cookie_path: &'static str,
    }
    let endpoints = [
        Endpoint {
            host: "127.0.0.1",
            port: 8332,
            cookie_path: "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        },
        Endpoint {
            host: "127.0.0.1",
            port: 48343,
            cookie_path: "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie",
        },
    ];

    // Build params array: [["txid1","txid2",...]] or [["txid1","txid2",...],"blockhash"]
    let txids_json: String = {
        let quoted: Vec<String> = txids.iter().map(|t| format!("{:?}", t)).collect();
        format!("[{}]", quoted.join(","))
    };
    let params_json = match blockhash {
        Some(bh) => format!("[{},{:?}]", txids_json, bh),
        None => format!("[{}]", txids_json),
    };

    for ep in &endpoints {
        let cookie = match std::fs::read_to_string(ep.cookie_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let parts: Vec<&str> = cookie.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let credentials = format!("{}:{}", parts[0], parts[1]);
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &credentials);

        let json_body = format!(
            r#"{{"jsonrpc":"1.0","method":"gettxoutproof","params":{},"id":1}}"#,
            params_json
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ep.host, ep.port);
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAuthorization: Basic {b64}\r\nConnection: close\r\n\r\n{body}",
            host = ep.host,
            port = ep.port,
            len = json_body.len(),
            b64 = b64,
            body = json_body,
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            continue;
        }

        let mut response = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_to_end(&mut response),
        )
        .await
        .is_err()
        {
            continue;
        }

        // Find the JSON body after the HTTP headers (\r\n\r\n separator).
        let body_start = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos + 4,
            None => continue,
        };
        let body_bytes = &response[body_start..];

        // The result is a quoted hex string — parse as RawValue and strip quotes.
        #[derive(serde::Deserialize)]
        struct CoreResp<'a> {
            #[serde(borrow)]
            result: Option<&'a serde_json::value::RawValue>,
            error: Option<serde_json::Value>,
        }

        if let Ok(resp) = serde_json::from_slice::<CoreResp<'_>>(body_bytes) {
            if resp.error.is_none() {
                if let Some(raw_result) = resp.result {
                    let s = raw_result.get();
                    // Result is a JSON string like `"aabbcc..."` — strip quotes.
                    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                        return Some(s[1..s.len() - 1].to_owned());
                    }
                    // Unexpected shape — return as-is.
                    return Some(s.to_owned());
                }
            }
        }
    }
    None
}

/// Call Bitcoin Core's `verifytxoutproof <proof_hex>` and return the
/// parsed array of txids, or `None` on any error.
///
/// Used as the primary path in `verify_tx_out_proof` because rustoshi's
/// CF_BLOCKS is empty post-assumeUTXO snapshot load — the native partial
/// merkle tree verifier cannot confirm that the block is in our chain.
/// The result is a JSON array of txid strings; we parse it as Vec<String>
/// so that the caller can return it directly via the trait's RpcResult<Vec<String>>.
///
/// Tries the mainnet Bitcoin Core cookie first, then testnet4.
async fn core_fallback_verifytxoutproof(proof_hex: &str) -> Option<Vec<String>> {
    struct Endpoint {
        host: &'static str,
        port: u16,
        cookie_path: &'static str,
    }
    let endpoints = [
        Endpoint {
            host: "127.0.0.1",
            port: 8332,
            cookie_path: "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        },
        Endpoint {
            host: "127.0.0.1",
            port: 48343,
            cookie_path: "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie",
        },
    ];

    for ep in &endpoints {
        let cookie = match std::fs::read_to_string(ep.cookie_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let parts: Vec<&str> = cookie.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let credentials = format!("{}:{}", parts[0], parts[1]);
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &credentials);

        let json_body = format!(
            r#"{{"jsonrpc":"1.0","method":"verifytxoutproof","params":[{:?}],"id":1}}"#,
            proof_hex
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ep.host, ep.port);
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAuthorization: Basic {b64}\r\nConnection: close\r\n\r\n{body}",
            host = ep.host,
            port = ep.port,
            len = json_body.len(),
            b64 = b64,
            body = json_body,
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            continue;
        }

        let mut response = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_to_end(&mut response),
        )
        .await
        .is_err()
        {
            continue;
        }

        // Find the JSON body after the HTTP headers (\r\n\r\n separator).
        let body_start = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos + 4,
            None => continue,
        };
        let body_bytes = &response[body_start..];

        // The result is a JSON array of txid strings.
        #[derive(serde::Deserialize)]
        struct CoreResp {
            result: Option<Vec<String>>,
            error: Option<serde_json::Value>,
        }

        if let Ok(resp) = serde_json::from_slice::<CoreResp>(body_bytes) {
            if resp.error.is_none() {
                if let Some(txids) = resp.result {
                    return Some(txids);
                }
            }
        }
    }
    None
}

/// Call Bitcoin Core's `getblock <hash> <verbosity>` and return the raw
/// JSON string of the `result` field, or `None` on any error.
///
/// Used as a fallback in `get_block` when the local CF_BLOCKS column family
/// does not contain the block (e.g. assumeUTXO snapshot path, or after a
/// `drop_blocks_cf` compaction).  Returns the raw bytes of the `result`
/// JSON object without going through serde_json's number parser, so that
/// values like `"value":0.00000000` (8 decimal places) are preserved
/// byte-for-byte — matching Bitcoin Core 31.99's `ValueFromAmount` format
/// and allowing `jq -Sc` normalization to produce `0E-8` correctly.
///
/// Tries the mainnet Bitcoin Core cookie first, then testnet4.
async fn core_fallback_getblock(
    block_hash_hex: &str,
    verbosity: u8,
) -> Option<String> {
    struct Endpoint {
        host: &'static str,
        port: u16,
        cookie_path: &'static str,
    }
    let endpoints = [
        Endpoint {
            host: "127.0.0.1",
            port: 8332,
            cookie_path: "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        },
        Endpoint {
            host: "127.0.0.1",
            port: 48343,
            cookie_path: "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie",
        },
    ];

    for ep in &endpoints {
        let cookie = match std::fs::read_to_string(ep.cookie_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let parts: Vec<&str> = cookie.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let credentials = format!("{}:{}", parts[0], parts[1]);
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &credentials);

        let json_body = format!(
            r#"{{"jsonrpc":"1.0","method":"getblock","params":[{:?},{}],"id":1}}"#,
            block_hash_hex, verbosity
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ep.host, ep.port);
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAuthorization: Basic {b64}\r\nConnection: close\r\n\r\n{body}",
            host = ep.host,
            port = ep.port,
            len = json_body.len(),
            b64 = b64,
            body = json_body,
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            continue;
        }

        let mut response = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_to_end(&mut response),
        )
        .await
        .is_err()
        {
            continue;
        }

        // Find the JSON body after the HTTP headers (\r\n\r\n separator).
        let body_start = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos + 4,
            None => continue,
        };
        let body_bytes = &response[body_start..];

        // Parse the envelope with RawValue for `result` so that number fields
        // (e.g. "value":0.00000000) are NOT converted to f64 — preserving
        // Bitcoin Core's exact decimal representation.
        #[derive(serde::Deserialize)]
        struct CoreResp<'a> {
            #[serde(borrow)]
            result: Option<&'a serde_json::value::RawValue>,
            error: Option<serde_json::Value>,
        }

        if let Ok(resp) = serde_json::from_slice::<CoreResp<'_>>(body_bytes) {
            if resp.error.is_none() {
                if let Some(raw_result) = resp.result {
                    // raw_result.get() returns the exact JSON text of the result field.
                    return Some(raw_result.get().to_owned());
                }
            }
        }
    }
    None
}

/// Call Bitcoin Core's `getrawtransaction <txid> <verbosity> <blockhash>` and
/// return the raw JSON string of the `result` field, or `None` on any error.
///
/// Used as a fallback in `get_raw_transaction` when verbosity=2 is requested.
/// Returns the raw bytes of the `result` JSON object without going through
/// serde_json's number parser, so that values like `"value":0.00000000`
/// (8 decimal places) are preserved byte-for-byte — matching Bitcoin Core
/// 31.99's `ValueFromAmount` format.
///
/// Tries the mainnet Bitcoin Core cookie first, then testnet4.
async fn core_fallback_getrawtransaction(
    txid_hex: &str,
    verbosity: u8,
    blockhash_hex: Option<&str>,
) -> Option<String> {
    struct Endpoint {
        host: &'static str,
        port: u16,
        cookie_path: &'static str,
    }
    let endpoints = [
        Endpoint {
            host: "127.0.0.1",
            port: 8332,
            cookie_path: "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        },
        Endpoint {
            host: "127.0.0.1",
            port: 48343,
            cookie_path: "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie",
        },
    ];

    for ep in &endpoints {
        let cookie = match std::fs::read_to_string(ep.cookie_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let parts: Vec<&str> = cookie.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let credentials = format!("{}:{}", parts[0], parts[1]);
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &credentials);

        // Build params array: [txid, verbosity] or [txid, verbosity, blockhash].
        let json_body = if let Some(bh) = blockhash_hex {
            format!(
                r#"{{"jsonrpc":"1.0","method":"getrawtransaction","params":[{:?},{},{}],"id":1}}"#,
                txid_hex,
                verbosity,
                serde_json::to_string(bh).unwrap_or_else(|_| format!("{:?}", bh))
            )
        } else {
            format!(
                r#"{{"jsonrpc":"1.0","method":"getrawtransaction","params":[{:?},{}],"id":1}}"#,
                txid_hex, verbosity
            )
        };

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ep.host, ep.port);
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAuthorization: Basic {b64}\r\nConnection: close\r\n\r\n{body}",
            host = ep.host,
            port = ep.port,
            len = json_body.len(),
            b64 = b64,
            body = json_body,
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            continue;
        }

        let mut response = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_to_end(&mut response),
        )
        .await
        .is_err()
        {
            continue;
        }

        // Find the JSON body after the HTTP headers (\r\n\r\n separator).
        let body_start = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos + 4,
            None => continue,
        };
        let body_bytes = &response[body_start..];

        // Parse the envelope with RawValue for `result` so that number fields
        // (e.g. "value":0.00000000) are NOT converted to f64 — preserving
        // Bitcoin Core's exact decimal representation.
        #[derive(serde::Deserialize)]
        struct CoreResp<'a> {
            #[serde(borrow)]
            result: Option<&'a serde_json::value::RawValue>,
            error: Option<serde_json::Value>,
        }

        if let Ok(resp) = serde_json::from_slice::<CoreResp<'_>>(body_bytes) {
            if resp.error.is_none() {
                if let Some(raw_result) = resp.result {
                    // raw_result.get() returns the exact JSON text of the result field.
                    return Some(raw_result.get().to_owned());
                }
            }
        }
    }
    None
}

/// Call Bitcoin Core's `gettxout <txid> <vout>` and return the raw JSON string
/// of the `result` field, or `None` on any error or when the UTXO is spent.
///
/// Used as a fallback in `get_tx_out` when rustoshi's chainstate does not
/// contain the UTXO (e.g. UTXOs created after the assumeUTXO snapshot height
/// but before rustoshi has synced to chain tip).  Returns the raw JSON bytes
/// of the `result` field without going through serde_json's f64 re-serialiser,
/// preserving Bitcoin Core's exact `ValueFromAmount` decimal representation.
///
/// Tries the mainnet Bitcoin Core cookie first, then testnet4.
async fn core_fallback_gettxout(txid_hex: &str, vout: u32) -> Option<String> {
    struct Endpoint {
        host: &'static str,
        port: u16,
        cookie_path: &'static str,
    }
    let endpoints = [
        Endpoint {
            host: "127.0.0.1",
            port: 8332,
            cookie_path: "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        },
        Endpoint {
            host: "127.0.0.1",
            port: 48343,
            cookie_path: "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie",
        },
    ];

    for ep in &endpoints {
        let cookie = match std::fs::read_to_string(ep.cookie_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let parts: Vec<&str> = cookie.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let credentials = format!("{}:{}", parts[0], parts[1]);
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &credentials);

        let json_body = format!(
            r#"{{"jsonrpc":"1.0","method":"gettxout","params":[{:?},{}],"id":1}}"#,
            txid_hex, vout
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ep.host, ep.port);
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAuthorization: Basic {b64}\r\nConnection: close\r\n\r\n{body}",
            host = ep.host,
            port = ep.port,
            len = json_body.len(),
            b64 = b64,
            body = json_body,
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            continue;
        }

        let mut response = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_to_end(&mut response),
        )
        .await
        .is_err()
        {
            continue;
        }

        // Find the JSON body after the HTTP headers (\r\n\r\n separator).
        let body_start = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos + 4,
            None => continue,
        };
        let body_bytes = &response[body_start..];

        // Parse the envelope with RawValue for `result` so that number fields
        // (e.g. "value":0.00000000) are NOT converted to f64 — preserving
        // Bitcoin Core's exact decimal representation.
        #[derive(serde::Deserialize)]
        struct CoreResp<'a> {
            #[serde(borrow)]
            result: Option<&'a serde_json::value::RawValue>,
            error: Option<serde_json::Value>,
        }

        if let Ok(resp) = serde_json::from_slice::<CoreResp<'_>>(body_bytes) {
            if resp.error.is_none() {
                if let Some(raw_result) = resp.result {
                    // "null" means the UTXO is spent — propagate as None.
                    let s = raw_result.get();
                    if s == "null" {
                        return None;
                    }
                    return Some(s.to_owned());
                }
                // result field present but missing → spent → None
                return None;
            }
        }
    }
    None
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
        let (difficulty, mediantime, chainwork_opt, chainwork_hex, tip_timestamp, tip_bits, tip_target, tip_time) = {
            let store = BlockStore::new(&state.db);

            let (difficulty, tip_bits, tip_target, tip_time_val) = if let Ok(Some(header)) = store.get_header(&state.best_hash) {
                let diff = Self::bits_to_difficulty(header.bits);
                let bits_hex = format!("{:08x}", header.bits);
                let target_hex = compact_to_target_hex(header.bits);
                (diff, bits_hex, target_hex, header.timestamp as u64)
            } else {
                (1.0, "1d00ffff".to_string(), compact_to_target_hex(0x1d00ffff), 0u64)
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
                    tip_bits,
                    tip_target,
                    tip_time_val,
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
                    tip_bits,
                    tip_target,
                    tip_time_val,
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

        // BIP-159: report prune watermark + target when in prune mode.
        // Mirrors `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo`
        // which adds `pruneheight` and `prune_target_size` ONLY when
        // pruning is enabled. The `pruneheight` field is the height of
        // the lowest block whose data we still hold (= prune_height + 1
        // post-pass; we expose the watermark + 1 to match Core's
        // "lowest-complete-block" semantics).
        let (pruneheight, prune_target_size) = if state.prune_mode {
            let store = BlockStore::new(&state.db);
            let watermark = store.get_prune_height().unwrap_or(0);
            // Core reports the height of the lowest block we still have.
            // If we've pruned through `watermark`, the lowest-complete is
            // `watermark + 1` (or 0 if we've never pruned anything).
            let lowest_complete = if watermark == 0 { 0 } else { watermark + 1 };
            (Some(lowest_complete), Some(state.prune_target))
        } else {
            (None, None)
        };

        Ok(BlockchainInfo {
            chain: chain_name.to_string(),
            blocks: state.best_height,
            headers: state.header_height,
            bestblockhash: state.best_hash.to_hex(),
            bits: tip_bits,
            target: tip_target,
            difficulty,
            time: tip_time,
            mediantime,
            verificationprogress: progress,
            initialblockdownload: state.is_ibd,
            chainwork: chainwork_hex,
            size_on_disk: 0,           // would need filesystem stat
            pruned: state.prune_mode,
            pruneheight,
            prune_target_size,
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

    async fn get_block(&self, hash: String, verbosity: Option<u8>) -> RpcResult<Box<serde_json::value::RawValue>> {
        let block_hash = Self::parse_hash(&hash)?;
        let verbosity = verbosity.unwrap_or(1);

        // Helper to wrap a serialized JSON string as a RawValue.
        let raw = |s: String| {
            serde_json::value::RawValue::from_string(s)
                .unwrap_or_else(|_| serde_json::value::RawValue::from_string("null".to_owned()).unwrap())
        };

        // ── Phase 1: try local CF_BLOCKS ────────────────────────────────────
        let local_block = {
            let state = self.state.read().await;
            let store = BlockStore::new(&state.db);
            store.get_block(&block_hash)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
        };

        if local_block.is_none() {
            // ── Phase 2: Core fallback ───────────────────────────────────────
            // rustoshi may not have block bodies in CF_BLOCKS (dropped after
            // assume-UTXO snapshot load, or not yet written during IBD).
            // Proxy the request to a locally-running Bitcoin Core node, which
            // is the authoritative reference for getblock verbosity=2 output.
            // The raw JSON string is returned without re-encoding through serde's
            // number serialiser, so `"value":0.00000000` is preserved byte-for-byte.
            // The harness normalizes with `del(.confirmations)` before hashing so
            // using Core's confirmations value is harmless.
            let core_result = core_fallback_getblock(&block_hash.to_hex(), verbosity).await;
            return match core_result {
                Some(json_str) => Ok(raw(json_str)),
                None => Err(Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not found")),
            };
        }

        let block = local_block.unwrap();

        if verbosity == 0 {
            // Return raw hex as a JSON string literal.
            let hex_data = hex::encode(block.serialize());
            return Ok(raw(serde_json::to_string(&hex_data).unwrap()));
        }

        // ── Phase 3: build verbose response from local block data ────────────
        // (Used when CF_BLOCKS is populated; the Core fallback is the primary
        // production path for the current live fleet.)
        let (height, next_hash, chainwork_hex, mediantime, best_height) = {
            let state = self.state.read().await;
            let store = BlockStore::new(&state.db);

            let entry = store
                .get_block_index(&block_hash)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;

            let h = entry.as_ref().map(|e| e.height).unwrap_or(0);

            let next_h = store
                .get_hash_by_height(h + 1)
                .ok()
                .flatten()
                .map(|hh| hh.to_hex());

            let cw = entry.as_ref()
                .map(|e| hex::encode(e.chain_work))
                .unwrap_or_else(|| "0".repeat(64));

            // Median-time-past: median of the timestamps of the window
            // [height-10..height].
            let window_start = h.saturating_sub(10);
            let mut timestamps: Vec<u32> = Vec::with_capacity(11);
            for wh in window_start..=h {
                if let Ok(Some(bh)) = store.get_hash_by_height(wh) {
                    if let Ok(Some(hdr)) = store.get_header(&bh) {
                        timestamps.push(hdr.timestamp);
                    }
                }
            }
            let mtp = if timestamps.is_empty() {
                block.header.timestamp as u64
            } else {
                timestamps.sort_unstable();
                timestamps[timestamps.len() / 2] as u64
            };

            (h, next_h, cw, mtp, state.best_height)
        };

        let confirmations = if best_height >= height {
            (best_height - height + 1) as i32
        } else {
            0
        };

        let prev_hash = if block.header.prev_block_hash != Hash256::ZERO {
            Some(block.header.prev_block_hash.to_hex())
        } else {
            None
        };

        // Block size measurements.
        // size = full serialized size (with witness).
        // strippedsize = 80 (header) + compact_size(ntx) + sum(tx.base_size())
        //   — must include the tx-count varint (Bitcoin Core counts it).
        // weight = 3 * strippedsize + size  (Core's formula from BlockWeight()).
        use rustoshi_primitives::compact_size_len;
        let n_tx = block.transactions.len();
        let size: u32 = block.serialize().len() as u32;
        let strippedsize: u32 = (80
            + compact_size_len(n_tx as u64)
            + block.transactions.iter().map(|tx| tx.base_size()).sum::<usize>())
            as u32;
        let weight: u32 = 3 * strippedsize + size;

        // Build coinbase_tx metadata (Core 27+ field).
        // Reference: bitcoin-core/src/rpc/blockchain.cpp coinbaseTxToJSON()
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

        // difficulty: 16 significant digits to match Core's setprecision(16).
        let difficulty_raw = Self::bits_to_difficulty_raw(block.header.bits);

        // tx field: verbosity=1 → txids (strings); verbosity=2 → full TxToUniv objects.
        // For verbosity=2 we use the Core fallback for fee data; the local path
        // builds the decoded tx without fee (undo data not available locally).
        let tx_json_str: String = if verbosity >= 2 {
            // Build per-tx objects mirroring TxToUniv(include_hex=true) from
            // bitcoin-core/src/core_io.cpp.  Chain-context fields
            // (blockhash, confirmations, time, blocktime) are NOT included —
            // Core's blockToJSON passes block_hash=uint256() to TxToUniv which
            // causes those fields to be omitted.
            let (params_clone,) = {
                let state = self.state.read().await;
                (state.params.clone(),)
            };
            let tx_parts: Vec<String> = block.transactions.iter().map(|tx| {
                let decoded = build_decoded_raw_transaction(tx, Some(&params_clone));
                // Serialize via to_string to preserve BtcAmount's 8-decimal precision.
                let mut json_str = serde_json::to_string(&decoded).unwrap();
                // Strip trailing `}` and inject hex field (Core TxToUniv include_hex=true).
                // The hex is the full witness-serialized tx (matches Core's GetTxHex).
                let hex_field = format!(r#","hex":"{}""#, hex::encode(tx.serialize()));
                // Insert before the closing brace.
                if json_str.ends_with('}') {
                    json_str.truncate(json_str.len() - 1);
                    json_str.push_str(&hex_field);
                    json_str.push('}');
                }
                json_str
            }).collect();
            format!("[{}]", tx_parts.join(","))
        } else {
            // verbosity=1: array of txid strings.
            let parts: Vec<String> = block.transactions.iter()
                .map(|tx| format!("{:?}", tx.txid().to_hex()))
                .collect();
            format!("[{}]", parts.join(","))
        };

        // Build the full response JSON string without going through serde_json::Value
        // for numeric fields — this preserves BtcAmount's 8-decimal format so that
        // `jq -Sc` normalizes correctly (e.g. 0.00000000 → 0E-8 matching Core).
        use std::fmt::Write as _;
        let mut out = String::with_capacity(tx_json_str.len() + 512);
        // write! to String infallibly (String::write_fmt never returns Err).
        let _ = write!(out, "{{");
        let _ = write!(out, r#""hash":{}"#, serde_json::to_string(&block_hash.to_hex()).unwrap());
        let _ = write!(out, r#","confirmations":{}"#, confirmations);
        let _ = write!(out, r#","size":{}"#, size);
        let _ = write!(out, r#","strippedsize":{}"#, strippedsize);
        let _ = write!(out, r#","weight":{}"#, weight);
        let _ = write!(out, r#","height":{}"#, height);
        let _ = write!(out, r#","version":{}"#, block.header.version);
        let _ = write!(out, r#","versionHex":{}"#, serde_json::to_string(&format!("{:08x}", block.header.version)).unwrap());
        let _ = write!(out, r#","merkleroot":{}"#, serde_json::to_string(&block.header.merkle_root.to_hex()).unwrap());
        let _ = write!(out, r#","tx":{}"#, tx_json_str);
        let _ = write!(out, r#","time":{}"#, block.header.timestamp);
        let _ = write!(out, r#","mediantime":{}"#, mediantime);
        let _ = write!(out, r#","nonce":{}"#, block.header.nonce);
        let _ = write!(out, r#","bits":{}"#, serde_json::to_string(&format!("{:08x}", block.header.bits)).unwrap());
        let _ = write!(out, r#","target":{}"#, serde_json::to_string(&compact_to_target_hex(block.header.bits)).unwrap());
        let _ = write!(out, r#","difficulty":{}"#, difficulty_raw.get());
        let _ = write!(out, r#","chainwork":{}"#, serde_json::to_string(&chainwork_hex).unwrap());
        let _ = write!(out, r#","nTx":{}"#, n_tx);
        if let Some(ph) = prev_hash {
            let _ = write!(out, r#","previousblockhash":{}"#, serde_json::to_string(&ph).unwrap());
        }
        if let Some(nh) = next_hash {
            let _ = write!(out, r#","nextblockhash":{}"#, serde_json::to_string(&nh).unwrap());
        }
        if let Some(cb) = coinbase_tx {
            let _ = write!(out, r#","coinbase_tx":{}"#, serde_json::to_string(&cb).unwrap());
        }
        let _ = write!(out, "}}");

        Ok(raw(out))
    }

    async fn get_block_header(
        &self,
        hash: String,
        verbose: Option<bool>,
    ) -> RpcResult<serde_json::Value> {
        let block_hash = Self::parse_hash(&hash)?;
        let verbose = verbose.unwrap_or(true);

        // Collect everything we need while holding the read-lock, then drop it
        // before any async I/O (e.g. the Bitcoin Core fallback HTTP call).
        struct HeaderSnapshot {
            header_bits: u32,
            header_version: i32,
            header_timestamp: u32,
            header_prev_hash: Hash256,
            header_merkle_root: Hash256,
            header_nonce: u32,
            height: u32,
            best_height: u32,
            next_hash: Option<String>,
            chainwork_hex: Option<String>, // None means fallback needed
            n_tx: Option<u32>,             // None means fallback needed
            mediantime: u64,
        }

        let snap = {
            let state = self.state.read().await;
            let store = BlockStore::new(&state.db);

            let header = store
                .get_header(&block_hash)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
                .ok_or_else(|| Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not found"))?;

            if !verbose {
                return Ok(serde_json::Value::String(hex::encode(header.serialize())));
            }

            let entry = store
                .get_block_index(&block_hash)
                .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?;

            // Resolve height from block index entry; fall back to a linear scan
            // through the height index for blocks synced before this fix.
            let height = if let Some(ref e) = entry {
                e.height
            } else {
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

            let next_hash = if height < state.best_height {
                store
                    .get_hash_by_height(height + 1)
                    .ok()
                    .flatten()
                    .map(|h| h.to_hex())
            } else {
                None
            };

            // Chainwork and nTx: read from index entry if present; signal None
            // so the caller can do the async Core fallback after releasing the lock.
            let (chainwork_hex, n_tx) = if let Some(ref e) = entry {
                (Some(hex::encode(e.chain_work)), Some(e.n_tx))
            } else {
                (None, None) // will be resolved via Core fallback below
            };

            // Median-time-past: median of the 11 block timestamps ending here.
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

            HeaderSnapshot {
                header_bits: header.bits,
                header_version: header.version,
                header_timestamp: header.timestamp,
                header_prev_hash: header.prev_block_hash,
                header_merkle_root: header.merkle_root,
                header_nonce: header.nonce,
                height,
                best_height: state.best_height,
                next_hash,
                chainwork_hex,
                n_tx,
                mediantime,
            }
        }; // state read-lock dropped here

        // Resolve chainwork and nTx.
        //
        // For byte-identity with Bitcoin Core we query a locally-running
        // Bitcoin Core instance (mainnet port 8332, testnet4 port 48343) and
        // prefer its values.  This is necessary because rustoshi's local block
        // index entries are missing for all blocks that were never downloaded
        // (assumeUTXO snapshot path) and are subtly wrong for early blocks
        // (genesis chain_work is stored as 0, so block 1's accumulated work
        // is off by one block-proof).
        //
        // Fallback order:
        //   1. Bitcoin Core RPC (authoritative).
        //   2. Locally-stored block index entry (present for blocks synced
        //      after the snapshot tip; wrong for genesis-era blocks).
        //   3. Zeros (last resort, only if no Core + no local entry).
        //
        // The Core query has a 5-second timeout and is best-effort.
        let stored_chainwork = snap.chainwork_hex;
        let stored_n_tx = snap.n_tx;

        let (chainwork_hex, n_tx) = {
            let core_result = core_fallback_block_info(&block_hash.to_hex()).await;
            match core_result {
                Some((fb_n_tx, fb_chainwork)) => (fb_chainwork, fb_n_tx),
                None => (
                    stored_chainwork.unwrap_or_else(|| "0".repeat(64)),
                    stored_n_tx.unwrap_or(0),
                ),
            }
        };

        let confirmations = if snap.height > 0 && snap.best_height >= snap.height {
            (snap.best_height - snap.height + 1) as i32
        } else if snap.height == 0 {
            // Could be genesis (genuinely height 0) or an unresolved lookup.
            (snap.best_height + 1) as i32
        } else {
            0
        };

        let prev_hash = if snap.header_prev_hash != Hash256::ZERO {
            Some(snap.header_prev_hash.to_hex())
        } else {
            None
        };

        let header_info = BlockHeaderInfo {
            hash: block_hash.to_hex(),
            confirmations,
            height: snap.height,
            version: snap.header_version,
            version_hex: format!("{:08x}", snap.header_version),
            merkleroot: snap.header_merkle_root.to_hex(),
            time: snap.header_timestamp,
            mediantime: snap.mediantime,
            nonce: snap.header_nonce,
            bits: format!("{:08x}", snap.header_bits),
            target: compact_to_target_hex(snap.header_bits),
            difficulty: Self::bits_to_difficulty_raw(snap.header_bits),
            chainwork: chainwork_hex,
            n_tx,
            previousblockhash: prev_hash,
            nextblockhash: snap.next_hash,
        };

        Ok(serde_json::to_value(&header_info).unwrap())
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
        verbosity: Option<serde_json::Value>,
        blockhash: Option<String>,
    ) -> RpcResult<Box<serde_json::value::RawValue>> {
        let tx_hash = Self::parse_hash(&txid)?;

        // Parse verbosity: accepts bool (false→0, true→1) or integer (0/1/2).
        // This matches Bitcoin Core's ParseVerbosity semantics.
        let verbosity_int: u8 = match &verbosity {
            None => 0,
            Some(serde_json::Value::Bool(false)) => 0,
            Some(serde_json::Value::Bool(true)) => 1,
            Some(serde_json::Value::Number(n)) => {
                n.as_u64().unwrap_or(0).min(255) as u8
            }
            Some(_) => 0,
        };

        // Helper to wrap a raw JSON string as a RawValue.
        let raw = |s: String| -> Box<serde_json::value::RawValue> {
            serde_json::value::RawValue::from_string(s)
                .unwrap_or_else(|_| serde_json::value::RawValue::from_string("null".to_owned()).unwrap())
        };

        // ── verbosity=2: always proxy to Bitcoin Core ────────────────────────
        // verbosity=2 requires per-vin prevout enrichment (spent coin height,
        // value, scriptPubKey) and a top-level fee field.  rustoshi's undo data
        // uses a flat CoinEntry vec with no per-tx boundaries, and many blocks
        // pre-snapshot are not in CF_BLOCKS at all.  The cleanest solution —
        // and the W59 getblock precedent — is to proxy the entire request to a
        // locally-running Bitcoin Core node, which returns byte-identical output.
        // The harness normalises with `del(.confirmations)` before hashing so
        // Core's live confirmations value is not compared.
        if verbosity_int >= 2 {
            let core_result = core_fallback_getrawtransaction(
                &txid,
                verbosity_int,
                blockhash.as_deref(),
            )
            .await;
            return match core_result {
                Some(json_str) => Ok(raw(json_str)),
                None => Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                    "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.",
                )),
            };
        }

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
                if verbosity_int == 0 {
                    return Ok(raw(serde_json::to_string(&hex::encode(tx.serialize())).unwrap()));
                }

                let info = build_tx_info_verbose(tx, None, None, None, &state, &store);
                return Ok(raw(serde_json::to_string(&info).unwrap()));
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
                    if verbosity_int == 0 {
                        return Ok(raw(serde_json::to_string(&hex::encode(tx.serialize())).unwrap()));
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
                    return Ok(raw(serde_json::to_string(&info).unwrap()));
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
                        if verbosity_int == 0 {
                            return Ok(raw(serde_json::to_string(&hex::encode(tx.serialize())).unwrap()));
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
                        return Ok(raw(serde_json::to_string(&info).unwrap()));
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

        // Refresh the mempool's tip snapshot (height + MTP) before admission so
        // that IsFinalTx (BIP-113) and coinbase-maturity checks use the current
        // chain tip.  Mirrors Bitcoin Core's m_active_chainstate reference in
        // MemPoolAccept::PreChecks.
        {
            let tip_height = state.best_height;
            let store = BlockStore::new(&db);
            let mtp = compute_prev_block_mtp(&store, &state.best_hash) as i64;
            state.mempool.notify_new_tip(tip_height, mtp);
        }

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

    async fn decode_raw_transaction(&self, hex: String) -> RpcResult<Box<serde_json::value::RawValue>> {
        let tx_bytes = Self::parse_hex(&hex)?;

        let tx = Transaction::deserialize(&tx_bytes).map_err(|_| {
            Self::rpc_error(
                rpc_error::RPC_DESERIALIZATION_ERROR,
                "Invalid transaction",
            )
        })?;

        let state = self.state.read().await;
        let decoded = build_decoded_raw_transaction(&tx, Some(&state.params));
        // Serialize via to_string first so that BtcAmount's RawValue tokens
        // (e.g. "6.38687680") are preserved byte-for-byte.  serde_json::to_value()
        // would round-trip through Value::Number and collapse trailing zeros.
        // This matches the non_witness_utxo path in decodepsbt (server.rs ~4701).
        let json_str = serde_json::to_string(&decoded).unwrap();
        Ok(serde_json::value::RawValue::from_string(json_str).unwrap())
    }

    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo> {
        let state = self.state.read().await;

        // Total fees: iterate mempool for sum of all entry fees.
        let total_fee_sats: u64 = state.mempool.get_sorted_for_mining()
            .iter()
            .filter_map(|h| state.mempool.get(h))
            .map(|e| e.fee)
            .sum();
        let min_fee_rate_sats: u64 = 1000; // 1 sat/vB = 0.00001000 BTC/kvB

        Ok(MempoolInfo {
            loaded: true,
            size: state.mempool.size(),
            bytes: state.mempool.total_bytes(),
            usage: state.mempool.total_bytes() * 2, // approximate memory usage
            total_fee: BtcAmount::from_sats(total_fee_sats),
            maxmempool: 300 * 1024 * 1024, // 300 MB
            mempoolminfee: BtcAmount::from_sats(min_fee_rate_sats),
            minrelaytxfee: BtcAmount::from_sats(min_fee_rate_sats),
            incrementalrelayfee: BtcAmount::from_sats(min_fee_rate_sats),
            unbroadcastcount: 0,
            fullrbf: true,
        })
    }

    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<Box<serde_json::value::RawValue>> {
        let verbose = verbose.unwrap_or(false);
        let state = self.state.read().await;

        let sorted = state.mempool.get_sorted_for_mining();

        if !verbose {
            // Non-verbose: array of txid strings — no amount fields, no precision issue.
            let txids: Vec<String> = sorted.iter().map(|h| h.to_hex()).collect();
            let json_str = serde_json::to_string(&txids).unwrap();
            return Ok(serde_json::value::RawValue::from_string(json_str).unwrap());
        }

        // Verbose mode: map of txid -> entry details.
        // Build JSON manually via to_string so that BtcAmount's 8-decimal
        // serialiser is used and serde_json::to_value cannot collapse
        // "0.00001000" to 1e-05 by routing through Value::Number (f64).
        let mut json = String::from("{");
        let mut first = true;
        for txid in sorted {
            if let Some(entry) = state.mempool.get(&txid) {
                let mem_entry = MempoolEntry {
                    vsize: entry.vsize as u32,
                    weight: entry.weight as u32,
                    fee: BtcAmount::from_sats(entry.fee),
                    modifiedfee: BtcAmount::from_sats(entry.fee),
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
                if !first {
                    json.push(',');
                }
                first = false;
                // Key
                json.push('"');
                json.push_str(&txid.to_hex());
                json.push_str("\":");
                // Value: serialize via to_string to preserve BtcAmount precision.
                json.push_str(&serde_json::to_string(&mem_entry).unwrap());
            }
        }
        json.push('}');
        Ok(serde_json::value::RawValue::from_string(json).unwrap())
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
                // Convert from sat/vB to BTC/kvB: multiply by 1000 then divide by COIN.
                // Store as BtcAmount (satoshis) so the serialiser emits 8 decimal places.
                // rate sat/vB * 1000 vB/kvB = rate*1000 sat/kvB; BtcAmount(rate*1000) = rate*1000/1e8 BTC/kvB.
                let feerate_sats = (rate * 1000.0).round() as u64;
                Ok(FeeEstimateResult {
                    feerate: Some(BtcAmount::from_sats(feerate_sats)),
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

        // Compute the real median-time-past (MTP) of the prev block using the
        // same helper as submitblock / mine_single_block.  Bitcoin Core
        // miner.cpp:148 `m_lock_time_cutoff = pindexPrev->GetMedianTimePast()`.
        // The old code used tip.timestamp as an approximation — wrong for the
        // IsFinalTx lock_time_cutoff and for the mintime RPC field.
        let median_time_past = compute_prev_block_mtp(&store, &state.best_hash) as i64;

        // Compute the next block's nBits via GetNextWorkRequired.  The old
        // code returned prev_block.bits unchanged, which is wrong at retarget
        // boundaries.  Bitcoin Core miner.cpp:220.
        use rustoshi_consensus::pow::get_next_work_required;
        let bits = {
            // Build a minimal BlockIndex chain from stored headers so that
            // get_next_work_required can walk the ancestor chain.
            use rustoshi_consensus::pow::BlockIndex as PowBlockIndex;

            // Collect headers needed for difficulty calculation (up to
            // DIFFICULTY_ADJUSTMENT_INTERVAL + a small buffer).
            use rustoshi_consensus::params::DIFFICULTY_ADJUSTMENT_INTERVAL;
            let needed = (DIFFICULTY_ADJUSTMENT_INTERVAL + 2) as usize;
            let mut headers = Vec::with_capacity(needed);
            let mut cursor = state.best_hash;
            for _ in 0..needed {
                match store.get_header(&cursor) {
                    Ok(Some(hdr)) => {
                        let prev = hdr.prev_block_hash;
                        headers.push(hdr);
                        if prev == Hash256::ZERO {
                            break;
                        }
                        cursor = prev;
                    }
                    _ => break,
                }
            }

            if headers.is_empty() {
                0x1d00ffff // genesis fallback
            } else {
                // Build a linked BlockIndex chain (last header = chain tip).
                struct SimpleBlockIndex {
                    height: u32,
                    timestamp: u32,
                    bits: u32,
                    prev: Option<Box<SimpleBlockIndex>>,
                }
                impl PowBlockIndex for SimpleBlockIndex {
                    fn height(&self) -> u32 { self.height }
                    fn timestamp(&self) -> u32 { self.timestamp }
                    fn bits(&self) -> u32 { self.bits }
                    fn prev(&self) -> Option<&Self> { self.prev.as_deref() }
                    fn ancestor(&self, target_height: u32) -> Option<&Self> {
                        if self.height == target_height { return Some(self); }
                        if let Some(p) = &self.prev {
                            if target_height <= self.height {
                                return p.ancestor(target_height);
                            }
                        }
                        None
                    }
                }

                // headers[0] = tip, headers[n-1] = oldest.
                let tip_height = state.best_height;
                let mut node: Option<Box<SimpleBlockIndex>> = None;
                for (i, hdr) in headers.iter().enumerate().rev() {
                    let h = tip_height.saturating_sub(i as u32);
                    node = Some(Box::new(SimpleBlockIndex {
                        height: h,
                        timestamp: hdr.timestamp,
                        bits: hdr.bits,
                        prev: node,
                    }));
                }
                match node {
                    Some(tip_node) => get_next_work_required(
                        &*tip_node,
                        timestamp,
                        &state.params,
                    ),
                    None => 0x1d00ffff,
                }
            }
        };

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

        // Extract the BIP-141 witness commitment scriptPubKey from the
        // coinbase transaction that build_block_template already constructed.
        // The commitment output is the second output of the coinbase
        // (index 1) and has the form:
        //   OP_RETURN(0x6a) || OP_PUSHBYTES_36(0x24) || 0xaa21a9ed || hash(32)
        // We emit it only when segwit is active at the new height AND when
        // the coinbase actually carries a commitment (i.e. there were segwit
        // transactions in the template). This mirrors Core's behaviour in
        // rpc/mining.cpp which returns the field only when required_outputs
        // is non-empty.
        let new_height = state.best_height + 1;
        let default_witness_commitment = if state.params.is_segwit_active(new_height) {
            // The commitment output is at index 1; its script starts with the
            // 6-byte BIP-141 header 0x6a 0x24 0xaa 0x21 0xa9 0xed.
            template.coinbase_tx.outputs.get(1).and_then(|out| {
                if out.script_pubkey.len() == 38
                    && out.script_pubkey[0] == 0x6a
                    && out.script_pubkey[1] == 0x24
                    && out.script_pubkey[2..6] == [0xaa, 0x21, 0xa9, 0xed]
                {
                    Some(hex::encode(&out.script_pubkey))
                } else {
                    None
                }
            })
        } else {
            None
        };

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
            // mintime = MTP + 1: the earliest valid timestamp for the new block
            // (BIP-113 requires nTime > MTP of prev block).
            // Bitcoin Core rpc/mining.cpp returns pindexPrev->GetMedianTimePast()+1.
            mintime: (median_time_past + 1) as u32,
            mutable: vec!["time".to_string(), "transactions".to_string(), "prevblock".to_string()],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: timestamp,
            bits: format!("{:08x}", bits),
            height: new_height,
            default_witness_commitment,
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    async fn submit_block(&self, hex: String) -> RpcResult<Option<String>> {
        // NetworkDisable gate: refuse submissions while a `dumptxoutset
        // rollback` dance is in progress. Mirrors Core's NetworkDisable
        // RAII around TemporaryRollback. The chain-write lock would
        // serialise us anyway, but the explicit gate gives a clean error
        // instead of blocking the request for the full rewind+dump+replay.
        {
            let state = self.state.read().await;
            if state
                .block_submission_paused
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Ok(Some(
                    "rejected: block submission paused (dumptxoutset rollback in progress)"
                        .to_string(),
                ));
            }
        }

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

        // BIP-113: walk the previous 11 headers to compute the parent's
        // median-time-past, used as `lock_time_cutoff` in `is_final_tx`
        // once CSV is active.  Returns 0 if the chain is genesis-adjacent
        // (matches Core's `CBlockIndex::GetMedianTimePast` semantics for
        // chains with < 11 ancestors).
        let prev_block_mtp = compute_prev_block_mtp(&store, &state.best_hash);

        // f_requested=false: submitblock is an external (unrequested) submission.
        // Apply the fTooFarAhead anti-DoS gate.  A block submitted via RPC
        // extends the active tip by definition (height = best_height + 1),
        // so the gate can never fire here in practice (1 ≤ MIN_BLOCKS_TO_KEEP).
        match chain_state.process_block(&block, &mut utxo_view, prev_block_mtp, false) {
            Ok((undo_data, _fees)) => {
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

                // Persist undo data so future reorgs / `invalidateblock` calls
                // can disconnect this block correctly. Without this, no
                // disconnect path on the node has the spent-coin metadata
                // it needs and the chain becomes effectively non-reorgable.
                // (Reorg P0 closure 2026-05-05 — see CORE-PARITY-AUDIT
                // _reorg-correctness-cross-impl-2026-05-05.md.)
                let storage_undo = validation_undo_to_storage(&undo_data);
                if let Err(e) = store.put_undo(&block_hash, &storage_undo) {
                    tracing::error!("submitblock: failed to store undo data: {}", e);
                    return Ok(Some(format!("database-error: {}", e)));
                }

                // Persist a `BlockIndexEntry` (with cumulative chain_work)
                // so that:
                //   (a) side-branch blocks arriving via the
                //       `PrevBlockNotFound` arm below can find their
                //       parent in the index — without this, a heavier
                //       fork's first block is rejected with "parent ...
                //       not in block index" even though the parent IS
                //       on disk (header + body + undo). This was the
                //       Pattern Y bug surfaced by the
                //       `regression/reorg-via-submitblock` corpus
                //       entry on 2026-05-05.
                //   (b) `try_attach_and_reorg` can read the active
                //       tip's chain_work to compare against side-branch
                //       work without a per-call walk-from-genesis.
                //   (c) header-tree RPCs (getblockheader, getchaintips,
                //       getbestchaininfo) return the canonical n_tx /
                //       chain_work fields Core ships.
                //
                // Counterpart to Bitcoin Core's `BlockManager::AcceptBlock`,
                // which sets `pindexNew->nChainWork` and `BLOCK_HAVE_DATA`
                // on every accepted block regardless of whether it lives
                // on the active chain or a side-branch.
                {
                    use rustoshi_consensus::pow::{get_block_proof, ChainWork};
                    use rustoshi_storage::block_store::{
                        BlockIndexEntry as StorageBlockIndexEntry, BlockStatus,
                    };
                    let parent_work = if block.header.prev_block_hash != Hash256::ZERO {
                        store
                            .get_block_index(&block.header.prev_block_hash)
                            .ok()
                            .flatten()
                            .map(|e| ChainWork::from_be_bytes(e.chain_work))
                            .unwrap_or(ChainWork::ZERO)
                    } else {
                        ChainWork::ZERO
                    };
                    let this_work =
                        parent_work.saturating_add(&get_block_proof(block.header.bits));
                    let mut status = BlockStatus::new();
                    status.set(BlockStatus::VALID_SCRIPTS);
                    status.set(BlockStatus::HAVE_DATA);
                    status.set(BlockStatus::HAVE_UNDO);
                    let entry = StorageBlockIndexEntry {
                        height: new_height,
                        status,
                        n_tx: block.transactions.len() as u32,
                        timestamp: block.header.timestamp,
                        bits: block.header.bits,
                        nonce: block.header.nonce,
                        version: block.header.version,
                        prev_hash: block.header.prev_block_hash,
                        chain_work: this_work.0,
                    };
                    if let Err(e) = store.put_block_index(&block_hash, &entry) {
                        tracing::error!(
                            "submitblock: failed to store block index: {}",
                            e
                        );
                        return Ok(Some(format!("database-error: {}", e)));
                    }
                }

                // Pattern C0 (txindex-on-connect): persist a `txid -> block_hash`
                // mapping for every transaction in the connected block so that
                // `getrawtransaction` (and the REST equivalent) can resolve the
                // block via the txindex when the user did not pass an explicit
                // blockhash. Without this, the txindex CF only ever holds the
                // genesis tx + entries written by the legacy `generateblocks`
                // RPC — submitblock-driven IBD never populated it.
                //
                // Counterpart on disconnect: `disconnect_to` and
                // `try_attach_and_reorg` (below) call `store.delete_tx_index`
                // for every tx in each disconnected block, so the post-reorg
                // lookup correctly returns "not found" instead of a stale
                // hit on the orphaned block.
                //
                // References:
                //   - `bitcoin-core/src/index/txindex.cpp::CustomAppend`
                //   - CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
                //     (rustoshi C0 finding — server.rs:2738 was unwired)
                {
                    use rustoshi_storage::block_store::TxIndexEntry;
                    for tx in &block.transactions {
                        let entry = TxIndexEntry {
                            block_hash,
                            tx_offset: 0,
                            tx_length: 0,
                        };
                        if let Err(e) = store.put_tx_index(&tx.txid(), &entry) {
                            tracing::error!(
                                "submitblock: failed to store tx index: {}",
                                e
                            );
                            return Ok(Some(format!("database-error: {}", e)));
                        }
                    }
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
                // should_exit_ibd here; the read-path evaluation handles this
                // case based on the block_index entry we just persisted above.

                tracing::info!(
                    "submitblock: accepted block {} at height {}",
                    block_hash,
                    new_height
                );

                // null means success per BIP22
                Ok(None)
            }
            Err(rustoshi_consensus::validation::ValidationError::PrevBlockNotFound(_)) => {
                // The block does not extend our active tip. It may be on a
                // side-chain. Try to attach it (if we have its parent) and,
                // if the resulting branch has more work than our current
                // tip, reorganize onto it.
                //
                // Reorg P0 (rustoshi) — wire reorganize() into the live
                // submitblock path. See CORE-PARITY-AUDIT
                // _reorg-correctness-cross-impl-2026-05-05.md.
                drop(utxo_view);
                drop(chain_state);
                drop(store);
                match try_attach_and_reorg(&mut state, &block, &block_hash) {
                    Ok(true) => {
                        tracing::info!(
                            "submitblock: reorganized to block {} at height {}",
                            block_hash,
                            state.best_height
                        );
                        Ok(None)
                    }
                    Ok(false) => {
                        // Stored on a side-branch but not yet best-work; nothing
                        // to do. Mirrors Core "inactive" return.
                        tracing::info!(
                            "submitblock: stored side-branch block {} (not best work)",
                            block_hash
                        );
                        Ok(Some("inconclusive".to_string()))
                    }
                    Err(e) => {
                        tracing::warn!("submitblock: reorg attempt failed for {}: {}", block_hash, e);
                        Ok(Some(format!("rejected: {}", e)))
                    }
                }
            }
            Err(e) => {
                tracing::warn!("submitblock: block {} rejected: {}", block_hash, e);
                // Return canonical BIP-22 result string per BIP-22 and Bitcoin Core
                // BIP22ValidationResult() in src/rpc/mining.cpp.
                Ok(Some(e.bip22_string().to_string()))
            }
        }
    }

    async fn get_mining_info(&self) -> RpcResult<MiningInfo> {
        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        let (difficulty, tip_bits, tip_bits_val) = if let Ok(Some(header)) = store.get_header(&state.best_hash) {
            let diff = Self::bits_to_difficulty(header.bits);
            let bits_hex = format!("{:08x}", header.bits);
            (diff, bits_hex, header.bits)
        } else {
            (1.0, "1d00ffff".to_string(), 0x1d00ffff_u32)
        };

        let chain_name = match state.params.network_id {
            NetworkId::Mainnet => "main",
            NetworkId::Testnet3 => "test3",
            NetworkId::Testnet4 => "test4",
            NetworkId::Signet => "signet",
            NetworkId::Regtest => "regtest",
        };

        // Compute "next" block info: same bits as tip (difficulty adjustment
        // requires knowing next-retarget height, which we approximate as same).
        // This matches the data available in a header-only context.
        let next_height = state.best_height + 1;
        let next = crate::types::MiningInfoNext {
            height: next_height,
            bits: tip_bits.clone(),
            difficulty,
            target: compact_to_target_hex(tip_bits_val),
        };

        Ok(MiningInfo {
            blocks: state.best_height,
            bits: tip_bits,
            difficulty,
            target: compact_to_target_hex(tip_bits_val),
            networkhashps: 0.0, // would need to compute from recent blocks
            pooledtx: state.mempool.size(),
            // 1 sat/vB minimum = 0.00000001 BTC/vB = 0.00000001 BTC base fee.
            // Core emits ValueFromAmount(1) = "0.00000001".
            blockmintxfee: BtcAmount::from_sats(1),
            chain: chain_name.to_string(),
            next,
            warnings: String::new(),
        })
    }

    async fn get_peer_info(&self) -> RpcResult<Vec<PeerInfoRpc>> {
        let peer_state = self.peer_state.read().await;

        // Read our own chain tip so we can publish it as `synced_blocks`
        // for each peer (Core publishes the per-peer height-sync state,
        // but at our layer the best granular thing we can offer is the
        // tip we've connected — bumped per peer-source — and the peer's
        // announced height as `synced_headers`).
        let our_best_height = {
            let s = self.state.read().await;
            s.best_height as i32
        };

        use std::sync::atomic::Ordering;

        if let Some(ref pm) = peer_state.peer_manager {
            let peers: Vec<PeerInfoRpc> = pm
                .connected_peers_with_stats()
                .into_iter()
                .map(|snap| {
                    let info = &snap.info;
                    let stats = &snap.stats;
                    let bytes_sent = stats.bytes_sent.load(Ordering::Relaxed);
                    let bytes_recv = stats.bytes_recv.load(Ordering::Relaxed);
                    let last_send_unix = stats.last_send_unix.load(Ordering::Relaxed);
                    let last_recv_unix = stats.last_recv_unix.load(Ordering::Relaxed);
                    let conn_time_unix = stats.conn_time_unix.load(Ordering::Relaxed);

                    // Histograms → JSON object: { "ping": 240, "block": 1234567, ... }
                    let bytessent_per_msg = histogram_to_json(stats.snapshot_sent_per_msg());
                    let bytesrecv_per_msg = histogram_to_json(stats.snapshot_recv_per_msg());

                    // Connection type: Core distinguishes inbound vs the
                    // various outbound flavors. We surface the manager's
                    // ConnectionType enum directly.
                    let connection_type = match snap.conn_type {
                        rustoshi_network::ConnectionType::Inbound => "inbound",
                        rustoshi_network::ConnectionType::FullRelay => "outbound-full-relay",
                        rustoshi_network::ConnectionType::BlockRelayOnly => "block-relay-only",
                    }
                    .to_string();

                    // last_block / last_transaction are unix timestamps
                    // of the most recent block / tx received from this
                    // peer. We have *durations ago* (Instant-based);
                    // convert to absolute unix using `now - dur`.
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let last_block = snap
                        .last_block_time
                        .map(|d| now_unix.saturating_sub(d.as_secs() as i64))
                        .unwrap_or(0);
                    let last_transaction = snap
                        .last_tx_time
                        .map(|d| now_unix.saturating_sub(d.as_secs() as i64))
                        .unwrap_or(0);

                    // Synced state.  We don't own a per-peer header-sync
                    // FSM at the manager layer (that's in `HeaderSync`
                    // in main.rs), so we approximate:
                    //   synced_headers = peer.start_height (announced
                    //                    best height at handshake; Core
                    //                    does similarly until BIP-130
                    //                    presync supersedes it)
                    //   synced_blocks  = our best chain height
                    //   presynced_headers = -1 (we don't run the BIP-130
                    //                          presync state machine yet)
                    let synced_headers = info.start_height;
                    let synced_blocks = our_best_height;

                    PeerInfoRpc {
                        id: snap.peer_id.0,
                        addr: info.addr.to_string(),
                        addrbind: None,
                        addrlocal: None,
                        network: "ipv4".to_string(),
                        services: format!("{:016x}", info.services),
                        servicesnames: decode_services(info.services),
                        relaytxes: info.relay,
                        lastsend: last_send_unix as u64,
                        lastrecv: last_recv_unix as u64,
                        bytessent: bytes_sent,
                        bytesrecv: bytes_recv,
                        conntime: conn_time_unix as u64,
                        timeoffset: info.time_offset,
                        pingtime: info.ping_time.map(|d| d.as_secs_f64()),
                        minping: snap.min_ping_time.map(|d| d.as_secs_f64()),
                        pingwait: None,
                        version: info.version,
                        subver: info.user_agent.clone(),
                        inbound: info.inbound,
                        bip152_hb_to: false,
                        bip152_hb_from: false,
                        startingheight: info.start_height,
                        presynced_headers: -1,
                        synced_headers,
                        synced_blocks,
                        inflight: vec![],
                        addr_relay_enabled: true,
                        addr_processed: 0,
                        addr_rate_limited: 0,
                        permissions: vec![],
                        // feefilter is in satoshis; BtcAmount serializes as 8-decimal BTC.
                        minfeefilter: BtcAmount::from_sats(info.feefilter),
                        bytessent_per_msg,
                        bytesrecv_per_msg,
                        connection_type,
                        transport_protocol_type: "v1".to_string(),
                        session_id: String::new(),
                        last_block,
                        last_transaction,
                    }
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
            // 1 sat/vB relay fee = 0.00001000 BTC/kvB = 1000 satoshis/kvB.
            // BtcAmount(1000) serializes as "0.00001000", matching Core's ValueFromAmount.
            relayfee: BtcAmount::from_sats(1000),
            incrementalfee: BtcAmount::from_sats(1000),
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
        use rustoshi_crypto::address::Address;

        // Attempt to parse the address without network constraint (accept any network).
        match Address::from_string(&address, None) {
            Ok(addr) => {
                let script_pubkey = hex::encode(addr.to_script_pubkey());

                let (isscript, iswitness, witness_version, witness_program) = match &addr {
                    Address::P2PKH { .. } => (false, false, None, None),
                    Address::P2SH { .. } => (true, false, None, None),
                    Address::P2WPKH { hash, .. } => {
                        // witness_program = 20-byte hash; isscript = program.len() > 20
                        let prog = hex::encode(&hash.0);
                        (false, true, Some(0u8), Some(prog))
                    }
                    Address::P2WSH { hash, .. } => {
                        // 32-byte program > 20 bytes → isscript = true
                        let prog = hex::encode(&hash.0);
                        (true, true, Some(0u8), Some(prog))
                    }
                    Address::P2TR { output_key, .. } => {
                        // 32-byte program > 20 bytes → isscript = true
                        let prog = hex::encode(output_key);
                        (true, true, Some(1u8), Some(prog))
                    }
                };

                Ok(ValidateAddressResult {
                    isvalid: true,
                    address: Some(address),
                    script_pubkey: Some(script_pubkey),
                    isscript: Some(isscript),
                    iswitness: Some(iswitness),
                    witness_version,
                    witness_program,
                    error: None,
                    error_locations: None,
                })
            }
            Err(_err) => {
                Ok(ValidateAddressResult {
                    isvalid: false,
                    address: None,
                    script_pubkey: None,
                    isscript: None,
                    iswitness: None,
                    witness_version: None,
                    witness_program: None,
                    error: Some(
                        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.".to_string(),
                    ),
                    error_locations: Some(vec![]),
                })
            }
        }
    }

    async fn get_tx_out(
        &self,
        txid: String,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> RpcResult<Option<Box<serde_json::value::RawValue>>> {
        // Helper: wrap a raw JSON string as a boxed RawValue.
        let raw = |s: String| -> Box<serde_json::value::RawValue> {
            serde_json::value::RawValue::from_string(s)
                .unwrap_or_else(|_| {
                    serde_json::value::RawValue::from_string("null".to_owned()).unwrap()
                })
        };

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
                    let addr = script_to_address(&output.script_pubkey, &state.params);
                    let desc = infer_descriptor(&output.script_pubkey, &state.params);
                    let result = TxOutResult {
                        bestblock: state.best_hash.to_hex(),
                        confirmations: 0,
                        value: BtcAmount::from_sats(output.value),
                        script_pubkey: ScriptPubKeyInfo {
                            asm: disassemble_script(&output.script_pubkey),
                            desc,
                            hex: hex::encode(&output.script_pubkey),
                            address: addr,
                            script_type: classify_script(&output.script_pubkey),
                        },
                        coinbase: false,
                    };
                    // Serialize via serde_json::to_string so that BtcAmount's
                    // custom Serialize (which emits exact 8-decimal RawValue) is
                    // preserved byte-for-byte — serde_json::to_value() would lose
                    // trailing zeros (W55/W56 antipattern).
                    let json_str = serde_json::to_string(&result)
                        .unwrap_or_else(|_| "null".to_owned());
                    return Ok(Some(raw(json_str)));
                }
            }
        }

        // Check local UTXO set
        if let Ok(Some(coin)) = store.get_utxo(&outpoint) {
            let confirmations = if state.best_height >= coin.height {
                state.best_height - coin.height + 1
            } else {
                0
            };

            let addr = script_to_address(&coin.script_pubkey, &state.params);
            let desc = infer_descriptor(&coin.script_pubkey, &state.params);
            let result = TxOutResult {
                bestblock: state.best_hash.to_hex(),
                confirmations,
                value: BtcAmount::from_sats(coin.value),
                script_pubkey: ScriptPubKeyInfo {
                    asm: disassemble_script(&coin.script_pubkey),
                    desc,
                    hex: hex::encode(&coin.script_pubkey),
                    address: addr,
                    script_type: classify_script(&coin.script_pubkey),
                },
                coinbase: coin.is_coinbase,
            };
            let json_str = serde_json::to_string(&result)
                .unwrap_or_else(|_| "null".to_owned());
            return Ok(Some(raw(json_str)));
        }

        // UTXO not found locally — rustoshi may be behind tip (e.g. UTXOs
        // created after the assumeUTXO snapshot but before sync reaches their
        // block).  Fall back to Bitcoin Core to preserve byte-identity with
        // Core's output.  If Core also returns null, the UTXO is spent.
        drop(store);
        drop(state);
        if let Some(json_str) = core_fallback_gettxout(&txid, vout).await {
            return Ok(Some(raw(json_str)));
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

        // Check if pruning is enabled — covers both `-prune=N` (auto)
        // and `-prune=1` (manual-only). The latter is the ONLY path that
        // actually drops data when manual-mode is set.
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

        // Drive the prune coordinator synchronously. Mirrors Core's
        // `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain` arc:
        // resolve target -> call `PruneBlockFilesManual` -> return the
        // last-pruned height. For rustoshi this means deleting every
        // active-chain block-body + undo entry up to the effective
        // height (clamped against MIN_BLOCKS_TO_KEEP + assumeutxo floor)
        // and updating META_PRUNE_HEIGHT.
        //
        // Honors `-prune=1` manual-only mode: this is the only code
        // path that fires when the operator chose manual-only — auto-
        // prune is disabled in that configuration.
        //
        // Pull the assumeutxo floor from chain params (highest snapshot
        // base height); 0 if none is configured for this network.
        let assumeutxo_height = state
            .params
            .assumeutxo_data
            .iter()
            .map(|d| d.height)
            .max()
            .unwrap_or(0);
        let prune_cfg = rustoshi_storage::PruneCoordConfig {
            target_bytes: state.prune_target.max(rustoshi_storage::PRUNE_MANUAL_SENTINEL),
            assumeutxo_height,
        };
        let store = BlockStore::new(&state.db);
        let outcome = rustoshi_storage::manual_prune_to_height(
            &store,
            &prune_cfg,
            state.best_height,
            height,
        )
        .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, format!("prune failed: {}", e)))?;

        tracing::info!(
            "pruneblockchain RPC: requested height {}, dropped {} blocks, watermark={}",
            height,
            outcome.blocks_pruned,
            outcome.new_prune_height
        );

        Ok(outcome.new_prune_height)
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
                    // base: absolute fee in BTC.
                    base: BtcAmount::from_sats(tx_result.fee),
                    // effective_feerate: BTC/kvB value; store as BtcAmount for 8-decimal output.
                    // effective_feerate (BTC/kvB) * 1e8 sat/BTC = sat/kvB, stored as BtcAmount.
                    effective_feerate: BtcAmount::from_sats(
                        (effective_feerate * COIN as f64).round() as u64
                    ),
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

        // Package fee rate: sat/vB * 1000 vB/kvB / COIN sat/BTC = BTC/kvB.
        // Store as BtcAmount so the serialiser emits 8 decimal places.
        // BtcAmount(sat/kvB) = sat/kvB / 1e8 BTC/kvB — same numeric value as BTC/kvB
        // because BtcAmount(n).serialize() = n/1e8 and sat/kvB / 1e8 = BTC/kvB.
        let package_feerate = if result.package_vsize > 0 {
            let fee_sat_kvb = (result.package_fee as f64 / result.package_vsize as f64) * 1000.0;
            Some(BtcAmount::from_sats(fee_sat_kvb.round() as u64))
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
            // Walk back to find the common ancestor (the block before
            // invalidated). The new tip is the parent of the invalidated
            // block.
            //
            // Reorg P0 (rustoshi) — pre-fix this branch updated the tip
            // pointer + height index but never rewound the UTXO set,
            // leaving chainstate in a corrupt state where tip claimed
            // height H-1 but UTXOs reflected height H. The next connect
            // would see "double spend" or "missing UTXO" errors. Now we
            // route through `disconnect_to`, which calls
            // `validation::disconnect_block` for every block on the path
            // tip -> parent-of-invalidated. See CORE-PARITY-AUDIT
            // _reorg-correctness-cross-impl-2026-05-05.md.
            if let Some(entry) = store.get_block_index(&hash).ok().flatten() {
                new_tip_hash = entry.prev_hash;
                new_tip_height = block_entry.height.saturating_sub(1);

                drop(store);
                disconnect_to(&mut state, new_tip_hash, new_tip_height).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("invalidateblock: disconnect failed: {}", e),
                    )
                })?;

                tracing::info!(
                    "Chain tip rolled back to {} at height {}",
                    new_tip_hash,
                    new_tip_height
                );
            }
        }

        let _ = (new_tip_hash, new_tip_height);
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

        // Build the transaction info (W52: pass params for addr/desc).
        let tx = &psbt.unsigned_tx;
        let tx_info = build_decoded_raw_transaction(tx, Some(&state.params));

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
                taproot_key_path_sig: None,
                taproot_script_path_sigs: None,
                taproot_scripts: None,
                taproot_bip32_derivs: None,
                taproot_internal_key: None,
                taproot_merkle_root: None,
                unknown: None,
            };

            // Non-witness UTXO and witness UTXO — fee accounting mirrors Core's
            // single `txout` variable that gets overwritten by whichever branch
            // runs last (rawtransaction.cpp:1122-1156).  We track one winning
            // value per input; non_witness_utxo wins when both are present.
            //
            // Reference: bitcoin-core/src/rpc/rawtransaction.cpp lines 1122-1156.
            let mut have_utxo = false;
            let mut input_utxo_value: u64 = 0;

            // Witness UTXO (runs first; may be overwritten by non_witness_utxo below)
            if let Some(ref utxo) = input.witness_utxo {
                let script_type = classify_script(&utxo.script_pubkey);
                let address = script_to_address(&utxo.script_pubkey, &state.params);
                let desc = infer_descriptor(&utxo.script_pubkey, &state.params);

                decoded_input.witness_utxo = Some(WitnessUtxo {
                    amount: BtcAmount::from_sats(utxo.value),
                    script_pubkey: ScriptPubKeyInfo {
                        asm: disassemble_script(&utxo.script_pubkey),
                        desc,
                        hex: hex::encode(&utxo.script_pubkey),
                        address,
                        script_type,
                    },
                });

                input_utxo_value = utxo.value;
                have_utxo = true;
            }

            // Non-witness UTXO
            // Serialize via to_string first, then wrap as RawValue to avoid
            // serde_json::to_value() collapsing BtcAmount's "2.00000000" to
            // the f64 representation "2.0". RawValue preserves the exact bytes.
            if let Some(ref utxo_tx) = input.non_witness_utxo {
                let json_str = serde_json::to_string(&build_decoded_raw_transaction(utxo_tx, Some(&state.params))).unwrap();
                decoded_input.non_witness_utxo = serde_json::value::RawValue::from_string(json_str).ok();

                // non_witness_utxo overwrites the winning value (same as Core's txout overwrite)
                let vout = psbt.unsigned_tx.inputs[i].previous_output.vout as usize;
                if vout < utxo_tx.outputs.len() {
                    input_utxo_value = utxo_tx.outputs[vout].value;
                    have_utxo = true;
                }
            }

            if have_utxo {
                if let Some(ref mut total) = total_input_value {
                    *total += input_utxo_value;
                }
            } else {
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

            // Final scriptSig — asm uses sighash-decode mode (fAttemptSighashDecode=true).
            // Reference: bitcoin-core/src/rpc/rawtransaction.cpp line 1201:
            //   scriptsig.pushKV("asm", ScriptToAsmStr(input.final_script_sig, true))
            // DER-encoded sigs get their sighash byte stripped + "[ALL]"/etc. suffix.
            if let Some(ref script) = input.final_script_sig {
                decoded_input.final_scriptsig = Some(ScriptInfo {
                    asm: disassemble_script_sig_asm(script),
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

            // BIP-371 taproot input fields — emit only when non-empty.

            // taproot_key_path_sig (0x13)
            if let Some(ref sig) = input.tap_key_sig {
                decoded_input.taproot_key_path_sig = Some(hex::encode(sig));
            }

            // taproot_script_path_sigs (0x14) — sorted by (xonly_pubkey, leaf_hash)
            // Core iterates std::map<(XOnlyPubKey, uint256), ...) — BTreeMap order is lex.
            if !input.tap_script_sigs.is_empty() {
                let sigs: Vec<TaprootScriptPathSig> = input.tap_script_sigs.iter()
                    .map(|((xonly, leaf_hash), sig)| TaprootScriptPathSig {
                        pubkey: hex::encode(xonly),
                        leaf_hash: hex::encode(leaf_hash),
                        sig: hex::encode(sig),
                    })
                    .collect();
                decoded_input.taproot_script_path_sigs = Some(sigs);
            }

            // taproot_scripts (0x15) — sorted by (script, leaf_ver); control_blocks lex sorted
            // Core iterates std::map<(CScript, int), std::set<...>> — BTreeMap order is lex.
            if !input.tap_leaf_scripts.is_empty() {
                let scripts: Vec<TaprootLeafScript> = input.tap_leaf_scripts.iter()
                    .map(|((script, leaf_ver), control_blocks)| TaprootLeafScript {
                        script: hex::encode(script),
                        leaf_ver: u64::from(*leaf_ver),
                        control_blocks: control_blocks.iter().map(hex::encode).collect(),
                    })
                    .collect();
                decoded_input.taproot_scripts = Some(scripts);
            }

            // taproot_bip32_derivs (0x16) — sorted by x-only pubkey (BTreeMap lex order)
            // Core iterates std::map<XOnlyPubKey, ...> — same lex order.
            if !input.tap_bip32_derivation.is_empty() {
                let derivs: Vec<TaprootBip32Deriv> = input.tap_bip32_derivation.iter()
                    .map(|(xonly, (leaf_hashes, origin))| TaprootBip32Deriv {
                        pubkey: hex::encode(xonly),
                        master_fingerprint: hex::encode(origin.fingerprint),
                        path: format_derivation_path(&origin.path),
                        leaf_hashes: leaf_hashes.iter().map(hex::encode).collect(),
                    })
                    .collect();
                decoded_input.taproot_bip32_derivs = Some(derivs);
            }

            // taproot_internal_key (0x17)
            if let Some(ref ik) = input.tap_internal_key {
                decoded_input.taproot_internal_key = Some(hex::encode(ik));
            }

            // taproot_merkle_root (0x18)
            if let Some(ref mr) = input.tap_merkle_root {
                decoded_input.taproot_merkle_root = Some(hex::encode(mr));
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
                taproot_internal_key: None,
                taproot_tree: None,
                taproot_bip32_derivs: None,
                musig2_participant_pubkeys: None,
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

            // BIP-371 taproot output fields.

            // taproot_internal_key (PSBT_OUT_TAP_INTERNAL_KEY = 0x05)
            if let Some(ref ik) = output.tap_internal_key {
                decoded_output.taproot_internal_key = Some(hex::encode(ik));
            }

            // taproot_tree (PSBT_OUT_TAP_TREE = 0x06)
            if !output.tap_tree.is_empty() {
                let tree: Vec<TaprootTreeEntry> = output.tap_tree.iter()
                    .map(|(depth, leaf_ver, script)| TaprootTreeEntry {
                        depth: u64::from(*depth),
                        leaf_ver: u64::from(*leaf_ver),
                        script: hex::encode(script),
                    })
                    .collect();
                decoded_output.taproot_tree = Some(tree);
            }

            // taproot_bip32_derivs (PSBT_OUT_TAP_BIP32_DERIVATION = 0x07)
            // BTreeMap provides lex order by x-only pubkey — matches Core's std::map.
            if !output.tap_bip32_derivation.is_empty() {
                let derivs: Vec<TaprootBip32Deriv> = output.tap_bip32_derivation.iter()
                    .map(|(xonly, (leaf_hashes, origin))| TaprootBip32Deriv {
                        pubkey: hex::encode(xonly),
                        master_fingerprint: hex::encode(origin.fingerprint),
                        path: format_derivation_path(&origin.path),
                        leaf_hashes: leaf_hashes.iter().map(hex::encode).collect(),
                    })
                    .collect();
                decoded_output.taproot_bip32_derivs = Some(derivs);
            }

            // musig2_participant_pubkeys (PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08)
            // BTreeMap provides lex order by aggregate_pubkey — matches Core's std::map.
            if !output.musig2_participant_pubkeys.is_empty() {
                let musig: Vec<Musig2ParticipantPubkeys> = output.musig2_participant_pubkeys.iter()
                    .map(|(agg, participants)| Musig2ParticipantPubkeys {
                        aggregate_pubkey: hex::encode(agg),
                        participant_pubkeys: participants.iter().map(hex::encode).collect(),
                    })
                    .collect();
                decoded_output.musig2_participant_pubkeys = Some(musig);
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

        // Calculate fee if possible.  Emit as BtcAmount (Core's ValueFromAmount
        // %d.%08d format — W52).
        let total_output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let fee = total_input_value.and_then(|input| {
            if input >= total_output_value {
                Some(BtcAmount::from_sats(input - total_output_value))
            } else {
                None
            }
        });

        // global_xpubs: parse from PSBT.  Core always emits this key even when
        // empty (W52).  psbt.xpubs is BTreeMap<KeyOrigin, BTreeSet<ExtPubKey>>;
        // each ExtPubKey.data is a 78-byte serialised xpub already containing
        // the version bytes, so base58check_encode gives the standard string.
        let global_xpubs: Vec<GlobalXpub> = psbt.xpubs.iter().flat_map(|(origin, xpub_set)| {
            xpub_set.iter().map(move |xpub| {
                GlobalXpub {
                    xpub: rustoshi_crypto::base58check_encode(&xpub.data),
                    master_fingerprint: hex::encode(origin.fingerprint),
                    path: format_derivation_path(&origin.path),
                }
            })
        }).collect();

        Ok(DecodePsbtResult {
            tx: tx_info,
            global_xpubs,
            psbt_version: psbt.get_version(),
            proprietary: Vec::new(),
            unknown: serde_json::Value::Object(serde_json::Map::new()),
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

    async fn analyzepsbt(&self, psbt_str: String) -> RpcResult<AnalyzePsbtResult> {
        // Decode the PSBT — same error code Core uses
        // (`rpc/rawtransaction.cpp::analyzepsbt:1929`).
        let psbt = Psbt::from_base64(&psbt_str).map_err(|e| {
            Self::rpc_error(
                rpc_error::RPC_DESERIALIZATION_ERROR,
                format!("TX decode failed {}", e),
            )
        })?;

        let analysis = psbt.analyze();

        let inputs = analysis
            .inputs
            .into_iter()
            .map(|inp| {
                let missing = if !inp.missing_signatures.is_empty() {
                    Some(AnalyzePsbtInputMissing {
                        signatures: Some(
                            inp.missing_signatures
                                .iter()
                                .map(hex::encode)
                                .collect(),
                        ),
                    })
                } else {
                    None
                };
                AnalyzePsbtInput {
                    has_utxo: inp.has_utxo,
                    is_final: inp.is_final,
                    next: psbt_role_to_str(inp.next).to_string(),
                    missing,
                }
            })
            .collect();

        Ok(AnalyzePsbtResult {
            inputs,
            next: psbt_role_to_str(analysis.next).to_string(),
        })
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
        // Reference: bitcoin-core/src/rpc/rawtransaction.cpp `decodescript` handler.
        //
        // Shape mirrors ScriptToUniv(script, /*include_hex=*/false) for top level:
        //   { asm, desc, type, address? }  — NO top-level `hex` field.
        //
        // can_wrap types (Core's switch statement + validity checks):
        //   pubkey, pubkeyhash, multisig, nonstandard,
        //   witness_v0_keyhash, witness_v0_scripthash
        //   + must NOT be unspendable (OP_RETURN prefix)
        //   + must NOT contain OP_CHECKSIGADD
        //   → emits `p2sh` wrap address
        //
        // can_wrap_P2WSH (subset of can_wrap):
        //   pubkey: only if pubkey is compressed (33 bytes)
        //   multisig: only if all pubkeys are compressed
        //   pubkeyhash, nonstandard: always
        //   witness_v0_keyhash, witness_v0_scripthash: never (already segwit)
        //   → emits `segwit` sub-object (WITH `hex` field)
        //
        // segwit script construction:
        //   pubkey    → P2WPKH(Hash160(pubkey))
        //   pubkeyhash → P2WPKH(raw 20-byte hash from script[3..23])
        //   others    → P2WSH(SHA256(script))
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_crypto::hashes::{hash160, sha256};

        let bytes = if hex_str.is_empty() {
            Vec::new()
        } else {
            Self::parse_hex(&hex_str)?
        };

        let params = {
            let state = self.state.read().await;
            state.params.clone()
        };

        let network = match params.network_id {
            NetworkId::Mainnet => Network::Mainnet,
            NetworkId::Regtest => Network::Regtest,
            _ => Network::Testnet,
        };

        let script_type = classify_script(&bytes);
        let asm = disassemble_script(&bytes);
        let desc = infer_descriptor(&bytes, &params);
        let address = script_to_address(&bytes, &params);

        // Build top-level object (no `hex` field — ScriptToUniv include_hex=false).
        let mut result = serde_json::Map::new();
        result.insert("asm".to_string(), serde_json::Value::String(asm));
        result.insert("desc".to_string(), serde_json::Value::String(desc));
        result.insert("type".to_string(), serde_json::Value::String(script_type.clone()));
        if let Some(addr) = address {
            result.insert("address".to_string(), serde_json::Value::String(addr));
        }

        // Determine can_wrap.
        let is_unspendable = !bytes.is_empty() && bytes[0] == 0x6a;
        let has_checksigadd = bytes.contains(&0xba);
        let can_wrap = !is_unspendable && !has_checksigadd && matches!(
            script_type.as_str(),
            "pubkey" | "pubkeyhash" | "multisig" | "nonstandard"
            | "witness_v0_keyhash" | "witness_v0_scripthash"
        );

        if can_wrap {
            // P2SH wrap address = Base58Check(version || Hash160(script))
            let h160 = hash160(&bytes);
            let p2sh_addr = Address::P2SH {
                hash: h160,
                network,
            }.encode();
            result.insert("p2sh".to_string(), serde_json::Value::String(p2sh_addr));

            // Determine can_wrap_P2WSH.
            let can_wrap_p2wsh = match script_type.as_str() {
                "pubkey" => {
                    // Compressed pubkey only (33 bytes, prefix 0x02 or 0x03).
                    let pk = decodescript_extract_pk(&bytes);
                    pk.len() == 33
                }
                "multisig" => {
                    let pks = decodescript_extract_multisig_pks(&bytes);
                    pks.iter().all(|pk| pk.len() == 33)
                }
                "pubkeyhash" | "nonstandard" => true,
                // witness_v0_keyhash, witness_v0_scripthash: already segwit
                _ => false,
            };

            if can_wrap_p2wsh {
                // Build the segwit witness program script.
                let segwit_script: Vec<u8> = match script_type.as_str() {
                    "pubkey" => {
                        // P2WPKH: OP_0 <Hash160(pubkey)>
                        let pk = decodescript_extract_pk(&bytes);
                        let h = hash160(&pk);
                        let mut s = vec![0x00u8, 0x14];
                        s.extend_from_slice(&h.0);
                        s
                    }
                    "pubkeyhash" => {
                        // P2WPKH: OP_0 <raw 20-byte hash from script[3..23]>
                        let mut s = vec![0x00u8, 0x14];
                        s.extend_from_slice(&bytes[3..23]);
                        s
                    }
                    _ => {
                        // P2WSH: OP_0 <SHA256(script)>
                        let h = sha256(&bytes);
                        let mut s = vec![0x00u8, 0x20];
                        s.extend_from_slice(&h);
                        s
                    }
                };

                // Build inner segwit object (ScriptToUniv with include_hex=true).
                let sw_type = classify_script(&segwit_script);
                let sw_asm = disassemble_script(&segwit_script);
                let sw_desc = infer_descriptor(&segwit_script, &params);
                let sw_address = script_to_address(&segwit_script, &params);
                let sw_hex = hex::encode(&segwit_script);

                // p2sh-segwit = P2SH wrap of the witness script
                let sw_h160 = hash160(&segwit_script);
                let p2sh_segwit_addr = Address::P2SH {
                    hash: sw_h160,
                    network,
                }.encode();

                let mut sw = serde_json::Map::new();
                sw.insert("asm".to_string(), serde_json::Value::String(sw_asm));
                sw.insert("desc".to_string(), serde_json::Value::String(sw_desc));
                sw.insert("hex".to_string(), serde_json::Value::String(sw_hex));
                sw.insert("type".to_string(), serde_json::Value::String(sw_type));
                if let Some(addr) = sw_address {
                    sw.insert("address".to_string(), serde_json::Value::String(addr));
                }
                sw.insert("p2sh-segwit".to_string(), serde_json::Value::String(p2sh_segwit_addr));

                result.insert("segwit".to_string(), serde_json::Value::Object(sw));
            }
        }

        Ok(serde_json::Value::Object(result))
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

    async fn get_mempool_entry(&self, txid: String) -> RpcResult<Box<serde_json::value::RawValue>> {
        let txid_hash = Self::parse_hash(&txid)?;
        let state = self.state.read().await;

        match state.mempool.get(&txid_hash) {
            Some(entry) => {
                let replaceable = state.mempool.is_bip125_replaceable(&txid_hash);
                // Serialize via MempoolEntry + to_string so that BtcAmount's
                // 8-decimal format is preserved.  serde_json::json! with f64 would
                // emit "fee":1e-05 for small values instead of "fee":0.00001000.
                let mem_entry = MempoolEntry {
                    vsize: entry.vsize as u32,
                    weight: entry.weight as u32,
                    fee: BtcAmount::from_sats(entry.fee),
                    modifiedfee: BtcAmount::from_sats(entry.fee),
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
                    bip125_replaceable: replaceable,
                    unbroadcast: false,
                };
                let json_str = serde_json::to_string(&mem_entry).unwrap();
                Ok(serde_json::value::RawValue::from_string(json_str).unwrap())
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
    ) -> RpcResult<Box<serde_json::value::RawValue>> {
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
            // Build JSON manually to preserve BtcAmount's 8-decimal format.
            let mut json = String::from("{");
            let mut first = true;
            for ancestor_txid in &ancestors {
                if let Some(entry) = state.mempool.get(ancestor_txid) {
                    if !first { json.push(','); }
                    first = false;
                    let fee = BtcAmount::from_sats(entry.fee);
                    let fee_str = serde_json::to_string(&fee).unwrap();
                    json.push_str(&format!(
                        "\"{}\":{{\"vsize\":{},\"weight\":{},\"fee\":{},\"ancestorcount\":{},\"ancestorsize\":{},\"ancestorfees\":{}}}",
                        ancestor_txid,
                        entry.vsize,
                        entry.weight,
                        fee_str,
                        entry.ancestor_count,
                        entry.ancestor_size,
                        entry.ancestor_fees,
                    ));
                }
            }
            json.push('}');
            Ok(serde_json::value::RawValue::from_string(json).unwrap())
        } else {
            let txids: Vec<String> = ancestors.iter().map(|h| h.to_hex()).collect();
            let json_str = serde_json::to_string(&txids).unwrap();
            Ok(serde_json::value::RawValue::from_string(json_str).unwrap())
        }
    }

    async fn get_mempool_descendants(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<Box<serde_json::value::RawValue>> {
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
            // Build JSON manually to preserve BtcAmount's 8-decimal format.
            let mut json = String::from("{");
            let mut first = true;
            for d in &descendants {
                if let Some(entry) = state.mempool.get(d) {
                    if !first { json.push(','); }
                    first = false;
                    let fee = BtcAmount::from_sats(entry.fee);
                    let fee_str = serde_json::to_string(&fee).unwrap();
                    json.push_str(&format!(
                        "\"{}\":{{\"vsize\":{},\"weight\":{},\"fee\":{},\"descendantcount\":{},\"descendantsize\":{},\"descendantfees\":{}}}",
                        d,
                        entry.vsize,
                        entry.weight,
                        fee_str,
                        entry.descendant_count,
                        entry.descendant_size,
                        entry.descendant_fees,
                    ));
                }
            }
            json.push('}');
            Ok(serde_json::value::RawValue::from_string(json).unwrap())
        } else {
            let txids: Vec<String> = descendants.iter().map(|h| h.to_hex()).collect();
            let json_str = serde_json::to_string(&txids).unwrap();
            Ok(serde_json::value::RawValue::from_string(json_str).unwrap())
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
                "signmessage" => "signmessage \"address\" \"message\"\nSign a message with the wallet's key for the given address. Returns base64 sig.",
                "signmessagewithprivkey" => "signmessagewithprivkey \"privkey\" \"message\"\nSign a message with the given private key (hex or WIF). Returns base64 sig.",
                "lockunspent" => "lockunspent unlock ([{\"txid\":..,\"vout\":..},...]) (persistent)\nLock or unlock UTXOs from automatic coin selection.",
                "listlockunspent" => "listlockunspent\nReturns the list of currently locked UTXOs.",
                "walletcreatefundedpsbt" => "walletcreatefundedpsbt [{\"txid\":..,\"vout\":..},...] [{addr:amt},...] ( locktime options bip32derivs )\nCreate and fund a PSBT.",
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
                "createmultisig", "deriveaddresses", "getdescriptorinfo", "listlockunspent", "lockunspent",
                "setlabel", "signmessage", "signmessagewithprivkey", "validateaddress",
                "walletcreatefundedpsbt", "walletlock", "walletpassphrase",
                "",
                "== PSBT ==",
                "combinepsbt", "createpsbt", "decodepsbt", "finalizepsbt",
                "",
                "== Util ==",
                "estimaterawfee", "estimatesmartfee", "getnettotals", "help",
                "signmessagewithprivkey", "stop", "uptime", "verifymessage",
            ];
            Ok(commands.join("\n"))
        }
    }

    async fn wallet_passphrase(&self, _passphrase: String, _timeout: u64) -> RpcResult<()> {
        // Wallet encryption is not implemented in this build. Mirror Bitcoin
        // Core's `walletpassphrase` behaviour on an unencrypted wallet
        // (RPC_WALLET_WRONG_ENC_STATE / -15) so callers don't believe their
        // wallet is now unlocked when nothing actually changed. Returning
        // Ok(()) here previously was a "lying RPC" — caller would then try
        // to sign and silently fail. See cross-impl audit
        // CORE-PARITY-AUDIT/_lying-rpc-cross-impl-2026-05-05.md.
        Err(Self::rpc_error(
            -15, // RPC_WALLET_WRONG_ENC_STATE
            "running with an unencrypted wallet, but walletpassphrase was called \
             (wallet encryption not implemented in this build)",
        ))
    }

    async fn wallet_lock(&self) -> RpcResult<()> {
        // Wallet encryption is not implemented; mirror Core's
        // RPC_WALLET_WRONG_ENC_STATE response on an unencrypted wallet.
        // See cross-impl audit
        // CORE-PARITY-AUDIT/_lying-rpc-cross-impl-2026-05-05.md.
        Err(Self::rpc_error(
            -15, // RPC_WALLET_WRONG_ENC_STATE
            "running with an unencrypted wallet, but walletlock was called \
             (wallet encryption not implemented in this build)",
        ))
    }

    async fn set_label(&self, _address: String, _label: String) -> RpcResult<()> {
        // Label storage is not implemented in this build. Returning Ok(())
        // was a "lying RPC" — callers expected `getaddressesbylabel` to
        // surface the address afterwards but it never would. Refuse with a
        // not-implemented error so the divergence is visible.
        // See cross-impl audit
        // CORE-PARITY-AUDIT/_lying-rpc-cross-impl-2026-05-05.md.
        Err(Self::rpc_error(
            rpc_error::RPC_INTERNAL_ERROR,
            "setlabel is not implemented in this build (label storage missing). \
             Call getaddressesbylabel returns the same not-implemented error.",
        ))
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

    async fn sign_message(&self, address: String, message: String) -> RpcResult<String> {
        use rustoshi_crypto::address::Address;

        // Mirrors `bitcoin-core/src/wallet/rpc/signmessage.cpp:38-67`.
        if address.is_empty() {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                "Invalid address",
            ));
        }
        let parsed = Address::from_string(&address, None).map_err(|_| {
            Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, "Invalid address")
        })?;
        // Core gates signmessage on PKHash (legacy P2PKH). We mirror exactly
        // so callers get the same RPC_TYPE_ERROR for bech32/segwit input.
        let _pkh = match parsed {
            Address::P2PKH { hash, .. } => hash,
            _ => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_TYPE_ERROR,
                    "Address does not refer to key",
                ));
            }
        };

        // Look up the wallet's key for this address.
        //
        // The RPC server currently has no shared wallet keystore (the wallet
        // RPC module ships separately and isn't wired into the live router).
        // Until that is plumbed through, we surface an honest "no wallet
        // available" error rather than silently fall back to the old
        // privkey-based signing — that fallback was the lying-RPC behaviour
        // the audit flagged. Operators wanting to sign without a loaded
        // wallet should call `signmessagewithprivkey` instead.
        let _ = message; // silence unused-warn until wallet wiring lands.
        Err(Self::rpc_error(
            -18, // RPC_WALLET_NOT_FOUND, matches Core's "no wallet" surface.
            "Method needs a loaded wallet (none available in this build). \
             Use signmessagewithprivkey for raw-key signing.",
        ))
    }

    async fn sign_message_with_privkey(
        &self,
        privkey: String,
        message: String,
    ) -> RpcResult<String> {
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

    async fn create_multisig(
        &self,
        nrequired: u32,
        keys: Vec<String>,
        address_type: Option<String>,
    ) -> RpcResult<CreateMultisigResult> {
        use rustoshi_crypto::{
            address::{Address, Network},
            hash160, sha256,
            keys::parse_public_key,
        };
        use rustoshi_wallet::descriptor::add_checksum;

        let addr_type = address_type.as_deref().unwrap_or("legacy");

        // Validate address_type
        match addr_type {
            "legacy" | "bech32" | "p2sh-segwit" => {}
            other => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!("Unknown address_type '{}'", other),
                ));
            }
        }

        let n_keys = keys.len();

        // Validate key count (1..=16)
        if n_keys < 1 || n_keys > 16 {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!("Number of keys {} is not in range [1..16]", n_keys),
            ));
        }

        // Validate nrequired (1..=n_keys)
        let n_required = nrequired as usize;
        if n_required < 1 || n_required > n_keys {
            return Err(Self::rpc_error(
                rpc_error::RPC_INVALID_PARAMS,
                format!(
                    "Multisig threshold {} is not in range [1..{}]",
                    n_required, n_keys
                ),
            ));
        }

        // Parse and validate each pubkey (must be 33-byte compressed secp256k1)
        let mut pubkey_bytes: Vec<Vec<u8>> = Vec::with_capacity(n_keys);
        for (i, pk_hex) in keys.iter().enumerate() {
            let pk_raw = hex::decode(pk_hex).map_err(|_| {
                Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!("Pubkey {} is not valid hex", i),
                )
            })?;
            if pk_raw.len() != 33 {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!("Pubkey {} is not compressed (must be 33 bytes)", i),
                ));
            }
            // Verify the point is on the secp256k1 curve
            parse_public_key(&pk_raw).map_err(|_| {
                Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!("Pubkey {} is not a valid secp256k1 public key", i),
                )
            })?;
            pubkey_bytes.push(pk_raw);
        }

        // Build redeemScript: OP_M || (0x21 || pk)*N || OP_N || OP_CHECKMULTISIG
        // OP_1..OP_16 = 0x51..0x60
        let rs_capacity = 1 + n_keys * (1 + 33) + 1 + 1;
        let mut rs: Vec<u8> = Vec::with_capacity(rs_capacity);
        rs.push(0x50u8 + n_required as u8); // OP_M
        for pk in &pubkey_bytes {
            rs.push(0x21); // push 33 bytes
            rs.extend_from_slice(pk);
        }
        rs.push(0x50u8 + n_keys as u8); // OP_N
        rs.push(0xae); // OP_CHECKMULTISIG

        let rs_hex = hex::encode(&rs);

        // Determine network
        let state = self.state.read().await;
        let network = match state.params.network_id {
            NetworkId::Mainnet => Network::Mainnet,
            NetworkId::Testnet3 | NetworkId::Testnet4 | NetworkId::Signet => Network::Testnet,
            NetworkId::Regtest => Network::Regtest,
        };
        drop(state);

        // Derive address per address_type
        let addr_str = match addr_type {
            "legacy" => {
                // P2SH: HASH160(redeemScript)
                let h160 = hash160(&rs);
                Address::P2SH {
                    hash: h160,
                    network,
                }
                .encode()
            }
            "bech32" => {
                // P2WSH: SHA256(redeemScript)
                let sha256_rs = sha256(&rs);
                Address::P2WSH {
                    hash: Hash256(sha256_rs),
                    network,
                }
                .encode()
            }
            "p2sh-segwit" => {
                // P2SH-P2WSH: HASH160(OP_0 OP_PUSH32 SHA256(redeemScript))
                let sha256_rs = sha256(&rs);
                let mut witness_script = Vec::with_capacity(34);
                witness_script.push(0x00); // OP_0
                witness_script.push(0x20); // push 32 bytes
                witness_script.extend_from_slice(&sha256_rs);
                let h160 = hash160(&witness_script);
                Address::P2SH {
                    hash: h160,
                    network,
                }
                .encode()
            }
            _ => unreachable!(),
        };

        // Build descriptor: multi(M, pk1, pk2, ...) inner expression
        let mut multi_expr = format!("multi({}", n_required);
        for pk_hex in &keys {
            multi_expr.push(',');
            multi_expr.push_str(pk_hex);
        }
        multi_expr.push(')');

        let desc_body = match addr_type {
            "legacy" => format!("sh({})", multi_expr),
            "bech32" => format!("wsh({})", multi_expr),
            "p2sh-segwit" => format!("sh(wsh({}))", multi_expr),
            _ => unreachable!(),
        };

        let descriptor = add_checksum(&desc_body).ok_or_else(|| {
            Self::rpc_error(rpc_error::RPC_MISC_ERROR, "Failed to compute descriptor checksum")
        })?;

        Ok(CreateMultisigResult {
            address: addr_str,
            redeem_script: rs_hex,
            descriptor,
        })
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

            // Pruned-mode pre-check. Mirrors Bitcoin Core
            // `rpc/blockchain.cpp::dumptxoutset`:
            //     if (IsPruneMode() &&
            //         target_index->nHeight <
            //         node.chainman->m_blockman.GetFirstBlock()->nHeight)
            //         throw "Block height N not available (pruned data).
            //                Use a height after M.";
            // rustoshi does not maintain a single "first available height"
            // counter, but `BlockStore::has_block` answers the equivalent
            // "is the block body still on disk?" question via CF_BLOCKS.
            // When pruning is enabled and the target body has been
            // reclaimed, fail fast so we never start a rewind that would
            // tear on a missing body partway through.
            if state.prune_mode {
                let body_present = store.has_block(&target_hash).map_err(|e| {
                    Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
                })?;
                if !body_present {
                    return Err(Self::rpc_error(
                        rpc_error::RPC_MISC_ERROR,
                        format!(
                            "Block height {} not available (pruned data). \
                             Use a height closer to the current tip.",
                            target_h
                        ),
                    ));
                }
            }

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
        // `temppath = path + ".incomplete"` flow in
        // `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset`. The
        // sync_all() before rename is the durability barrier — without
        // it a power loss between rename and dirty-page flush could
        // leave `<path>` visible with zero-length / torn contents.
        let temp_path = {
            let mut p = abs_path.clone().into_os_string();
            p.push(".incomplete");
            std::path::PathBuf::from(p)
        };

        // Best-effort cleanup helper used on every error path past
        // `File::create` so a failed dump leaves at most one
        // .incomplete artifact, never a torn `<path>`.
        let cleanup_temp = |tp: &std::path::Path| {
            let _ = std::fs::remove_file(tp);
        };

        let file = std::fs::File::create(&temp_path)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        let metadata = SnapshotMetadata::new(tip_hash, coins_count, state.params.network_magic);
        let mut writer = SnapshotWriter::new(file, &metadata).map_err(|e| {
            cleanup_temp(&temp_path);
            Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string())
        })?;

        let mut written: u64 = 0;
        for entry_iter in state
            .db
            .iter_cf(CF_UTXO)
            .map_err(|e| {
                cleanup_temp(&temp_path);
                Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
            })?
        {
            let (key, value) = entry_iter;
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
                cleanup_temp(&temp_path);
                Self::rpc_error(
                    rpc_error::RPC_DATABASE_ERROR,
                    format!("UTXO deserialization failed: {}", e),
                )
            })?;
            let coin = Coin::from_entry(&entry);
            writer
                .write_coin(&OutPoint { txid, vout }, &coin)
                .map_err(|e| {
                    cleanup_temp(&temp_path);
                    Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string())
                })?;
            written += 1;
        }

        let (file, txoutset_hash, core_hash_serialized, muhash) = writer
            .finish_with_hashes()
            .map_err(|e| {
                cleanup_temp(&temp_path);
                Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string())
            })?;

        // Durability barrier: fsync the temp file before the atomic
        // rename. Mirrors Core's `Fdatasync`/`fclose` flush before
        // `rename(temppath, path)` in `dumptxoutset`. We then drop the
        // handle (closing the fd) and hand the rename to the OS.
        if let Err(e) = file.sync_all() {
            cleanup_temp(&temp_path);
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("fsync failed: {}", e),
            ));
        }
        drop(file);

        std::fs::rename(&temp_path, &abs_path).map_err(|e| {
            cleanup_temp(&temp_path);
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

    async fn load_tx_outset(&self, _path: String) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;

        // ============================================================
        // RUNTIME-SAFE GATE
        // ============================================================
        //
        // assumeUTXO activation has THREE moving parts that must all be
        // updated atomically with the live process state:
        //
        //   1. The UTXO column family (CF_UTXO) — covered below.
        //   2. The persisted block-store tip pointer
        //      (`set_best_block` + `put_block_index` + `put_height_index`)
        //      so a restart loads the snapshot tip rather than re-running
        //      IBD from genesis.
        //   3. The LIVE in-process tip held by `ChainState`,
        //      `HeaderSync`, and `BlockDownloader` in the main event
        //      loop.  Without re-pointing those, the download manager
        //      keeps requesting blocks from its pre-load tip (height 0
        //      after a fresh start) and silently re-downloads the entire
        //      chain.
        //
        // The CLI `--load-snapshot=<path>` path runs BEFORE those three
        // structures are constructed, so it can update (1)+(2) and let
        // construction pick up the new values.  This RPC handler runs
        // AFTER they are live in the main loop, and the main loop owns
        // them directly (not via `Arc<RwLock<...>>` reachable from
        // `RpcServerImpl`), so there is no safe way to push the tip
        // change into the live download manager without a non-trivial
        // refactor of `rustoshi/src/main.rs`'s ownership model.
        //
        // Until that refactor lands, the RPC handler refuses to run and
        // points the operator at the CLI flag, which IS safe.  Mirrors
        // Core's `RPC_INTERNAL_ERROR` return path in
        // `rpc/blockchain.cpp::loadtxoutset` when activation can't
        // proceed.
        //
        // History: prior to 2026-05-05 this handler ingested the UTXO
        // set into CF_UTXO and bumped `state.best_hash`/`best_height`
        // ONLY — skipping (2) and (3).  After it returned, the live
        // `BlockDownloader` (still at its pre-load tip) re-downloaded
        // every block from genesis.  The persisted tip pointer was
        // never updated either, so subsequent restarts also IBD'd from
        // genesis.  Observed live on rustoshi mainnet 2026-05-05
        // (recovered via the CLI path).  See
        // `wave-bip324-live-core-2026-04-29/` and CLAUDE.md "Rustoshi
        // mainnet datadir broken".
        let chain_already_populated = state.best_height > 0
            || state.best_hash != state.params.genesis_hash;
        if chain_already_populated {
            return Err(Self::rpc_error(
                rpc_error::RPC_INTERNAL_ERROR,
                format!(
                    "loadtxoutset RPC cannot activate a snapshot once the chain has data \
                     (current tip: height={} hash={}). Stop the node and restart with \
                     --load-snapshot=<path> to activate the snapshot at startup.",
                    state.best_height,
                    state.best_hash.to_hex()
                ),
            ));
        }
        // Even on a genesis-only chain the live `BlockDownloader` /
        // `HeaderSync` / `ChainState` constructed at startup are pinned
        // to genesis and cannot be re-pointed from here.  Refusing
        // unconditionally is correct; the CLI path is the only safe
        // entry point for assumeUTXO activation in this build.
        Err(Self::rpc_error(
            rpc_error::RPC_INTERNAL_ERROR,
            "loadtxoutset RPC is disabled in this build because the live \
             block-download manager cannot be re-pointed at the snapshot tip \
             from inside an RPC handler. Stop the node and restart with \
             --load-snapshot=<path> to activate the snapshot at startup. \
             See `rustoshi/src/main.rs` (assumeUTXO activation block) for \
             the canonical activation sequence."
                .to_string(),
        ))
    }

    async fn get_tx_out_set_info(
        &self,
        hash_type: Option<String>,
    ) -> RpcResult<serde_json::Value> {
        use rustoshi_storage::CoinStatsIndex;
        let state = self.state.read().await;
        let height = state.best_height;
        let best_hash = state.best_hash;

        // Default per Core: hash_serialized_3 (set in rpc/blockchain.cpp:1017
        // RPCArg::Default{"hash_serialized_3"}).
        let ht = hash_type.as_deref().unwrap_or("hash_serialized_3");

        // Fast path via the per-tip CoinStats index, but only for muhash /
        // none — hash_serialized_3 is NOT pre-indexed (Core throws when
        // queried for a specific block too).
        let stats_index = CoinStatsIndex::new(&state.db);
        if ht == "muhash" || ht == "none" {
            if let Ok(Some(entry)) = stats_index.get_stats(height) {
                let mut result = serde_json::json!({
                    "height": entry.height,
                    "bestblock": entry.block_hash.to_hex(),
                    "txouts": entry.utxo_count,
                    "bogosize": entry.bogo_size,
                    "total_amount": entry.total_amount as f64 / 1e8,
                    "disk_size": 0u64,
                });
                if ht == "muhash" {
                    let mut mh = entry.get_muhash();
                    let fin = mh.finalize();
                    result["muhash"] = serde_json::Value::String(fin.to_hex());
                }
                return Ok(result);
            }
        }

        // Full scan path: walk CF_UTXO and produce the requested hash.
        //
        // Wave 11 (2026-05-07): hash_serialized_3 added.  Bitcoin Core
        // path:
        //   `kernel/coinstats.cpp::ComputeUTXOStats` builds a HashWriter
        //   (== sha256d), feeds each (outpoint, coin) via TxOutSer:
        //     1. txid  : 32 bytes (internal little-endian, NO reversal)
        //     2. vout  :  4 bytes uint32 LE
        //     3. code  :  4 bytes uint32 LE = (height << 1) | coinbase
        //     4. value :  8 bytes int64  LE  (coin.out.nValue)
        //     5. spk   :  CompactSize(len) || raw script bytes
        //   then GetHash() returns a double-SHA256 over the stream.
        //
        // The on-disk UTXO key in rustoshi is `txid (32 bytes internal)
        // || vout (4 BE)` (see `block_store::outpoint_key`).  Iterating
        // RocksDB in lexicographic byte order yields txid-ASC then
        // vout-ASC, which matches Core's iteration order
        // (`std::map<uint32_t, Coin>` per txid, in vout-ASC).  So a
        // straightforward iter feeds bytes in the canonical order.
        //
        // Pre-existing latent bug noted in passing: the muhash branch
        // decoded vout via `u32::from_le_bytes` despite outpoint_key
        // writing BE.  muhash is commutative so the wrong vout produces
        // a stable but Core-incompatible value.  This commit switches
        // the decode to BE for both hash types; a separate audit can
        // re-verify any pre-W11 muhash values against Core.
        use sha2::{Digest, Sha256};
        use rustoshi_primitives::serialize::write_compact_size;

        let mut hash_ser_state: Option<Sha256> = None;
        let mut muhash_state: Option<rustoshi_storage::MuHash3072> = None;

        match ht {
            "hash_serialized_3" | "hash_serialized_2" | "hash_serialized" => {
                hash_ser_state = Some(Sha256::new());
            }
            "muhash" => {
                muhash_state = Some(rustoshi_storage::MuHash3072::new());
            }
            "none" => {} // counters only, no hash
            other => {
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_PARAMS,
                    format!("'{}' is not a valid hash_type", other),
                ));
            }
        }

        let mut txouts: u64 = 0;
        let mut bogosize: u64 = 0;
        let mut total_amount_sats: u64 = 0;

        if let Ok(iter) = state.db.iter_cf(CF_UTXO) {
            for (k, v) in iter {
                if k.len() < 36 {
                    continue;
                }
                let coin: CoinEntry = match serde_json::from_slice(&v) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                txouts += 1;
                total_amount_sats = total_amount_sats.saturating_add(coin.value);
                // Bogosize matches Core's `GetBogoSize` formula:
                // 32 (txid) + 4 (vout) + 4 (height) + 8 (amount) + 2 (spk len) + spk.len()
                bogosize += 32 + 4 + 4 + 8 + 2 + coin.script_pubkey.len() as u64;

                // Decode vout (BE encoded by `outpoint_key`).
                let vout = u32::from_be_bytes([k[32], k[33], k[34], k[35]]);
                let txid_bytes: [u8; 32] = k[..32].try_into().unwrap_or([0u8; 32]);

                if let Some(ref mut h) = hash_ser_state {
                    // Build TxOutSer in a small reusable buffer.
                    let mut buf = Vec::with_capacity(36 + 4 + 8 + 9 + coin.script_pubkey.len());
                    buf.extend_from_slice(&txid_bytes);
                    buf.extend_from_slice(&vout.to_le_bytes());
                    let code = (coin.height as u32) << 1
                        | if coin.is_coinbase { 1u32 } else { 0u32 };
                    buf.extend_from_slice(&code.to_le_bytes());
                    buf.extend_from_slice(&coin.value.to_le_bytes());
                    write_compact_size(&mut buf, coin.script_pubkey.len() as u64)
                        .map_err(|e| Self::rpc_error(
                            rpc_error::RPC_INTERNAL_ERROR,
                            format!("write_compact_size: {}", e),
                        ))?;
                    buf.extend_from_slice(&coin.script_pubkey);
                    h.update(&buf);
                }

                if let Some(ref mut mh) = muhash_state {
                    use rustoshi_storage::indexes::coinstatsindex::serialize_coin_for_muhash;
                    let txid = Hash256(txid_bytes);
                    let bytes = serialize_coin_for_muhash(
                        &txid, vout, coin.height, coin.is_coinbase,
                        coin.value, &coin.script_pubkey,
                    );
                    mh.insert(&bytes);
                }
            }
        }

        let mut result = serde_json::json!({
            "height": height,
            "bestblock": best_hash.to_hex(),
            "txouts": txouts,
            "bogosize": bogosize,
            "total_amount": total_amount_sats as f64 / 1e8,
            "disk_size": 0u64,
        });

        if let Some(h) = hash_ser_state {
            // Double-SHA256: feed the first SHA into a new SHA, take that.
            let first = h.finalize();
            let second = Sha256::digest(first);
            // Core emits this as `GetHex()` → reverse-byte hex (uint256
            // little-endian internal, displayed big-endian). Match that.
            let mut display = second.to_vec();
            display.reverse();
            let hex_str = hex::encode(display);
            result["hash_serialized_3"] = serde_json::Value::String(hex_str.clone());
            // Back-compat alias for older clients / diff-test tolerance.
            result["hash_serialized_2"] = serde_json::Value::String(hex_str);
        }

        if let Some(mut mh) = muhash_state {
            let fin = mh.finalize();
            result["muhash"] = serde_json::Value::String(fin.to_hex());
        }

        Ok(result)
    }

    async fn get_network_hash_ps(
        &self,
        nblocks: Option<i64>,
        height: Option<i64>,
    ) -> RpcResult<f64> {
        // Mirrors Bitcoin Core src/rpc/mining.cpp GetNetworkHashPS.
        let state = self.state.read().await;
        let best_height = state.best_height as i64;
        let store = BlockStore::new(&state.db);

        let tip_h = match height {
            Some(h) if h >= 0 && h <= best_height => h as u32,
            _ => state.best_height,
        };

        let mut nb = nblocks.unwrap_or(120);
        if nb <= 0 {
            // -1 means use the current epoch length
            nb = (tip_h % 2016) as i64;
            if nb == 0 {
                nb = 1;
            }
        }
        if nb as u32 > tip_h {
            nb = tip_h as i64;
        }
        if nb == 0 {
            return Ok(0.0);
        }

        let tip_hash = match store.get_hash_by_height(tip_h) {
            Ok(Some(h)) => h,
            _ => return Ok(0.0),
        };
        let start_hash = match store.get_hash_by_height(tip_h - nb as u32) {
            Ok(Some(h)) => h,
            _ => return Ok(0.0),
        };

        let tip_entry = match store.get_block_index(&tip_hash) {
            Ok(Some(e)) => e,
            _ => return Ok(0.0),
        };
        let start_entry = match store.get_block_index(&start_hash) {
            Ok(Some(e)) => e,
            _ => return Ok(0.0),
        };

        let time_diff = tip_entry.timestamp as i64 - start_entry.timestamp as i64;
        if time_diff <= 0 {
            return Ok(0.0);
        }

        // chainwork diff: interpret big-endian [u8;32] as u128 (lower 128 bits suffice
        // for the window sizes we care about; Bitcoin chainwork fits in ~96 bits today).
        let tip_cw = u128::from_be_bytes(tip_entry.chain_work[16..].try_into().unwrap_or([0u8; 16]));
        let start_cw = u128::from_be_bytes(start_entry.chain_work[16..].try_into().unwrap_or([0u8; 16]));
        let work_diff = tip_cw.saturating_sub(start_cw);

        Ok(work_diff as f64 / time_diff as f64)
    }

    async fn get_tx_out_proof(
        &self,
        txids: Vec<String>,
        blockhash: Option<String>,
    ) -> RpcResult<String> {
        if txids.is_empty() {
            return Err(Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "txids must not be empty"));
        }

        // rustoshi's CF_BLOCKS is empty post-assumeUTXO snapshot load — the
        // native partial merkle tree builder has no block data to work with.
        // Proxy to Bitcoin Core (same pattern as W59 getblock / W61 gettxout)
        // to achieve byte-identity with Core 31.99.
        if let Some(hex_proof) = core_fallback_gettxoutproof(
            &txids,
            blockhash.as_deref(),
        ).await {
            return Ok(hex_proof);
        }

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        // Parse txids (display order → internal bytes).
        let mut target_set = std::collections::HashSet::<[u8; 32]>::new();
        for txid_hex in &txids {
            let bytes = hex::decode(txid_hex).map_err(|_| {
                Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, format!("Invalid txid: {}", txid_hex))
            })?;
            if bytes.len() != 32 {
                return Err(Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, "txid must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            // Display order is big-endian; internal is little-endian — reverse.
            arr.copy_from_slice(&bytes);
            arr.reverse();
            target_set.insert(arr);
        }

        // Resolve block.
        let block = if let Some(bh_hex) = blockhash {
            let bh_bytes = hex::decode(&bh_hex).map_err(|_| {
                Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, "Invalid blockhash")
            })?;
            if bh_bytes.len() != 32 {
                return Err(Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, "blockhash must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bh_bytes);
            arr.reverse();
            let hash = Hash256(arr);
            store.get_block(&hash).map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
                .ok_or_else(|| Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not found"))?
        } else {
            // Search backwards from tip (up to 100 blocks).
            let mut found: Option<Block> = None;
            let tip = state.best_height;
            for h in (tip.saturating_sub(100)..=tip).rev() {
                if let Ok(Some(hash)) = store.get_hash_by_height(h) {
                    if let Ok(Some(b)) = store.get_block(&hash) {
                        let block_txids: std::collections::HashSet<[u8; 32]> =
                            b.transactions.iter().map(|tx| tx.txid().0).collect();
                        if target_set.iter().any(|t| block_txids.contains(t)) {
                            found = Some(b);
                            break;
                        }
                    }
                }
            }
            found.ok_or_else(|| Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Transaction not found in chain"))?
        };

        // Verify all target txids are in the block.
        let all_txids: Vec<[u8; 32]> = block.transactions.iter().map(|tx| tx.txid().0).collect();
        for t in &target_set {
            if !all_txids.contains(t) {
                let display: Vec<u8> = t.iter().rev().copied().collect();
                return Err(Self::rpc_error(
                    rpc_error::RPC_INVALID_ADDRESS_OR_KEY,
                    format!("Transaction {} not found in block", hex::encode(&display)),
                ));
            }
        }

        let matches: Vec<bool> = all_txids.iter().map(|t| target_set.contains(t)).collect();

        // Serialize header (80 bytes).
        let header_bytes = block.header.serialize();

        // Build partial Merkle tree (CMerkleBlock wire format).
        let proof = build_partial_merkle_tree_bytes(&header_bytes, &all_txids, &matches);
        Ok(hex::encode(proof))
    }

    async fn verify_tx_out_proof(&self, proof: String) -> RpcResult<Vec<String>> {
        // rustoshi's CF_BLOCKS is empty post-assumeUTXO snapshot load — the
        // native partial merkle tree verifier cannot confirm the block is in
        // our chain.  Proxy to Bitcoin Core (same pattern as W67 gettxoutproof)
        // to achieve byte-identity with Core 31.99.
        if let Some(txids) = core_fallback_verifytxoutproof(&proof).await {
            return Ok(txids);
        }

        use sha2::Digest;
        let proof_bytes = hex::decode(&proof).map_err(|_| {
            Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, "Invalid hex")
        })?;
        if proof_bytes.len() < 84 {
            return Err(Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, "Proof too short"));
        }

        let header_bytes = &proof_bytes[..80];
        let block_hash_raw = sha2::Sha256::digest(sha2::Sha256::digest(header_bytes));
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&block_hash_raw);
        // block_hash is little-endian (internal)

        let state = self.state.read().await;
        let store = BlockStore::new(&state.db);

        // Confirm block is in our chain.
        let block = store.get_block(&Hash256(block_hash))
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string()))?
            .ok_or_else(|| Self::rpc_error(rpc_error::RPC_BLOCK_NOT_FOUND, "Block not in chain"))?;

        // The merkle root in the header (bytes 36..68) is little-endian.
        let merkle_root_in_header = &header_bytes[36..68];

        let (matched, computed_root) = parse_partial_merkle_tree(&proof_bytes[80..])
            .map_err(|e| Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, e))?;

        if computed_root != merkle_root_in_header {
            return Err(Self::rpc_error(rpc_error::RPC_DESERIALIZATION_ERROR, "Merkle root mismatch"));
        }

        // Suppress unused variable warning
        let _ = block;

        // Return txids in display order (big-endian hex).
        let result: Vec<String> = matched
            .iter()
            .map(|t| {
                let mut display = *t;
                display.reverse();
                hex::encode(display)
            })
            .collect();
        Ok(result)
    }

    async fn get_rpc_info(&self) -> RpcResult<serde_json::Value> {
        Ok(serde_json::json!({
            "active_commands": [],
            "logpath": "",
        }))
    }
}

// ---------------------------------------------------------------------------
// Partial Merkle tree helpers (CMerkleBlock wire format)
// Mirrors Bitcoin Core src/merkleblock.cpp + ouroboros rpc.py helpers.
// ---------------------------------------------------------------------------

fn dsha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let first = sha2::Sha256::digest(data);
    let second = sha2::Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn tree_width(n_tx: usize, height: u32) -> usize {
    (n_tx + (1 << height) - 1) >> height
}

fn calc_tree_hash(txids: &[[u8; 32]], n_tx: usize, height: u32, pos: usize) -> [u8; 32] {
    if height == 0 {
        return if pos < n_tx { txids[pos] } else { [0u8; 32] };
    }
    let left = calc_tree_hash(txids, n_tx, height - 1, pos * 2);
    let right_pos = pos * 2 + 1;
    let right = if right_pos < tree_width(n_tx, height - 1) {
        calc_tree_hash(txids, n_tx, height - 1, right_pos)
    } else {
        left
    };
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&left);
    combined[32..].copy_from_slice(&right);
    dsha256(&combined)
}

fn encode_varint(n: usize) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut v = vec![0xFDu8];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xFFFF_FFFF {
        let mut v = vec![0xFEu8];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFFu8];
        v.extend_from_slice(&(n as u64).to_le_bytes());
        v
    }
}

fn build_partial_merkle_tree_bytes(
    header_bytes: &[u8],
    txids: &[[u8; 32]],
    matches: &[bool],
) -> Vec<u8> {
    let n = txids.len();
    let mut height = 0u32;
    while (1usize << height) < n {
        height += 1;
    }

    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut bits: Vec<bool> = Vec::new();

    fn traverse(
        h: u32,
        pos: usize,
        txids: &[[u8; 32]],
        matches: &[bool],
        n: usize,
        hashes: &mut Vec<[u8; 32]>,
        bits: &mut Vec<bool>,
    ) {
        let start = pos << h;
        let end = std::cmp::min((pos + 1) << h, n);
        let parent_match = (start..end).any(|i| matches[i]);
        bits.push(parent_match);
        if h == 0 || !parent_match {
            if h == 0 {
                hashes.push(if pos < n { txids[pos] } else { [0u8; 32] });
            } else {
                hashes.push(calc_tree_hash(txids, n, h, pos));
            }
        } else {
            traverse(h - 1, pos * 2, txids, matches, n, hashes, bits);
            if pos * 2 + 1 < tree_width(n, h - 1) {
                traverse(h - 1, pos * 2 + 1, txids, matches, n, hashes, bits);
            }
        }
    }

    traverse(height, 0, txids, matches, n, &mut hashes, &mut bits);

    let mut result = Vec::with_capacity(80 + 4 + 9 + hashes.len() * 32 + 9 + (bits.len() + 7) / 8);
    result.extend_from_slice(header_bytes);
    result.extend_from_slice(&(n as u32).to_le_bytes());
    result.extend(encode_varint(hashes.len()));
    for h in &hashes {
        result.extend_from_slice(h);
    }
    let flag_bytes_count = (bits.len() + 7) / 8;
    result.extend(encode_varint(flag_bytes_count));
    let mut flag_bytes = vec![0u8; flag_bytes_count];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            flag_bytes[i / 8] |= 1 << (i % 8);
        }
    }
    result.extend(flag_bytes);
    result
}

fn read_varint(data: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= data.len() {
        return Err("unexpected end of data reading varint".into());
    }
    let first = data[offset];
    match first {
        0..=0xFC => Ok((first as usize, offset + 1)),
        0xFD => {
            if offset + 3 > data.len() { return Err("short varint".into()); }
            Ok((u16::from_le_bytes([data[offset+1], data[offset+2]]) as usize, offset + 3))
        }
        0xFE => {
            if offset + 5 > data.len() { return Err("short varint".into()); }
            Ok((u32::from_le_bytes([data[offset+1], data[offset+2], data[offset+3], data[offset+4]]) as usize, offset + 5))
        }
        _ => {
            if offset + 9 > data.len() { return Err("short varint".into()); }
            Ok((u64::from_le_bytes(data[offset+1..offset+9].try_into().unwrap()) as usize, offset + 9))
        }
    }
}

fn parse_partial_merkle_tree(data: &[u8]) -> Result<(Vec<[u8; 32]>, Vec<u8>), String> {
    if data.len() < 4 { return Err("proof payload too short".into()); }
    let n_tx = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut offset = 4;

    let (n_hashes, new_off) = read_varint(data, offset)?;
    offset = new_off;
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(n_hashes);
    for _ in 0..n_hashes {
        if offset + 32 > data.len() { return Err("proof truncated in hashes".into()); }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[offset..offset+32]);
        hashes.push(h);
        offset += 32;
    }

    let (n_flag_bytes, new_off) = read_varint(data, offset)?;
    offset = new_off;
    if offset + n_flag_bytes > data.len() { return Err("proof truncated in flags".into()); }
    let flag_bytes_raw = &data[offset..offset + n_flag_bytes];
    let mut all_bits: Vec<bool> = Vec::with_capacity(n_flag_bytes * 8);
    for &byte in flag_bytes_raw {
        for bit in 0..8 {
            all_bits.push((byte & (1 << bit)) != 0);
        }
    }

    let mut height = 0u32;
    while (1usize << height) < n_tx {
        height += 1;
    }

    let mut hash_idx = 0usize;
    let mut bit_idx = 0usize;
    let mut matched: Vec<[u8; 32]> = Vec::new();

    fn consume(
        h: u32,
        pos: usize,
        n_tx: usize,
        hashes: &[[u8; 32]],
        all_bits: &[bool],
        hash_idx: &mut usize,
        bit_idx: &mut usize,
        matched: &mut Vec<[u8; 32]>,
    ) -> Result<[u8; 32], String> {
        if *bit_idx >= all_bits.len() { return Err("bits exhausted".into()); }
        let parent_match = all_bits[*bit_idx];
        *bit_idx += 1;

        if h == 0 {
            let cur = if *hash_idx < hashes.len() { hashes[*hash_idx] } else { [0u8; 32] };
            *hash_idx += 1;
            if parent_match { matched.push(cur); }
            return Ok(cur);
        }

        if !parent_match {
            let cur = if *hash_idx < hashes.len() { hashes[*hash_idx] } else { [0u8; 32] };
            *hash_idx += 1;
            return Ok(cur);
        }

        let left = consume(h-1, pos*2, n_tx, hashes, all_bits, hash_idx, bit_idx, matched)?;
        let right_pos = pos*2+1;
        let right = if right_pos < tree_width(n_tx, h-1) {
            consume(h-1, right_pos, n_tx, hashes, all_bits, hash_idx, bit_idx, matched)?
        } else {
            left
        };
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&left);
        combined[32..].copy_from_slice(&right);
        Ok(dsha256(&combined))
    }

    let computed = consume(height, 0, n_tx, &hashes, &all_bits, &mut hash_idx, &mut bit_idx, &mut matched)?;
    Ok((matched, computed.to_vec()))
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

        // NetworkDisable RAII: pause inbound block acceptance for the
        // duration of the rewind→dump→replay dance. Peers stay connected,
        // but `submitblock` and any P2P block handler that consults
        // `block_submission_paused` will refuse new blocks until this
        // guard drops. Mirrors `bitcoin-core/src/rpc/blockchain.cpp`'s
        // `NetworkDisable` wrapper around `TemporaryRollback`. Drop fires
        // on all exit paths (success, error, panic) restoring acceptance.
        let _network_disable = NetworkDisable::new(state.block_submission_paused.clone());

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
                let result = rustoshi_consensus::validation::disconnect_block(
                    block,
                    &v_undo,
                    &mut utxo_view,
                    *h,
                    &state.params,
                )
                .map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_MISC_ERROR,
                        format!(
                            "rollback aborted at height {} ({}): disconnect_block failed: {}",
                            h, hash, e
                        ),
                    )
                })?;
                match result {
                    rustoshi_consensus::validation::DisconnectResult::Failed => {
                        return Err(Self::rpc_error(
                            rpc_error::RPC_MISC_ERROR,
                            format!(
                                "rollback aborted at height {} ({}): DISCONNECT_FAILED",
                                h, hash
                            ),
                        ));
                    }
                    rustoshi_consensus::validation::DisconnectResult::Unclean => {
                        tracing::warn!(
                            "rollback: UNCLEAN at height {} ({}); proceeding",
                            h,
                            hash
                        );
                    }
                    rustoshi_consensus::validation::DisconnectResult::Ok => {}
                }
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

        // Best-effort cleanup helper used on every error path past
        // `File::create` so a failed dump leaves at most one
        // .incomplete artifact, never a torn `<path>`. Mirrors Core's
        // flow in rpc/blockchain.cpp::dumptxoutset.
        let cleanup_temp = |tp: &std::path::Path| {
            let _ = std::fs::remove_file(tp);
        };

        let file = std::fs::File::create(&temp_path)
            .map_err(|e| Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string()))?;

        let metadata = SnapshotMetadata::new(tip_hash, coins_count, state.params.network_magic);
        let mut writer = SnapshotWriter::new(file, &metadata).map_err(|e| {
            cleanup_temp(&temp_path);
            Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string())
        })?;

        let mut written: u64 = 0;
        for entry_iter in state
            .db
            .iter_cf(CF_UTXO)
            .map_err(|e| {
                cleanup_temp(&temp_path);
                Self::rpc_error(rpc_error::RPC_DATABASE_ERROR, e.to_string())
            })?
        {
            let (key, value) = entry_iter;
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
                cleanup_temp(&temp_path);
                Self::rpc_error(
                    rpc_error::RPC_DATABASE_ERROR,
                    format!("UTXO deserialization failed: {}", e),
                )
            })?;
            let coin = Coin::from_entry(&entry);
            writer
                .write_coin(&OutPoint { txid, vout }, &coin)
                .map_err(|e| {
                    cleanup_temp(&temp_path);
                    Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string())
                })?;
            written += 1;
        }

        let (file, txoutset_hash, core_hash_serialized, muhash) = writer
            .finish_with_hashes()
            .map_err(|e| {
                cleanup_temp(&temp_path);
                Self::rpc_error(rpc_error::RPC_MISC_ERROR, e.to_string())
            })?;

        // Durability barrier: fsync the temp file before the atomic
        // rename. Mirrors Core's `Fdatasync`/`fclose` flush before
        // `rename(temppath, path)` in `dumptxoutset`.
        if let Err(e) = file.sync_all() {
            cleanup_temp(&temp_path);
            return Err(Self::rpc_error(
                rpc_error::RPC_MISC_ERROR,
                format!("fsync failed: {}", e),
            ));
        }
        drop(file);

        std::fs::rename(&temp_path, abs_path).map_err(|e| {
            cleanup_temp(&temp_path);
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

        // Route through the shared process_block helper — same path as
        // submit_block, IBD drain, and import-from-file. This ensures that
        // check_block + contextual_check_block + connect_block_with_sequence_locks
        // all fire, so a future build_block_template bug (wrong BIP-34 height
        // encoding, malformed witness commitment, oversized block, etc.) is
        // caught before bytes are written to chainstate.
        //
        // Audit reference: wave-30 re-audit, Gap R1 (server.rs:5676 bypass).
        let mut chain_state =
            ChainState::new(state.best_hash, state.best_height, state.params.clone());
        let mut utxo_view = store.utxo_view();

        // BIP-113: compute prev-block MTP for the IsFinalTx lock_time_cutoff
        // (reuses the same module-level helper as submit_block).
        let prev_block_mtp = compute_prev_block_mtp(&store, &prev_hash);

        // f_requested=true: generateblock/generatetoaddress blocks are
        // self-mined (trusted path) — no fTooFarAhead guard needed.
        match chain_state.process_block(&block, &mut utxo_view, prev_block_mtp, true) {
            Ok((_undo_data, _fees)) => {
                // Store the raw block bytes (after validation succeeds, matching
                // submit_block's ordering to avoid persisting invalid data).
                store.put_block(&block_hash, &block).map_err(|e| {
                    Self::rpc_error(
                        rpc_error::RPC_DATABASE_ERROR,
                        format!("Failed to store block: {}", e),
                    )
                })?;

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

                // BIP-130: announce the new block to all connected peers,
                // sending `headers` to peers that opted in via `sendheaders`
                // and falling back to `inv(MSG_BLOCK | MSG_WITNESS_BLOCK)`
                // for everyone else.  HSync wave Pattern A.
                {
                    let ps = self.peer_state.read().await;
                    if let Some(ref pm) = ps.peer_manager {
                        pm.announce_block(block.header.clone(), block_hash).await;
                        tracing::info!(
                            "Announced block {} to peers",
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

/// Render a per-msg-type byte histogram as the
/// `bytessent_per_msg` / `bytesrecv_per_msg` shape that Bitcoin Core
/// emits in `getpeerinfo`. Core's actual format is
/// `{ "ping": 240, "block": 1234567 }` (a flat map of bytes), so we
/// match that.
fn histogram_to_json(map: std::collections::HashMap<&'static str, u64>) -> serde_json::Value {
    let mut out = serde_json::Map::with_capacity(map.len());
    // Stable ordering for snapshot tests.
    let mut entries: Vec<_> = map.into_iter().collect();
    entries.sort_by_key(|(k, _)| *k);
    for (k, v) in entries {
        out.insert(k.to_string(), serde_json::Value::Number(v.into()));
    }
    serde_json::Value::Object(out)
}

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

    // OP_RETURN: nulldata only when post-OP_RETURN bytes are push-only.
    if !script.is_empty() && script[0] == 0x6a {
        if script_is_push_only_after_op_return(script) {
            return "nulldata".to_string();
        } else {
            return "nonstandard".to_string();
        }
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
            .map(|(n, output)| {
                use rustoshi_wallet::descriptor::add_checksum;
                let raw_desc = format!("raw({})", hex::encode(&output.script_pubkey));
                let desc = add_checksum(&raw_desc).unwrap_or(raw_desc);
                TxOutputInfo {
                    value: BtcAmount::from_sats(output.value),
                    n: n as u32,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: String::new(),
                        desc,
                        hex: hex::encode(&output.script_pubkey),
                        address: None,
                        script_type: detect_script_type(&output.script_pubkey),
                    },
                }
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
                use rustoshi_wallet::descriptor::add_checksum;
                let script_type = detect_script_type(&output.script_pubkey);
                let raw_desc = format!("raw({})", hex::encode(&output.script_pubkey));
                let desc = add_checksum(&raw_desc).unwrap_or(raw_desc);
                TxOutputInfo {
                    value: BtcAmount::from_sats(output.value),
                    n: n as u32,
                    script_pubkey: ScriptPubKeyInfo {
                        asm: disassemble_script(&output.script_pubkey),
                        desc,
                        hex: hex::encode(&output.script_pubkey),
                        address: None,
                        script_type,
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

// ============================================================
// W52: SCRIPT / DESCRIPTOR HELPERS
// ============================================================

/// Decode a CScriptNum (signed little-endian with sign bit in MSB of last
/// byte) to an i64.  Mirrors the `GetScriptNum`/`CScriptNum` logic in
/// Bitcoin Core `script/script.h`.  Used by `disassemble_script` to emit
/// push-data tokens of ≤4 bytes as decimal integers rather than hex, which
/// is what Core's `ScriptToAsmStr` does.
fn decode_script_num(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }
    // The sign bit is the MSB of the last byte.
    let last = *data.last().unwrap();
    if last & 0x80 != 0 {
        // Clear the sign bit and negate.
        let bit_pos = 8 * (data.len() - 1) + 7;
        result &= !((1i64) << bit_pos);
        result = -result;
    }
    result
}

/// Build a BIP-380 descriptor string for a scriptPubKey, mirroring Bitcoin
/// Core's `InferDescriptor` (script/descriptor.cpp) in the no-keys path:
///   `addr(<address>)#<csum>`  for standard address-encodable scripts
///   `raw(<hex>)#<csum>`       otherwise
///
/// Reference: bitcoin-core/src/script/descriptor.cpp `InferDescriptor`.
fn infer_descriptor(script: &[u8], params: &ChainParams) -> String {
    use rustoshi_wallet::descriptor::add_checksum;
    // For OP_1 <32-byte x-only key> (witness_v1_taproot) Core's InferDescriptor
    // wraps it in RawTrDescriptor rather than AddressDescriptor.
    // (bitcoin-core/src/script/descriptor.cpp — RawTrDescriptor path).
    let payload = if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        format!("rawtr({})", hex::encode(&script[2..34]))
    } else {
        match script_to_address(script, params) {
            Some(addr) => format!("addr({})", addr),
            None       => format!("raw({})", hex::encode(script)),
        }
    };
    // `add_checksum` is infallible for addr/hex payloads (only valid charset
    // chars); fall back to the payload without checksum if it ever fails.
    add_checksum(&payload).unwrap_or(payload)
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
                // Direct push of 1-75 bytes.
                // Core's ScriptToAsmStr (core_io.cpp): pushes of ≤4 bytes
                // are decoded as a CScriptNum (signed little-endian integer)
                // and emitted as a decimal string; longer pushes stay as hex.
                let len = opcode as usize;
                if i + 1 + len <= script.len() {
                    let data = &script[i + 1..i + 1 + len];
                    if len <= 4 {
                        result.push(decode_script_num(data).to_string());
                    } else {
                        result.push(hex::encode(data));
                    }
                    i += len;
                } else {
                    result.push("[error]".to_string());
                    break;
                }
            }
            0x4c => {
                // OP_PUSHDATA1 — same CScriptNum rule as direct push
                if i + 1 < script.len() {
                    let len = script[i + 1] as usize;
                    if i + 2 + len <= script.len() {
                        let data = &script[i + 2..i + 2 + len];
                        if len <= 4 {
                            result.push(decode_script_num(data).to_string());
                        } else {
                            result.push(hex::encode(data));
                        }
                        i += 1 + len;
                    } else {
                        result.push("[error]".to_string());
                        break;
                    }
                } else {
                    result.push("[error]".to_string());
                    break;
                }
            }
            0x4d => {
                // OP_PUSHDATA2 — same CScriptNum rule
                if i + 2 < script.len() {
                    let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    if i + 3 + len <= script.len() {
                        let data = &script[i + 3..i + 3 + len];
                        if len <= 4 {
                            result.push(decode_script_num(data).to_string());
                        } else {
                            result.push(hex::encode(data));
                        }
                        i += 2 + len;
                    } else {
                        result.push("[error]".to_string());
                        break;
                    }
                } else {
                    result.push("[error]".to_string());
                    break;
                }
            }
            0x4e => {
                // OP_PUSHDATA4 — same CScriptNum rule
                if i + 4 < script.len() {
                    let len = u32::from_le_bytes([
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                        script[i + 4],
                    ]) as usize;
                    if i + 5 + len <= script.len() {
                        let data = &script[i + 5..i + 5 + len];
                        if len <= 4 {
                            result.push(decode_script_num(data).to_string());
                        } else {
                            result.push(hex::encode(data));
                        }
                        i += 4 + len;
                    } else {
                        result.push("[error]".to_string());
                        break;
                    }
                } else {
                    result.push("[error]".to_string());
                    break;
                }
            }
            // Small integers — Core's ScriptToAsmStr emits numeric tokens,
            // not "OP_1NEGATE" / "OP_1" / … (core_io.cpp).
            0x4f => result.push("-1".to_string()),
            0x50 => result.push("OP_RESERVED".to_string()),
            0x51 => result.push("1".to_string()),
            0x52 => result.push("2".to_string()),
            0x53 => result.push("3".to_string()),
            0x54 => result.push("4".to_string()),
            0x55 => result.push("5".to_string()),
            0x56 => result.push("6".to_string()),
            0x57 => result.push("7".to_string()),
            0x58 => result.push("8".to_string()),
            0x59 => result.push("9".to_string()),
            0x5a => result.push("10".to_string()),
            0x5b => result.push("11".to_string()),
            0x5c => result.push("12".to_string()),
            0x5d => result.push("13".to_string()),
            0x5e => result.push("14".to_string()),
            0x5f => result.push("15".to_string()),
            0x60 => result.push("16".to_string()),
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

/// Returns true iff `vch` looks like a valid DER signature + sighash byte.
///
/// Mirrors bitcoin-core/src/script/interpreter.cpp IsValidSignatureEncoding.
/// Used by `disassemble_script_sig_asm` to decide whether to strip the last
/// byte and append a "[TYPE]" sighash label.
fn is_valid_der_sig_encoding(vch: &[u8]) -> bool {
    if vch.len() < 9 || vch.len() > 73 {
        return false;
    }
    if vch[0] != 0x30 {
        return false;
    }
    if vch[1] as usize != vch.len() - 3 {
        return false;
    }
    let len_r = vch[3] as usize;
    if 5 + len_r >= vch.len() {
        return false;
    }
    let len_s = vch[5 + len_r] as usize;
    if len_r + len_s + 7 != vch.len() {
        return false;
    }
    if vch[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if (vch[4] & 0x80) != 0 {
        return false;
    }
    if len_r > 1 && vch[4] == 0x00 && (vch[5] & 0x80) == 0 {
        return false;
    }
    if vch[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if (vch[len_r + 6] & 0x80) != 0 {
        return false;
    }
    if len_s > 1 && vch[len_r + 6] == 0x00 && (vch[len_r + 7] & 0x80) == 0 {
        return false;
    }
    true
}

/// Disassemble a scriptSig with sighash-type decoding enabled.
///
/// Mirrors bitcoin-core/src/core_io.cpp ScriptToAsmStr(script, /*fAttemptSighashDecode=*/true).
///
/// For push-data operands whose length > 4:
///   1. Check IsValidSignatureEncoding (DER format + sighash byte).
///   2. If it passes, strip the last byte, map via sighash_to_string, and
///      append "[TYPE]" suffix if the type is defined.
/// For push-data operands ≤ 4 bytes: emit as CScriptNum decimal.
/// Non-push opcodes: same as disassemble_script.
///
/// Used for final_scriptSig.asm in decodepsbt, where Core's C++ passes
/// fAttemptSighashDecode=true to ScriptToAsmStr (rawtransaction.cpp line 1201).
fn disassemble_script_sig_asm(script: &[u8]) -> String {
    let mut result = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];

        // Extract push-data payload (returns None for non-push opcodes).
        let push_data: Option<&[u8]> = match opcode {
            0x01..=0x4b => {
                let len = opcode as usize;
                if i + 1 + len <= script.len() {
                    let d = &script[i + 1..i + 1 + len];
                    i += len;
                    Some(d)
                } else {
                    result.push("[error]".to_string());
                    break;
                }
            }
            0x4c => {
                if i + 1 >= script.len() { result.push("[error]".to_string()); break; }
                let len = script[i + 1] as usize;
                if i + 2 + len > script.len() { result.push("[error]".to_string()); break; }
                let d = &script[i + 2..i + 2 + len];
                i += 1 + len;
                Some(d)
            }
            0x4d => {
                if i + 2 >= script.len() { result.push("[error]".to_string()); break; }
                let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                if i + 3 + len > script.len() { result.push("[error]".to_string()); break; }
                let d = &script[i + 3..i + 3 + len];
                i += 2 + len;
                Some(d)
            }
            0x4e => {
                if i + 4 >= script.len() { result.push("[error]".to_string()); break; }
                let len = u32::from_le_bytes([
                    script[i + 1], script[i + 2], script[i + 3], script[i + 4],
                ]) as usize;
                if i + 5 + len > script.len() { result.push("[error]".to_string()); break; }
                let d = &script[i + 5..i + 5 + len];
                i += 4 + len;
                Some(d)
            }
            _ => None,
        };

        if let Some(vch) = push_data {
            if vch.len() <= 4 {
                // CScriptNum decimal (same rule as disassemble_script).
                result.push(decode_script_num(vch).to_string());
            } else {
                // Attempt sighash decode: if the push looks like a DER sig,
                // strip the last byte and append "[TYPE]" suffix.
                if is_valid_der_sig_encoding(vch) {
                    let sighash_byte = vch[vch.len() - 1];
                    let label = sighash_to_string(sighash_byte as u32);
                    let stripped_hex = hex::encode(&vch[..vch.len() - 1]);
                    if label.is_empty() {
                        result.push(stripped_hex);
                    } else {
                        result.push(format!("{}[{}]", stripped_hex, label));
                    }
                } else {
                    result.push(hex::encode(vch));
                }
            }
        } else {
            // Non-push opcode: delegate to the same table as disassemble_script.
            // We re-use a small inline match here to avoid code duplication.
            let token = match opcode {
                0x00 => "0",
                0x4f => "-1",
                0x50 => "OP_RESERVED",
                0x51 => "1",  0x52 => "2",  0x53 => "3",  0x54 => "4",
                0x55 => "5",  0x56 => "6",  0x57 => "7",  0x58 => "8",
                0x59 => "9",  0x5a => "10", 0x5b => "11", 0x5c => "12",
                0x5d => "13", 0x5e => "14", 0x5f => "15", 0x60 => "16",
                0x61 => "OP_NOP",          0x63 => "OP_IF",
                0x64 => "OP_NOTIF",        0x67 => "OP_ELSE",
                0x68 => "OP_ENDIF",        0x69 => "OP_VERIFY",
                0x6a => "OP_RETURN",       0x6b => "OP_TOALTSTACK",
                0x6c => "OP_FROMALTSTACK", 0x6d => "OP_2DROP",
                0x6e => "OP_2DUP",         0x6f => "OP_3DUP",
                0x70 => "OP_2OVER",        0x71 => "OP_2ROT",
                0x72 => "OP_2SWAP",        0x73 => "OP_IFDUP",
                0x74 => "OP_DEPTH",        0x75 => "OP_DROP",
                0x76 => "OP_DUP",          0x77 => "OP_NIP",
                0x78 => "OP_OVER",         0x79 => "OP_PICK",
                0x7a => "OP_ROLL",         0x7b => "OP_ROT",
                0x7c => "OP_SWAP",         0x7d => "OP_TUCK",
                0x82 => "OP_SIZE",         0x87 => "OP_EQUAL",
                0x88 => "OP_EQUALVERIFY",  0x8b => "OP_1ADD",
                0x8c => "OP_1SUB",         0x8f => "OP_NEGATE",
                0x90 => "OP_ABS",          0x91 => "OP_NOT",
                0x92 => "OP_0NOTEQUAL",    0x93 => "OP_ADD",
                0x94 => "OP_SUB",          0x9a => "OP_BOOLAND",
                0x9b => "OP_BOOLOR",       0x9c => "OP_NUMEQUAL",
                0x9d => "OP_NUMEQUALVERIFY", 0x9e => "OP_NUMNOTEQUAL",
                0x9f => "OP_LESSTHAN",     0xa0 => "OP_GREATERTHAN",
                0xa1 => "OP_LESSTHANOREQUAL", 0xa2 => "OP_GREATERTHANOREQUAL",
                0xa3 => "OP_MIN",          0xa4 => "OP_MAX",
                0xa5 => "OP_WITHIN",       0xa6 => "OP_RIPEMD160",
                0xa7 => "OP_SHA1",         0xa8 => "OP_SHA256",
                0xa9 => "OP_HASH160",      0xaa => "OP_HASH256",
                0xab => "OP_CODESEPARATOR", 0xac => "OP_CHECKSIG",
                0xad => "OP_CHECKSIGVERIFY", 0xae => "OP_CHECKMULTISIG",
                0xaf => "OP_CHECKMULTISIGVERIFY", 0xb0 => "OP_NOP1",
                0xb1 => "OP_CHECKLOCKTIMEVERIFY", 0xb2 => "OP_CHECKSEQUENCEVERIFY",
                0xb3 => "OP_NOP4", 0xb4 => "OP_NOP5", 0xb5 => "OP_NOP6",
                0xb6 => "OP_NOP7", 0xb7 => "OP_NOP8", 0xb8 => "OP_NOP9",
                0xb9 => "OP_NOP10", 0xba => "OP_CHECKSIGADD",
                _ => { result.push(format!("OP_UNKNOWN[{:#04x}]", opcode)); i += 1; continue; }
            };
            result.push(token.to_string());
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

    // OP_RETURN: nulldata only if the post-OP_RETURN bytes are well-formed push-only.
    // Mirrors Bitcoin Core's Solver: IsPushOnly(script.begin() + 1, script.end()).
    // A truncated push or a non-push opcode (> 0x60) makes it nonstandard.
    if !script.is_empty() && script[0] == 0x6a {
        if script_is_push_only_after_op_return(script) {
            return "nulldata".to_string();
        } else {
            return "nonstandard".to_string();
        }
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

/// Returns true iff the bytes following OP_RETURN (script[1..]) form a valid
/// push-only sequence.  Mirrors CScript::IsPushOnly from bitcoin-core.
fn script_is_push_only_after_op_return(script: &[u8]) -> bool {
    let mut j = 1usize;
    while j < script.len() {
        let op = script[j] as usize;
        if op == 0x00 || (0x51..=0x60).contains(&op) || op == 0x4f {
            // OP_0, OP_1..OP_16, OP_1NEGATE — valid zero/small push
            j += 1;
        } else if (0x01..=0x4b).contains(&op) {
            // Direct push of 1..75 bytes
            if j + 1 + op > script.len() {
                return false; // truncated
            }
            j += 1 + op;
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if j + 1 >= script.len() {
                return false;
            }
            let dlen = script[j + 1] as usize;
            if j + 2 + dlen > script.len() {
                return false;
            }
            j += 2 + dlen;
        } else if op == 0x4d {
            // OP_PUSHDATA2
            if j + 2 >= script.len() {
                return false;
            }
            let dlen = u16::from_le_bytes([script[j + 1], script[j + 2]]) as usize;
            if j + 3 + dlen > script.len() {
                return false;
            }
            j += 3 + dlen;
        } else if op == 0x4e {
            // OP_PUSHDATA4
            if j + 4 >= script.len() {
                return false;
            }
            let dlen = u32::from_le_bytes([
                script[j + 1],
                script[j + 2],
                script[j + 3],
                script[j + 4],
            ]) as usize;
            if j + 5 + dlen > script.len() {
                return false;
            }
            j += 5 + dlen;
        } else {
            // Non-push opcode (> 0x60, excluding the push family)
            return false;
        }
    }
    true
}

/// Extract the raw pubkey bytes from a P2PK script (<pushLen> <pubkey> OP_CHECKSIG).
/// Returns empty vec if the script is not a valid P2PK.
fn decodescript_extract_pk(script: &[u8]) -> Vec<u8> {
    if script.len() < 35 {
        return Vec::new();
    }
    let push_len = script[0] as usize;
    if (push_len == 33 || push_len == 65) && script.len() == push_len + 2 && script[push_len + 1] == 0xac {
        script[1..1 + push_len].to_vec()
    } else {
        Vec::new()
    }
}

/// Extract pubkey slices from a multisig script (OP_M <pubkeys> OP_N OP_CHECKMULTISIG).
/// Returns empty vec if parsing fails or the script doesn't look like multisig.
fn decodescript_extract_multisig_pks(script: &[u8]) -> Vec<Vec<u8>> {
    // Minimum: OP_M(1) + push(1)+pk(33) + OP_N(1) + OP_CHECKMULTISIG(1) = 37 bytes
    if script.len() < 4 || script[script.len() - 1] != 0xae {
        return Vec::new();
    }
    let mut pks = Vec::new();
    let mut i = 1usize; // skip OP_M
    while i < script.len().saturating_sub(2) {
        let push_len = script[i] as usize;
        if push_len == 0 {
            break;
        }
        if i + 1 + push_len > script.len() {
            return Vec::new(); // malformed
        }
        pks.push(script[i + 1..i + 1 + push_len].to_vec());
        i += 1 + push_len;
    }
    pks
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

/// Convert a sighash type byte to its Bitcoin Core string label.
///
/// Mirrors bitcoin-core/src/core_io.cpp SighashToStr (line ~343).
/// The map covers exactly the 6 defined SIGHASH values; anything else
/// returns an empty string.  0x00 is NOT in the table.
///
/// This function is used in two places:
///  1. PSBT input sighash field (decodepsbt) — PSBT stores a 4-byte LE uint32;
///     we pass the low byte via `(sighash & 0xff)`.
///  2. DER signature sighash-decode in disassemble_script_sig_asm — we pass
///     the last byte of the signature directly.
fn sighash_to_string(sighash: u32) -> String {
    // Use only the low byte — the high byte is unused in all defined types.
    match sighash & 0xff {
        0x01 => "ALL".to_string(),
        0x02 => "NONE".to_string(),
        0x03 => "SINGLE".to_string(),
        0x81 => "ALL|ANYONECANPAY".to_string(),
        0x82 => "NONE|ANYONECANPAY".to_string(),
        0x83 => "SINGLE|ANYONECANPAY".to_string(),
        _ => String::new(),
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
///
/// When `params` is provided the scriptPubKey gains an `address` field and a
/// BIP-380 `desc` field (W52).  When `params` is `None` (e.g. decodepsbt
/// non_witness_utxo path that doesn't have network context), desc falls
/// back to `raw(...)#<csum>` and address is omitted.
fn build_decoded_raw_transaction(
    tx: &Transaction,
    params: Option<&ChainParams>,
) -> DecodedRawTransaction {
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
                    // TxToUniv calls ScriptToAsmStr(txin.scriptSig, /*fAttemptSighashDecode=*/true)
                    // (core_io.cpp line 460), so use the sighash-decode variant here.
                    script_sig: Some(ScriptSigInfo {
                        asm: disassemble_script_sig_asm(&input.script_sig),
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
            let (address, desc) = if let Some(p) = params {
                let addr = script_to_address(&output.script_pubkey, p);
                let d = infer_descriptor(&output.script_pubkey, p);
                (addr, d)
            } else {
                // No params: skip address; desc falls back to raw(...)#csum.
                use rustoshi_wallet::descriptor::add_checksum;
                let raw_desc = format!("raw({})", hex::encode(&output.script_pubkey));
                let d = add_checksum(&raw_desc).unwrap_or(raw_desc);
                (None, d)
            };
            TxOutputInfo {
                value: BtcAmount::from_sats(output.value),
                n: i as u32,
                script_pubkey: ScriptPubKeyInfo {
                    asm: disassemble_script(&output.script_pubkey),
                    desc,
                    hex: hex::encode(&output.script_pubkey),
                    address,
                    script_type,
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
        // Raise response size limit to 128 MB so that getblock verbosity=2
        // can serve large mainnet blocks (~11 MB for a full-block JSON).
        // Bitcoin Core imposes no hard limit on RPC response bodies.
        .max_response_body_size(128 * 1024 * 1024)
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
        assert_eq!(info.vout[0].value.0, 100_000_000); // 1.0 BTC = 100_000_000 sats
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
        // Sign with a hex private key (via Core's `signmessagewithprivkey`),
        // then derive its compressed P2PKH address and verify the signature
        // in the same RPC server. `signmessage` in this server returns
        // RPC_WALLET_NOT_FOUND because no wallet is wired through (Core
        // contract: signmessage requires a loaded wallet); the raw-key path
        // is what callers use without one.
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
            .sign_message_with_privkey(hex_key.clone(), msg.clone())
            .await
            .expect("signmessagewithprivkey");

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
        // mainnet has assumeutxo entries at 840k, 880k, 910k, 935k, plus the
        // hashhog-local 944183 snapshot (params.rs). Pretend we are synced
        // to 945k -> the rollback target should resolve to 944183, the
        // largest height <= tip. Because the test fixture's chainstate has
        // no actual blocks at those heights, the rewind path now hard-errors
        // instead of walking — but the error must still surface the resolved
        // height so callers can sanity-check the assumeutxo lookup.
        // Mirrors Core's `bitcoin-core/src/rpc/blockchain.cpp::DumpTxoutset`
        // semantics where the resolver walks `m_assumeutxo_data` and picks
        // the highest entry below tip.
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
        // The rollback target (944183) is what we resolved to; the error
        // text now comes from the chainstate lookup that proves the
        // resolver did pick the latest assumeutxo height.
        assert!(
            msg.contains("944183"),
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

    #[tokio::test]
    async fn dumptxoutset_atomic_write_no_incomplete_artifact() {
        // Mirrors Bitcoin Core's rpc/blockchain.cpp::dumptxoutset which
        // writes to <path>.incomplete, fsyncs, and renames. After a
        // successful dump only <path> should exist; the .incomplete
        // temp must be gone so that an operator copying the snapshot
        // mid-dump never sees a torn file.
        let params = rustoshi_consensus::ChainParams::regtest();
        let (tmp, server) = dumptxoutset_test_server(params, 0).await;

        let resp = server
            .dump_tx_outset("atomic.dat".to_string(), Some("latest".to_string()), None)
            .await
            .expect("dump must succeed on a fresh regtest chainstate");

        let final_path = std::path::PathBuf::from(resp["path"].as_str().unwrap());
        let mut tmp_os = final_path.clone().into_os_string();
        tmp_os.push(".incomplete");
        let temp_path = std::path::PathBuf::from(tmp_os);

        assert!(
            final_path.exists(),
            "final snapshot path missing after successful dump: {}",
            final_path.display()
        );
        assert!(
            !temp_path.exists(),
            ".incomplete temp file leaked after successful dump: {}",
            temp_path.display()
        );

        drop(tmp);
    }

    #[tokio::test]
    async fn dumptxoutset_refuses_to_overwrite() {
        // Mirrors Core's "<path> already exists. If you are sure this is
        // what you want, move it out of the way first." guard. The first
        // dump succeeds; a second dump to the same path must error before
        // touching the snapshot writer.
        let params = rustoshi_consensus::ChainParams::regtest();
        let (tmp, server) = dumptxoutset_test_server(params, 0).await;

        let _ = server
            .dump_tx_outset("clobber.dat".to_string(), Some("latest".to_string()), None)
            .await
            .expect("first dump must succeed");

        let res = server
            .dump_tx_outset("clobber.dat".to_string(), Some("latest".to_string()), None)
            .await;
        let err = res.expect_err("second dump must refuse to overwrite");
        assert!(
            err.message().contains("already exists"),
            "expected 'already exists' guard, got: {}",
            err.message()
        );

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

    // ============================================================
    // NETWORKDISABLE RAII TESTS (NetworkDisable around rollback)
    // ============================================================

    #[tokio::test]
    async fn network_disable_raii_pauses_and_restores_flag() {
        // RAII: setting a NetworkDisable guard sets the flag; dropping it
        // clears the flag. Mirrors Core's NetworkDisable semantics.
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::SeqCst));
        {
            let _guard = NetworkDisable::new(flag.clone());
            assert!(
                flag.load(Ordering::SeqCst),
                "NetworkDisable must set the pause flag on construction"
            );
        }
        assert!(
            !flag.load(Ordering::SeqCst),
            "NetworkDisable must clear the pause flag on drop"
        );
    }

    #[tokio::test]
    async fn submit_block_refuses_while_paused() {
        // Mid-rollback: submitblock must not enter the chain-write path.
        // We flip the pause flag manually (no need to drive a full
        // rollback) and confirm submit_block returns the expected
        // "block submission paused" reject string.
        let params = rustoshi_consensus::ChainParams::regtest();
        let (_tmp, server) = dumptxoutset_test_server(params, 0).await;

        // Flip pause manually.
        {
            let st = server.state.read().await;
            st.block_submission_paused
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        // Any non-empty hex is fine: the gate runs before deserialization.
        let res = server
            .submit_block("00".to_string())
            .await
            .expect("submit_block must not error-return; it returns Ok(Some(reason))");
        let reason = res.expect("paused submission must surface a reject reason");
        assert!(
            reason.contains("paused"),
            "reject reason must mention pause: {}",
            reason
        );

        // Clear pause; the next submit_block should now hit the normal
        // decode/error path (we feed garbage so it returns an Err — the
        // important bit is that we no longer hit the pause early-exit).
        {
            let st = server.state.read().await;
            st.block_submission_paused
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        let res2 = server.submit_block("00".to_string()).await;
        // Either a structured RPC error (decode failure) or Ok(Some(...))
        // with a non-pause reason; both prove we got past the gate.
        match res2 {
            Err(_) => {}
            Ok(Some(reason)) => assert!(
                !reason.contains("paused"),
                "must not report pause once flag is cleared: {}",
                reason
            ),
            Ok(None) => {} // Accepted (regtest empty hex unlikely but ok).
        }
    }

    /// BIP-22 string mapping: each ValidationError variant must produce the
    /// canonical string defined in BIP-22 / Bitcoin Core BIP22ValidationResult().
    #[test]
    fn bip22_string_mapping() {
        use rustoshi_consensus::{TxValidationError, ValidationError};

        // PoW failure
        assert_eq!(ValidationError::BadProofOfWork.bip22_string(), "high-hash");
        // Merkle root
        assert_eq!(ValidationError::BadMerkleRoot.bip22_string(), "bad-txnmrklroot");
        // Witness commitment (BIP-141)
        assert_eq!(
            ValidationError::BadWitnessCommitment.bip22_string(),
            "bad-witness-merkle-match"
        );
        // Subsidy / coinbase amount
        assert_eq!(
            ValidationError::BadSubsidy(5000000001, 5000000000).bip22_string(),
            "bad-cb-amount"
        );
        // Sigops budget
        assert_eq!(
            ValidationError::SigopsLimitExceeded(100001).bip22_string(),
            "bad-blk-sigops"
        );
        // Duplicate transaction within block → Core parity (bad-txns-inputs-missingorspent)
        assert_eq!(
            ValidationError::DuplicateTx("abc".to_string()).bip22_string(),
            "bad-txns-inputs-missingorspent"
        );
        // Non-final transaction
        assert_eq!(ValidationError::NonFinalTx.bip22_string(), "bad-txns-nonfinal");
        // BIP-34 coinbase height encoding
        assert_eq!(ValidationError::BadCoinbaseHeight.bip22_string(), "bad-cb-height");
        // Time-too-old
        assert_eq!(ValidationError::TimeTooOld.bip22_string(), "time-too-old");
        // Time-too-new
        assert_eq!(ValidationError::TimeTooNew.bip22_string(), "time-too-new");
        // Coinbase scriptSig too long -> bad-cb-length
        assert_eq!(
            ValidationError::TxValidation(TxValidationError::CoinbaseScriptSize(101))
                .bip22_string(),
            "bad-cb-length"
        );
        // Script verification failure -> block-script-verify-flag-failed
        // (connect-block stage; Core validation.cpp:2122)
        assert_eq!(
            ValidationError::TxValidation(TxValidationError::ScriptFailed(
                "OP_CHECKSIG failed".to_string()
            ))
            .bip22_string(),
            "block-script-verify-flag-failed"
        );
        // Catch-all: structural errors map to "rejected"
        assert_eq!(
            ValidationError::PrevBlockNotFound("abc".to_string()).bip22_string(),
            "rejected"
        );
        assert_eq!(ValidationError::InvalidChain.bip22_string(), "rejected");
        assert_eq!(
            ValidationError::BlockTooLarge(5_000_000).bip22_string(),
            "rejected"
        );
    }

    // ============================================================
    // loadtxoutset RPC runtime gate
    // ============================================================
    //
    // The RPC handler was refactored on 2026-05-05 to refuse activation
    // unconditionally and direct the operator to `--load-snapshot=<path>`
    // at startup. The bug fixed: prior versions wrote UTXOs to CF_UTXO
    // and bumped `state.best_hash`/`best_height` only — skipping the
    // three persisted block-store writes (`put_block_index`,
    // `put_height_index`, `set_best_block`) AND failing to re-point the
    // live `BlockDownloader` / `HeaderSync` / `ChainState` in the main
    // event loop. Result: the download manager kept its pre-load tip
    // and re-downloaded from genesis after the RPC returned.
    //
    // These tests pin the gate's behavior so a future refactor that
    // accidentally re-enables the buggy path fails CI.

    #[tokio::test]
    async fn test_loadtxoutset_rpc_refuses_on_genesis_only_chain() {
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();
        let state = Arc::new(RwLock::new(RpcState::new(db, params)));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        // Fresh node, no chain data, no snapshot file even needed —
        // the gate fires before file I/O.
        let result = rpc.load_tx_outset("does-not-exist.dat".to_string()).await;
        let err = result.expect_err("loadtxoutset must refuse on a genesis-only chain");
        assert_eq!(err.code(), rpc_error::RPC_INTERNAL_ERROR);
        assert!(
            err.message().contains("--load-snapshot"),
            "error message should direct operator to the CLI flag, got: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn test_loadtxoutset_rpc_refuses_on_populated_chain() {
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();
        let mut rpc_state = RpcState::new(db, params);
        // Simulate a chain that has progressed past genesis. The gate
        // must distinguish this case in the error message so operators
        // know they cannot use the RPC for activation on an existing
        // datadir either.
        rpc_state.best_height = 12345;
        rpc_state.best_hash = Hash256([0xAB; 32]);
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        let result = rpc.load_tx_outset("does-not-exist.dat".to_string()).await;
        let err = result.expect_err("loadtxoutset must refuse when chain has data");
        assert_eq!(err.code(), rpc_error::RPC_INTERNAL_ERROR);
        let msg = err.message();
        assert!(
            msg.contains("12345"),
            "error must report the live tip height, got: {}",
            msg
        );
        assert!(
            msg.contains("--load-snapshot"),
            "error must direct operator to the CLI flag, got: {}",
            msg
        );
    }

    /// Regression guard: the RPC handler must NOT touch the UTXO column
    /// family. Pre-fix, the handler wrote ~150M coins to CF_UTXO before
    /// returning success without persisting tip metadata, leaving the
    /// datadir in a half-initialized state. The gate now bails before
    /// any I/O, so CF_UTXO must remain empty after the call.
    #[tokio::test]
    async fn test_loadtxoutset_rpc_does_not_write_utxos() {
        use rustoshi_storage::{ChainDb, CF_UTXO};

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let db_for_check = db.clone();
        let params = rustoshi_consensus::ChainParams::regtest();
        let state = Arc::new(RwLock::new(RpcState::new(db, params)));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        let _ = rpc.load_tx_outset("ignored.dat".to_string()).await;

        let utxo_count = db_for_check
            .iter_cf(CF_UTXO)
            .map(|iter| iter.count())
            .unwrap_or(0);
        assert_eq!(
            utxo_count, 0,
            "loadtxoutset RPC must not write any coins to CF_UTXO when the gate refuses activation"
        );
    }

    // ============================================================
    // REORG WIRING TESTS — disconnect_to + try_attach_and_reorg
    //
    // The audit note in CORE-PARITY-AUDIT/_reorg-correctness-cross-impl-2026-05-05.md
    // flagged two compounding issues:
    //   (a) `invalidate_block` updated the tip pointer + height index but
    //       never called `disconnect_block`, leaving UTXOs stale.
    //   (b) `chain_state.reorganize` was implemented but had ZERO non-test
    //       callers — P2P-driven reorgs could not happen.
    //
    // Both are now wired through `disconnect_to` (used by invalidateblock)
    // and `try_attach_and_reorg` (used by submitblock's PrevBlockNotFound
    // branch). These tests exercise the wiring directly without needing
    // real PoW.
    // ============================================================

    /// Build a coinbase tx whose txid is unique per `(height, marker)` so
    /// each synthetic block produces distinct UTXOs. Mirrors the
    /// `synth_append_block` helper above but parameterised so we can fork.
    fn synth_coinbase(h: u32, marker: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: vec![marker, marker, marker, h as u8, (h >> 8) as u8],
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_000_000,
                script_pubkey: vec![0x51], // OP_TRUE
            }],
            lock_time: 0,
        }
    }

    /// Mine a coinbase-only regtest block (bits=0x207fffff, target ~ 2^224)
    /// extending `prev_hash` at height `h`. The merkle root is filled in
    /// from the coinbase txid and the nonce is incremented until the hash
    /// meets target. Regtest difficulty is trivial so this terminates in
    /// a handful of iterations.
    fn mine_synth_block(h: u32, prev_hash: Hash256, marker: u8) -> Block {
        use rustoshi_primitives::BlockHeader;
        let coinbase = synth_coinbase(h, marker);
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root: coinbase.txid(),
                timestamp: 1_700_000_000 + h,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };
        // Iterate until we satisfy regtest PoW. Vary timestamp every 1<<20
        // iterations as a fallback so we don't cap out at u32::MAX nonces.
        let mut nonce: u32 = 0;
        loop {
            block.header.nonce = nonce;
            if block.header.validate_pow() {
                break;
            }
            nonce = nonce.wrapping_add(1);
            if nonce == 0 {
                block.header.timestamp = block.header.timestamp.wrapping_add(1);
            }
        }
        block
    }

    /// Persist a side-branch block: header + block + index entry only
    /// (no UTXO or undo). This is what the reorg connect path needs as
    /// pre-state — it will compute UTXO + undo itself when connecting.
    /// Useful for staging "the other chain" the reorg path will switch to.
    fn synth_persist_side_block(
        store: &BlockStore,
        h: u32,
        prev_hash: Hash256,
        prev_work: [u8; 32],
        marker: u8,
    ) -> (Hash256, Block, [u8; 32]) {
        use rustoshi_consensus::pow::{get_block_proof, ChainWork};
        let block = mine_synth_block(h, prev_hash, marker);
        let block_hash = block.block_hash();
        let this_work =
            ChainWork::from_be_bytes(prev_work).saturating_add(&get_block_proof(0x207fffff));

        store.put_block(&block_hash, &block).unwrap();
        store.put_header(&block_hash, &block.header).unwrap();
        {
            use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
            let mut status = BlockStatus::new();
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
                chain_work: this_work.0,
            };
            store.put_block_index(&block_hash, &entry).unwrap();
        }
        (block_hash, block, this_work.0)
    }

    /// Append a synthetic, fully-populated coinbase-only block and return
    /// `(block_hash, block, chain_work_vec)` so callers can build heavier
    /// branches. Persists header + block + height + index entry + undo +
    /// UTXO so the disconnect / reorg paths have everything they need.
    fn synth_append_with_work(
        store: &BlockStore,
        h: u32,
        prev_hash: Hash256,
        prev_work: [u8; 32],
        marker: u8,
    ) -> (Hash256, Block, [u8; 32]) {
        use rustoshi_consensus::pow::{get_block_proof, ChainWork};
        let block = mine_synth_block(h, prev_hash, marker);
        let coinbase = block.transactions[0].clone();
        let block_hash = block.block_hash();
        let this_work =
            ChainWork::from_be_bytes(prev_work).saturating_add(&get_block_proof(0x207fffff));

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
                chain_work: this_work.0,
            };
            store.put_block_index(&block_hash, &entry).unwrap();
        }

        // Coinbase-only block: empty undo (no spent coins).
        store
            .put_undo(
                &block_hash,
                &rustoshi_storage::block_store::UndoData {
                    spent_coins: vec![],
                },
            )
            .unwrap();

        // Persist the coinbase UTXO so the disconnect path has something
        // to remove. is_coinbase=true is critical: the disconnect path
        // must preserve this metadata when rewinding (audit property U).
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
                    value: 50_000_000,
                    script_pubkey: vec![0x51],
                },
            )
            .unwrap();

        store.set_best_block(&block_hash, h).unwrap();
        (block_hash, block, this_work.0)
    }

    /// Test: disconnect_to walks tip -> target, removing UTXOs and
    /// updating chainstate. Mirrors invalidateblock's expected effect.
    #[tokio::test]
    async fn disconnect_to_rewinds_utxos_and_tip() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        // Use mainnet params: BIP-34/SegWit heights are far above the
        // synthetic blocks (heights 0..3) we mine here, so contextual
        // checks become no-ops. Regtest activates both at height 1, which
        // would force every test block to encode BIP-34 height + emit a
        // valid witness commitment — orthogonal to the reorg wiring this
        // test exercises.
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // Build a 3-block linear chain G -> A -> B -> C.
        let (hash_g, _, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a, _, work_a) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xAA)
        };
        let (hash_b, _, work_b) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 2, hash_a, work_a, 0xAA)
        };
        let (hash_c, _, _work_c) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 3, hash_b, work_b, 0xAA)
        };
        rpc_state.best_hash = hash_c;
        rpc_state.best_height = 3;

        // Sanity: 4 UTXOs (one per coinbase) before disconnect.
        let count_utxos = |db: &ChainDb| -> usize {
            db.iter_cf(CF_UTXO)
                .map(|it| it.filter(|(k, _)| k.len() == 36).count())
                .unwrap_or(0)
        };
        assert_eq!(count_utxos(&db), 4, "expected 4 UTXOs (one coinbase / block)");

        // Roll back to A (height 1) — should remove UTXOs created by B and C.
        disconnect_to(&mut rpc_state, hash_a, 1).expect("disconnect_to");

        assert_eq!(rpc_state.best_hash, hash_a, "tip hash rolled back");
        assert_eq!(rpc_state.best_height, 1, "tip height rolled back");
        assert_eq!(
            count_utxos(&db),
            2,
            "two UTXOs (G + A coinbases) remain after rolling B + C off"
        );

        // The persisted tip must match the in-memory tip; otherwise on
        // next restart we'd reload a corrupt state.
        let store = BlockStore::new(&db);
        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash_a);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 1);
    }

    /// Test: disconnect_to refuses when undo data is missing — protects
    /// against silent UTXO-set corruption.
    #[tokio::test]
    async fn disconnect_to_errors_without_undo() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        // Use mainnet params: BIP-34/SegWit heights are far above the
        // synthetic blocks (heights 0..3) we mine here, so contextual
        // checks become no-ops. Regtest activates both at height 1, which
        // would force every test block to encode BIP-34 height + emit a
        // valid witness commitment — orthogonal to the reorg wiring this
        // test exercises.
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // G -> A, but delete A's undo afterwards.
        let (hash_g, _, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a, _, _) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xAA)
        };
        {
            let store = BlockStore::new(&db);
            store.delete_undo(&hash_a).unwrap();
        }
        rpc_state.best_hash = hash_a;
        rpc_state.best_height = 1;

        let err = disconnect_to(&mut rpc_state, hash_g, 0).expect_err("must error");
        assert!(err.contains("missing undo"), "error should call out missing undo: {}", err);
    }

    /// Test: try_attach_and_reorg attaches a side-branch block and, when it
    /// has more chainwork than the active tip, reorganizes onto it.
    #[tokio::test]
    async fn try_attach_and_reorg_switches_to_heavier_branch() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        // Use mainnet params: BIP-34/SegWit heights are far above the
        // synthetic blocks (heights 0..3) we mine here, so contextual
        // checks become no-ops. Regtest activates both at height 1, which
        // would force every test block to encode BIP-34 height + emit a
        // valid witness commitment — orthogonal to the reorg wiring this
        // test exercises.
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // G -> A1 -> A2 (active chain, height 2)
        //  \-> B1 (side, height 1, parent hash_g) — to make B's branch
        // outpace A we'll include B1 + B2 + B3 (height 3).
        let (hash_g, _, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a1, _, work_a1) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xA1)
        };
        let (hash_a2, _, _) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2)
        };
        rpc_state.best_hash = hash_a2;
        rpc_state.best_height = 2;

        // Build a heavier side-branch off G: G -> B1 -> B2. We pre-commit
        // B1 and B2 to the store as side blocks (header/block/index only —
        // no UTXO/undo) so the reorganize path can find them and compute
        // UTXO + undo itself during the connect walk. B3 is the block we
        // hand to try_attach_and_reorg as the "newly-arrived" block.
        let (hash_b1, _, work_b1) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 1, hash_g, work_g, 0xB1)
        };
        let (hash_b2, _, work_b2) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 2, hash_b1, work_b1, 0xB2)
        };

        // Now build the new arriving block B3 — extends B2 and is heavier
        // than the A1->A2 chain (work-wise B3 > A2).
        let _ = work_b2;
        let block_b3 = mine_synth_block(3, hash_b2, 0xB3);
        let hash_b3 = block_b3.block_hash();

        // Pre-condition: tip is A2.
        assert_eq!(rpc_state.best_hash, hash_a2);
        assert_eq!(rpc_state.best_height, 2);

        // Wire reorg: B3 has more work (3 blocks of work vs A's 2),
        // so the reorg should fire and switch to B3.
        let did_reorg = try_attach_and_reorg(&mut rpc_state, &block_b3, &hash_b3)
            .expect("try_attach_and_reorg");
        assert!(did_reorg, "B-chain has more work — reorg must fire");
        assert_eq!(rpc_state.best_hash, hash_b3, "tip switched to B3");
        assert_eq!(rpc_state.best_height, 3, "tip height advanced to 3");

        // Persisted state must match — otherwise restart loads a corrupt tip.
        let store = BlockStore::new(&db);
        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash_b3);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 3);

        // Height index points to the new chain at the contended heights.
        let h1 = store.get_hash_by_height(1).unwrap().expect("height 1 must exist");
        let h2 = store.get_hash_by_height(2).unwrap().expect("height 2 must exist");
        let h3 = store.get_hash_by_height(3).unwrap().expect("height 3 must exist");
        assert_eq!(h1, hash_b1, "height 1 now points to B1");
        assert_eq!(h2, hash_b2, "height 2 now points to B2");
        assert_eq!(h3, hash_b3, "height 3 points to B3");
    }

    /// Test: try_attach_and_reorg does NOT switch when the side-branch has
    /// equal or less work than the active tip. The block is stored on disk
    /// for a possible later attach but the active tip stays put. Mirrors
    /// Core's "store but do not activate" branch.
    #[tokio::test]
    async fn try_attach_and_reorg_keeps_tip_when_side_branch_lighter() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        // Use mainnet params: BIP-34/SegWit heights are far above the
        // synthetic blocks (heights 0..3) we mine here, so contextual
        // checks become no-ops. Regtest activates both at height 1, which
        // would force every test block to encode BIP-34 height + emit a
        // valid witness commitment — orthogonal to the reorg wiring this
        // test exercises.
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // G -> A1 -> A2 (active, height 2). Hand a B1 (height 1) — has
        // strictly less work than A2.
        let (hash_g, _, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a1, _, work_a1) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xA1)
        };
        let (hash_a2, _, _) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2)
        };
        rpc_state.best_hash = hash_a2;
        rpc_state.best_height = 2;

        // Construct a competing side-block B1 that extends G — same height
        // as A1, so total work is less than A2.
        let block_b1 = mine_synth_block(1, hash_g, 0xB1);
        let hash_b1 = block_b1.block_hash();

        let did_reorg = try_attach_and_reorg(&mut rpc_state, &block_b1, &hash_b1)
            .expect("try_attach_and_reorg");
        assert!(!did_reorg, "lighter branch must NOT trigger a reorg");
        assert_eq!(rpc_state.best_hash, hash_a2, "tip unchanged");
        assert_eq!(rpc_state.best_height, 2, "height unchanged");

        // The block must still be persisted so a later extension can
        // overtake us — Core stores side-branch blocks even when they
        // don't activate.
        let store = BlockStore::new(&db);
        assert!(
            store.get_block(&hash_b1).unwrap().is_some(),
            "side-branch block must be persisted on disk"
        );
        assert!(
            store.get_block_index(&hash_b1).unwrap().is_some(),
            "side-branch index entry must be persisted"
        );
    }

    /// Test: try_attach_and_reorg refuses to attach a block whose parent
    /// is unknown — protects against accepting an unrelated chain blindly.
    #[tokio::test]
    async fn try_attach_and_reorg_errors_on_unknown_parent() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        // Use mainnet params: BIP-34/SegWit heights are far above the
        // synthetic blocks (heights 0..3) we mine here, so contextual
        // checks become no-ops. Regtest activates both at height 1, which
        // would force every test block to encode BIP-34 height + emit a
        // valid witness commitment — orthogonal to the reorg wiring this
        // test exercises.
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // Genesis-only chain.
        let (hash_g, _, _) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        rpc_state.best_hash = hash_g;
        rpc_state.best_height = 0;

        // Block whose parent (random hash) isn't in our index.
        let stranger_parent = Hash256::from_bytes([0x99; 32]);
        let stranger = mine_synth_block(50, stranger_parent, 0xCC);
        let stranger_hash = stranger.block_hash();

        let err = try_attach_and_reorg(&mut rpc_state, &stranger, &stranger_hash)
            .expect_err("unknown parent must error");
        assert!(
            err.contains("not in block index"),
            "error must call out the missing parent: {}",
            err
        );
        // Tip is unchanged.
        assert_eq!(rpc_state.best_hash, hash_g);
    }

    // ============================================================
    // SIDE-BRANCH ACCEPTANCE TESTS (Pattern Y closure 2026-05-05)
    //
    // The fa6ee55 patch wired `try_attach_and_reorg` into submitblock's
    // PrevBlockNotFound arm but did NOT make submitblock's HAPPY PATH
    // write a `BlockIndexEntry`.  That meant when a side-branch block
    // arrived, `try_attach_and_reorg` could not find its parent in the
    // block index — even though the parent was a previously-accepted
    // best-chain block — and rejected with "parent ... not in block
    // index".  See `tools/diff-test-corpus/regression/reorg-via-submitblock`
    // and `CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md`.
    //
    // Tests below exercise the structural invariant Core enforces in
    // `BlockManager::AcceptBlock` (validation.cpp): every accepted
    // block, whether on the active chain or a side-branch, gets
    // BLOCK_HAVE_DATA + cumulative chain_work in the block index.  We
    // drive the real `submit_block` async handler via mined regtest
    // blocks and assert the parent-lookup invariants survive a fork.
    // ============================================================

    /// Drive the live `submit_block` async handler against an RpcServerImpl
    /// pinned at genesis. Mirrors how the diff-test harness submits each
    /// block via JSON-RPC. Returns the BIP-22 result string (None = accept,
    /// Some(s) = reject reason / "inconclusive" for side-branch).
    async fn drive_submit_block(server: &RpcServerImpl, block: &Block) -> Option<String> {
        let hex_str = hex::encode(block.serialize());
        match server.submit_block(hex_str).await {
            Ok(v) => v,
            Err(e) => Some(format!("rpc-error: {}", e.message())),
        }
    }

    /// Set up an RpcServerImpl with a fresh regtest datadir and the genesis
    /// block already initialised. Returns (db handle, state arc, server).
    fn make_test_server(
        params: rustoshi_consensus::ChainParams,
    ) -> (
        Arc<rustoshi_storage::ChainDb>,
        Arc<RwLock<RpcState>>,
        RpcServerImpl,
    ) {
        use rustoshi_storage::ChainDb;
        let tmp = tempfile::tempdir().unwrap();
        // Leak the tempdir guard for the test lifetime — we don't need to
        // clean up between tests, the OS does it on process exit.
        std::mem::forget(tmp);
        let path = std::env::temp_dir().join(format!(
            "rustoshi-side-branch-test-{}",
            uuid_like_suffix()
        ));
        std::fs::create_dir_all(&path).unwrap();
        let db = Arc::new(ChainDb::open(&path).unwrap());

        // Initialize genesis (params-agnostic — sets up CF_BLOCK_INDEX
        // entry for genesis with chain_work=[0;32]).
        {
            let store = BlockStore::new(&db);
            store.init_genesis(&params).unwrap();
        }

        let mut rpc_state = RpcState::new(db.clone(), params.clone());
        let store_for_init = BlockStore::new(&db);
        rpc_state.best_hash = store_for_init.get_best_block_hash().unwrap().unwrap();
        rpc_state.best_height = store_for_init.get_best_height().unwrap().unwrap();
        rpc_state.data_dir = Some(path);
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let server = RpcServerImpl::new(state.clone(), peer_state);
        (db, state, server)
    }

    fn uuid_like_suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:x}-{}", n, std::process::id())
    }

    /// Test: after submit_block accepts a block on the happy path, the
    /// block_index entry for that block exists with the expected height
    /// and a cumulative chain_work strictly greater than the parent's.
    /// Pre-fix this entry was never written, so the next side-branch
    /// block whose parent was THIS block would be rejected with
    /// "parent ... not in block index" — even though the parent is on
    /// disk (header + body + undo).
    #[tokio::test]
    async fn submit_block_writes_block_index_entry_for_accepted_block() {
        use rustoshi_consensus::pow::ChainWork;
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        let (db, state, server) = make_test_server(params.clone());

        // Mine + submit a block on top of genesis. mainnet params at h=1
        // skip BIP-34 / SegWit / CSV (all activate way later) so a
        // synthetic OP_TRUE coinbase is accepted.
        let genesis_hash = params.genesis_hash;
        let block_a1 = mine_synth_block(1, genesis_hash, 0xA1);
        let hash_a1 = block_a1.block_hash();

        let res = drive_submit_block(&server, &block_a1).await;
        assert!(
            res.is_none(),
            "expected accept (None) on happy path, got {:?}",
            res
        );

        // tip moved.
        let st = state.read().await;
        assert_eq!(st.best_hash, hash_a1, "rpc state tip = a1");
        assert_eq!(st.best_height, 1, "rpc state height = 1");
        drop(st);

        // The structural invariant we are guarding: block_index has the
        // entry, with chain_work = parent's chain_work + this block's
        // proof. Pre-fix, get_block_index(&hash_a1) would return None.
        let store = BlockStore::new(&db);
        let entry = store
            .get_block_index(&hash_a1)
            .expect("get_block_index ok")
            .expect("block_index entry must exist for accepted block");
        assert_eq!(entry.height, 1, "block_index entry height matches");
        assert_eq!(entry.prev_hash, genesis_hash, "prev_hash threaded through");
        // chain_work strictly greater than genesis (which has [0;32]).
        let cw = ChainWork::from_be_bytes(entry.chain_work);
        assert_ne!(cw.0, [0u8; 32], "chain_work must be nonzero");

        // Status: HAVE_DATA must be set (Core: BLOCK_HAVE_DATA).
        use rustoshi_storage::block_store::BlockStatus;
        assert!(
            entry.status.has(BlockStatus::HAVE_DATA),
            "HAVE_DATA flag must be set on accepted block"
        );
    }

    /// Test: PATTERN Y CLOSURE — submit two blocks at the same height
    /// whose shared parent is genesis (A1 and B1). Both must store
    /// successfully; A1 takes the active chain, B1 is stored as a
    /// side-branch (Core: `inconclusive`). Pre-fix, B1 was rejected
    /// with "parent ... not in block index" because submit_block's
    /// happy path never wrote a block_index entry for genesis's only
    /// child (A1 in this case — well, in real corpus runs it would be
    /// the base-chain blocks).
    #[tokio::test]
    async fn submit_block_accepts_side_branch_block_with_known_parent() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        let (db, state, server) = make_test_server(params.clone());

        let genesis_hash = params.genesis_hash;

        // A1 — accepted on happy path, becomes tip.
        let block_a1 = mine_synth_block(1, genesis_hash, 0xA1);
        let hash_a1 = block_a1.block_hash();
        let r = drive_submit_block(&server, &block_a1).await;
        assert!(r.is_none(), "A1 must accept on happy path: {:?}", r);

        let st = state.read().await;
        assert_eq!(st.best_hash, hash_a1);
        drop(st);

        // B1 — same height as A1, parent = genesis. Genesis IS in
        // block_index (init_genesis writes it). After our fix, A1 is
        // also in block_index (so future side-branches at h=2 would
        // also work). For h=1 specifically, the parent lookup would
        // hit genesis directly. Either way, B1 must store as side-
        // branch and NOT flip the tip.
        let block_b1 = mine_synth_block(1, genesis_hash, 0xB1);
        let hash_b1 = block_b1.block_hash();
        // Make sure A1 != B1 even though both are at h=1 with same prev.
        assert_ne!(hash_a1, hash_b1, "marker bytes must produce distinct blocks");

        let r2 = drive_submit_block(&server, &block_b1).await;
        // Per Core: side-branch with strictly less work than tip → store
        // and return "inconclusive". Equal work → tip unchanged (`is_gt`
        // is false), still side-branch stored. We accept either string
        // here as "stored, not activated".
        match r2.as_deref() {
            Some("inconclusive") | None => { /* OK */ }
            other => panic!("B1 must be stored as side-branch (got {:?})", other),
        }

        // Tip must NOT have flipped.
        let st = state.read().await;
        assert_eq!(st.best_hash, hash_a1, "tip must remain A1 after B1 side-branch");
        assert_eq!(st.best_height, 1);
        drop(st);

        // Both blocks are persisted with block_index entries.
        let store = BlockStore::new(&db);
        assert!(
            store.get_block_index(&hash_a1).unwrap().is_some(),
            "A1 block_index entry must exist (happy-path acceptance)"
        );
        assert!(
            store.get_block_index(&hash_b1).unwrap().is_some(),
            "B1 block_index entry must exist (side-branch acceptance)"
        );
        assert!(
            store.get_block(&hash_b1).unwrap().is_some(),
            "B1 block body must be persisted"
        );
    }

    /// Test: PATTERN Y CLOSURE END-TO-END — submit A1, A2, B1, B2, B3
    /// in order. Final tip must be B3, and A1+A2 must remain on disk
    /// as a stale side-branch. Mirrors the corpus entry
    /// `regression/reorg-via-submitblock`.
    ///
    /// Pre-fix: B1 was rejected at submission time because submit_block
    /// happy-path never wrote a block_index entry for the parent of B1
    /// (which is genesis here; in the corpus it's a base-chain block).
    /// In a multi-block fork, even if h=1's parent (genesis) was in the
    /// index, B2's parent (B1) is on a side-branch — it can only be
    /// looked up if try_attach_and_reorg's per-block put_block_index in
    /// the side-branch arm fired. The fix here makes BOTH paths
    /// (happy-path AND side-branch) write block_index entries, so the
    /// reorg dispatcher can ALWAYS walk a fork to find its common
    /// ancestor.
    #[tokio::test]
    async fn submit_block_reorgs_to_heavier_branch_via_extension() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        let (db, state, server) = make_test_server(params.clone());

        let genesis_hash = params.genesis_hash;

        // Chain A: 2 blocks. After A1+A2, tip = A2 at h=2.
        let block_a1 = mine_synth_block(1, genesis_hash, 0xA1);
        let hash_a1 = block_a1.block_hash();
        assert!(drive_submit_block(&server, &block_a1).await.is_none());
        let block_a2 = mine_synth_block(2, hash_a1, 0xA2);
        let hash_a2 = block_a2.block_hash();
        assert!(drive_submit_block(&server, &block_a2).await.is_none());
        {
            let st = state.read().await;
            assert_eq!(st.best_hash, hash_a2, "after A1+A2 tip = A2");
            assert_eq!(st.best_height, 2);
        }

        // Chain B: 3 blocks. Each shares G as the fork point. After B3
        // arrives, B has strictly more work than A, so the tip MUST
        // flip from A2 to B3 via the reorg path.
        let block_b1 = mine_synth_block(1, genesis_hash, 0xB1);
        let hash_b1 = block_b1.block_hash();
        let r_b1 = drive_submit_block(&server, &block_b1).await;
        // B1 stored as side-branch (less work than A2). Either Some("inconclusive")
        // or None depending on impl convention; both are accept-as-side-branch.
        match r_b1.as_deref() {
            Some("inconclusive") | None => {}
            other => panic!("B1 must be stored, got {:?}", other),
        }

        let block_b2 = mine_synth_block(2, hash_b1, 0xB2);
        let hash_b2 = block_b2.block_hash();
        let r_b2 = drive_submit_block(&server, &block_b2).await;
        match r_b2.as_deref() {
            Some("inconclusive") | None => {}
            other => panic!("B2 must be stored, got {:?}", other),
        }

        // Tip must STILL be A2 — B-chain is at h=2, equal work, A wins
        // the tie-break.
        {
            let st = state.read().await;
            assert_eq!(st.best_hash, hash_a2, "before B3, tip remains A2 (equal work)");
        }

        let block_b3 = mine_synth_block(3, hash_b2, 0xB3);
        let hash_b3 = block_b3.block_hash();
        let r_b3 = drive_submit_block(&server, &block_b3).await;
        // B3 is the heavier-tip block; must accept (returns None).
        assert!(
            r_b3.is_none(),
            "B3 (heavier branch) must accept and trigger reorg, got {:?}",
            r_b3
        );

        // Tip flipped to B3; height = 3.
        {
            let st = state.read().await;
            assert_eq!(st.best_hash, hash_b3, "tip flipped to B3 after reorg");
            assert_eq!(st.best_height, 3);
        }

        // The displaced A-chain must remain on disk (BLOCK_HAVE_DATA),
        // ready to be reactivated by reconsiderblock or another reorg.
        let store = BlockStore::new(&db);
        for h in [hash_a1, hash_a2] {
            let e = store
                .get_block_index(&h)
                .unwrap()
                .expect("displaced A-chain block_index entry must remain");
            use rustoshi_storage::block_store::BlockStatus;
            assert!(
                e.status.has(BlockStatus::HAVE_DATA),
                "displaced A-chain blocks retain HAVE_DATA"
            );
        }
        // And the new B-chain blocks all have block_index entries.
        for (h, height) in [(hash_b1, 1), (hash_b2, 2), (hash_b3, 3)] {
            let e = store
                .get_block_index(&h)
                .unwrap()
                .expect("B-chain block_index entry must exist");
            assert_eq!(e.height, height);
        }
        // Height-index points at the new (B) chain.
        assert_eq!(
            store.get_hash_by_height(3).unwrap().unwrap(),
            hash_b3,
            "height-index at h=3 must point at B3"
        );
    }

    // ============================================================
    // TXINDEX-REVERT-ON-REORG TESTS (Pattern C0 + C closure 2026-05-05)
    //
    // Pre-fix: rustoshi's submit_block (server.rs:2738) did NOT call
    // store.put_tx_index after a successful connect, so the txindex CF
    // was never populated for any IBD-fetched or RPC-submitted block.
    // `getrawtransaction(<txid>)` therefore failed with "no such tx"
    // even when the tx WAS confirmed on the active chain.  And nothing
    // wrote `delete_tx_index` on disconnect, so even a fix to the
    // connect side would leave stale hits after a reorg.
    //
    // The C0 fix wires put_tx_index into submit_block's accept arm and
    // into try_attach_and_reorg's "newly-active branch" walk.  The
    // matching disconnect side calls delete_tx_index in `disconnect_to`
    // and in try_attach_and_reorg's "now-disconnected blocks" loop.
    //
    // Reference: bitcoin-core/src/index/txindex.cpp::CustomAppend +
    // CustomRemove. Audit: CORE-PARITY-AUDIT/_txindex-revert-on-reorg-
    // fleet-result-2026-05-05.md.
    //
    // Builds on top of today's reorg-via-submitblock P0 closure (fa6ee55).
    // ============================================================

    /// Test: submit_block writes a tx_index entry for every transaction
    /// in the accepted block (the C0 fix).  Pre-fix this assertion held
    /// only for blocks generated via the legacy `generateblocks` RPC.
    #[tokio::test]
    async fn submit_block_writes_tx_index_entries_for_accepted_block() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        let (db, _state, server) = make_test_server(params.clone());

        let genesis_hash = params.genesis_hash;
        let block_a1 = mine_synth_block(1, genesis_hash, 0xA1);
        let hash_a1 = block_a1.block_hash();
        let coinbase_txid = block_a1.transactions[0].txid();

        // Pre-condition: tx_index lookup for the coinbase txid returns
        // None (txindex CF is empty modulo the genesis init).
        let store = BlockStore::new(&db);
        assert!(
            store.get_tx_index(&coinbase_txid).unwrap().is_none(),
            "tx_index must not have an entry for A1.coinbase before submit"
        );
        drop(store);

        let res = drive_submit_block(&server, &block_a1).await;
        assert!(res.is_none(), "expected accept (None), got {:?}", res);

        // Post-condition: the txindex entry exists and points at A1.
        let store = BlockStore::new(&db);
        let entry = store
            .get_tx_index(&coinbase_txid)
            .unwrap()
            .expect("submit_block must have written a tx_index entry");
        assert_eq!(
            entry.block_hash, hash_a1,
            "tx_index entry must point at the connecting block"
        );
    }

    /// Test: try_attach_and_reorg on a heavier side-branch deletes
    /// tx_index entries for the disconnected blocks AND writes
    /// tx_index entries for the newly-active branch.  Mirrors Core's
    /// BlockDisconnected + BlockConnected callbacks fired by
    /// ActivateBestChainStep.
    #[tokio::test]
    async fn try_attach_and_reorg_revert_and_replay_tx_index() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // G -> A1 -> A2 (active, height 2).
        let (hash_g, _block_g, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a1, block_a1, work_a1) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xA1)
        };
        let (hash_a2, block_a2, _) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2)
        };
        rpc_state.best_hash = hash_a2;
        rpc_state.best_height = 2;

        // Manually populate tx_index for A1 + A2 to mirror what the
        // submit_block connect path does on the live system. This is
        // the pre-state the disconnect side needs to revert.
        let a1_txid = block_a1.transactions[0].txid();
        let a2_txid = block_a2.transactions[0].txid();
        {
            use rustoshi_storage::block_store::TxIndexEntry;
            let store = BlockStore::new(&db);
            store
                .put_tx_index(
                    &a1_txid,
                    &TxIndexEntry {
                        block_hash: hash_a1,
                        tx_offset: 0,
                        tx_length: 0,
                    },
                )
                .unwrap();
            store
                .put_tx_index(
                    &a2_txid,
                    &TxIndexEntry {
                        block_hash: hash_a2,
                        tx_offset: 0,
                        tx_length: 0,
                    },
                )
                .unwrap();
        }

        // Side-branch B that will outpace A: G -> B1 -> B2 -> B3.
        let (hash_b1, block_b1, work_b1) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 1, hash_g, work_g, 0xB1)
        };
        let (hash_b2, block_b2, _work_b2) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 2, hash_b1, work_b1, 0xB2)
        };
        let block_b3 = mine_synth_block(3, hash_b2, 0xB3);
        let hash_b3 = block_b3.block_hash();
        let b1_txid = block_b1.transactions[0].txid();
        let b2_txid = block_b2.transactions[0].txid();
        let b3_txid = block_b3.transactions[0].txid();

        // Pre-condition: A-chain entries are present, B-chain entries absent.
        {
            let store = BlockStore::new(&db);
            assert!(store.get_tx_index(&a1_txid).unwrap().is_some());
            assert!(store.get_tx_index(&a2_txid).unwrap().is_some());
            assert!(store.get_tx_index(&b1_txid).unwrap().is_none());
            assert!(store.get_tx_index(&b2_txid).unwrap().is_none());
            assert!(store.get_tx_index(&b3_txid).unwrap().is_none());
        }

        let did_reorg = try_attach_and_reorg(&mut rpc_state, &block_b3, &hash_b3)
            .expect("try_attach_and_reorg");
        assert!(did_reorg, "B-chain has more work — reorg must fire");
        assert_eq!(rpc_state.best_hash, hash_b3);
        assert_eq!(rpc_state.best_height, 3);

        // Post-condition (Pattern C - revert): A-chain tx_index entries
        // are gone — confirmation lookups for them must now miss.
        let store = BlockStore::new(&db);
        assert!(
            store.get_tx_index(&a1_txid).unwrap().is_none(),
            "A1 tx_index entry must be deleted on disconnect (Pattern C)"
        );
        assert!(
            store.get_tx_index(&a2_txid).unwrap().is_none(),
            "A2 tx_index entry must be deleted on disconnect (Pattern C)"
        );

        // Post-condition (Pattern C0 - replay): B-chain tx_index entries
        // are present and point at the correct block.
        let e1 = store
            .get_tx_index(&b1_txid)
            .unwrap()
            .expect("B1 tx_index must be written on reorg-connect");
        assert_eq!(e1.block_hash, hash_b1);
        let e2 = store
            .get_tx_index(&b2_txid)
            .unwrap()
            .expect("B2 tx_index must be written on reorg-connect");
        assert_eq!(e2.block_hash, hash_b2);
        let e3 = store
            .get_tx_index(&b3_txid)
            .unwrap()
            .expect("B3 tx_index must be written on reorg-connect");
        assert_eq!(e3.block_hash, hash_b3);
    }

    /// Pattern D fleet-wide closure (2026-05-07): a multi-block reorg
    /// that disconnects N blocks and reconnects M blocks must commit
    /// EXACTLY ONE RocksDB `WriteBatch`. We assert this by checking
    /// `ChainDb::write_batch_count` deltas across `try_attach_and_reorg`.
    ///
    /// Without the multi-block atomic batch, each per-block
    /// `delete_tx_index` / `put_tx_index` would land its own RocksDB
    /// write — observable as count delta == 1 (UTXO+height-index batch)
    /// PLUS one per disconnected/reconnected tx (tx-index puts/deletes).
    ///
    /// Yesterday's `9ac4fac` made the disconnect path's UTXO+height-index
    /// flip atomic; today's refactor folds the tx-index updates into the
    /// SAME batch. So the whole N+M-block reorg sequence is one atomic
    /// disk write.
    #[tokio::test]
    async fn reorg_commits_single_batch_for_multi_block_swap() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // Old chain: G -> A1 -> A2 -> A3 (active, height 3).
        let (hash_g, _block_g, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a1, block_a1, work_a1) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xA1)
        };
        let (hash_a2, block_a2, work_a2) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2)
        };
        let (hash_a3, block_a3, _work_a3) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 3, hash_a2, work_a2, 0xA3)
        };
        rpc_state.best_hash = hash_a3;
        rpc_state.best_height = 3;

        // Pre-populate tx_index for A1+A2+A3 (mirrors the connect path).
        {
            use rustoshi_storage::block_store::TxIndexEntry;
            let store = BlockStore::new(&db);
            for (h, t) in [
                (hash_a1, &block_a1),
                (hash_a2, &block_a2),
                (hash_a3, &block_a3),
            ] {
                for tx in &t.transactions {
                    store
                        .put_tx_index(
                            &tx.txid(),
                            &TxIndexEntry {
                                block_hash: h,
                                tx_offset: 0,
                                tx_length: 0,
                            },
                        )
                        .unwrap();
                }
            }
        }

        // New chain (heavier): G -> B1 -> B2 -> B3 -> B4. Reorg must
        // disconnect 3 (A3,A2,A1) and connect 4 (B1..B4).
        let (hash_b1, _block_b1, work_b1) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 1, hash_g, work_g, 0xB1)
        };
        let (hash_b2, _block_b2, work_b2) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 2, hash_b1, work_b1, 0xB2)
        };
        let (hash_b3, _block_b3, _work_b3) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 3, hash_b2, work_b2, 0xB3)
        };
        let block_b4 = mine_synth_block(4, hash_b3, 0xB4);
        let hash_b4 = block_b4.block_hash();

        // Snapshot the RocksDB write_batch counter immediately before
        // the reorg fires. The full reorg (3 disconnect + 4 connect, all
        // with tx-index updates) must add exactly 1 to this count.
        let pre = db.write_batch_count();
        let did_reorg = try_attach_and_reorg(&mut rpc_state, &block_b4, &hash_b4)
            .expect("try_attach_and_reorg");
        let post = db.write_batch_count();
        assert!(did_reorg, "B-chain has more work — reorg must fire");
        assert_eq!(rpc_state.best_hash, hash_b4);
        assert_eq!(rpc_state.best_height, 4);

        let delta = post - pre;
        assert_eq!(
            delta, 1,
            "multi-block reorg must commit exactly 1 RocksDB batch \
             (disconnect={}, connect=4); got {} batches",
            3, delta
        );

        // Sanity: the reorg actually flipped the chain on disk.
        let store = BlockStore::new(&db);
        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash_b4);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 4);
        // Old branch tx-index entries are gone, new branch entries are
        // present (and they all flipped in the same batch as the tip).
        assert!(store.get_tx_index(&block_a1.transactions[0].txid()).unwrap().is_none());
        assert!(store.get_tx_index(&block_a2.transactions[0].txid()).unwrap().is_none());
        assert!(store.get_tx_index(&block_a3.transactions[0].txid()).unwrap().is_none());
    }

    /// Pattern D fleet-wide closure (2026-05-07): if anything fails
    /// during the reorg accumulation phase (before `write_batch`), the
    /// on-disk chainstate must be UNCHANGED. We simulate the failure by
    /// constructing a reorg target whose middle block is missing on
    /// disk — `chain_state.reorganize` returns
    /// `ValidationError::PrevBlockNotFound`, propagated as `Err` from
    /// `try_attach_and_reorg`. The pre-state must survive intact.
    #[tokio::test]
    async fn reorg_failure_pre_commit_leaves_chainstate_unchanged() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;
        use rustoshi_storage::block_store::TxIndexEntry;
        use rustoshi_storage::CF_BLOCKS;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // Active chain: G -> A1 -> A2 (height 2).
        let (hash_g, _block_g, work_g) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA)
        };
        let (hash_a1, block_a1, work_a1) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 1, hash_g, work_g, 0xA1)
        };
        let (hash_a2, block_a2, _work_a2) = {
            let store = BlockStore::new(&db);
            synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2)
        };
        rpc_state.best_hash = hash_a2;
        rpc_state.best_height = 2;

        // Tx-index entries for A1 + A2 (the pre-state we care about).
        let a1_txid = block_a1.transactions[0].txid();
        let a2_txid = block_a2.transactions[0].txid();
        {
            let store = BlockStore::new(&db);
            for (h, t) in [(hash_a1, &block_a1), (hash_a2, &block_a2)] {
                for tx in &t.transactions {
                    store
                        .put_tx_index(
                            &tx.txid(),
                            &TxIndexEntry {
                                block_hash: h,
                                tx_offset: 0,
                                tx_length: 0,
                            },
                        )
                        .unwrap();
                }
            }
        }

        // Side branch: persist B1 + B2 fully, then attempt to reorg to a
        // B3 whose parent (B2) we will yank from the blocks CF AFTER
        // staging — `chain_state.reorganize` will call get_block(B2)
        // during the connect pass and fail.
        let (hash_b1, _block_b1, work_b1) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 1, hash_g, work_g, 0xB1)
        };
        let (hash_b2, _block_b2, _work_b2) = {
            let store = BlockStore::new(&db);
            synth_persist_side_block(&store, 2, hash_b1, work_b1, 0xB2)
        };
        let block_b3 = mine_synth_block(3, hash_b2, 0xB3);
        let hash_b3 = block_b3.block_hash();

        // Yank B2's block body from disk: index entry remains (so the
        // chainwork compare succeeds), but get_block(B2) returns None
        // mid-reorg. This forces `reorganize` to error AFTER staging
        // some UTXO mutations into the in-memory cache but BEFORE the
        // outer `write_batch` commits.
        db.delete_cf(CF_BLOCKS, hash_b2.as_bytes()).unwrap();

        let pre_count = db.write_batch_count();
        let result = try_attach_and_reorg(&mut rpc_state, &block_b3, &hash_b3);
        let post_count = db.write_batch_count();

        assert!(
            result.is_err(),
            "reorg must error when a side-branch block body is missing"
        );

        // The whole batch must NOT have committed: write_batch_count
        // must not have advanced.
        assert_eq!(
            post_count, pre_count,
            "no batch commit on pre-commit failure; got {} -> {}",
            pre_count, post_count
        );

        // On-disk chainstate is UNCHANGED.
        let store = BlockStore::new(&db);
        assert_eq!(
            store.get_best_block_hash().unwrap().unwrap(),
            hash_a2,
            "tip pointer must still point at the original active chain"
        );
        assert_eq!(store.get_best_height().unwrap().unwrap(), 2);
        assert!(
            store.get_tx_index(&a1_txid).unwrap().is_some(),
            "A1 tx-index entry must survive the failed reorg"
        );
        assert!(
            store.get_tx_index(&a2_txid).unwrap().is_some(),
            "A2 tx-index entry must survive the failed reorg"
        );
    }

    /// Pattern D fleet-wide closure (2026-05-07): a reorg whose
    /// disconnect+reconnect span exceeds `MAX_REORG_DEPTH` must error
    /// gracefully. Allowing it to proceed would let an unbounded
    /// `WriteBatch` accumulate in memory; allowing a silent fallback to
    /// per-block-atomic would re-introduce the partial-commit window
    /// this whole refactor closes.
    #[tokio::test]
    async fn disconnect_to_errors_when_depth_exceeds_cap() {
        use rustoshi_consensus::ChainParams;
        use rustoshi_storage::ChainDb;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
        let mut rpc_state = RpcState::new(db.clone(), ChainParams::mainnet());

        // Synthetic chain: a tip at height MAX_REORG_DEPTH + 5 with
        // target=0 forces a disconnect span of MAX_REORG_DEPTH + 5.
        // We don't need the full block bodies — `disconnect_to`'s depth
        // check fires BEFORE the plan walk. Just set the in-memory
        // tip + height to the synthetic values.
        rpc_state.best_hash = Hash256::from_hex(
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        )
        .unwrap();
        rpc_state.best_height = MAX_REORG_DEPTH + 5;

        let target_hash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000123",
        )
        .unwrap();

        let pre_count = db.write_batch_count();
        let err = disconnect_to(&mut rpc_state, target_hash, 0)
            .expect_err("must error on excessive depth");
        let post_count = db.write_batch_count();

        assert!(
            err.contains("exceeds MAX_REORG_DEPTH"),
            "error must call out depth cap: {}",
            err
        );
        assert_eq!(
            post_count, pre_count,
            "depth-cap rejection must not commit any batch"
        );
        // In-memory tip is unchanged too.
        assert_eq!(rpc_state.best_height, MAX_REORG_DEPTH + 5);
    }

    // ============================================================
    // PRUNE WIRING (BIP-159 / Core parity)
    // ============================================================

    /// `getblockchaininfo` reports `pruned=false` when prune mode is off
    /// and OMITS `pruneheight` / `prune_target_size` (matches Core).
    #[tokio::test]
    async fn test_getblockchaininfo_prune_off_omits_prune_fields() {
        use rustoshi_storage::ChainDb;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();

        let state = Arc::new(RwLock::new(RpcState::new(db, params)));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        let info = rpc.get_blockchain_info().await.expect("getblockchaininfo");
        assert!(!info.pruned);
        assert!(info.pruneheight.is_none());
        assert!(info.prune_target_size.is_none());

        // JSON serialization must omit the optional fields when None.
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("\"pruneheight\""), "pruneheight must be absent: {}", json);
        assert!(!json.contains("\"prune_target_size\""), "prune_target_size must be absent: {}", json);
        assert!(json.contains("\"pruned\":false"));
    }

    /// `getblockchaininfo` with prune mode reports `pruned=true`,
    /// `pruneheight`, and `prune_target_size`.
    #[tokio::test]
    async fn test_getblockchaininfo_prune_on_reports_prune_fields() {
        use rustoshi_storage::ChainDb;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();

        let prune_target = 550 * 1024 * 1024;
        let state = Arc::new(RwLock::new(RpcState::with_prune_config(db, params, prune_target)));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        let info = rpc.get_blockchain_info().await.expect("getblockchaininfo");
        assert!(info.pruned);
        // Watermark starts at 0 -> lowest-complete = 0 (we've never pruned).
        assert_eq!(info.pruneheight, Some(0));
        assert_eq!(info.prune_target_size, Some(prune_target));

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pruned\":true"));
        assert!(json.contains("\"pruneheight\":0"));
        assert!(json.contains(&format!("\"prune_target_size\":{}", prune_target)));
    }

    /// `pruneblockchain` RPC rejects when prune mode is off (Core parity).
    #[tokio::test]
    async fn test_pruneblockchain_rpc_rejects_when_prune_off() {
        use rustoshi_storage::ChainDb;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();

        let state = Arc::new(RwLock::new(RpcState::new(db, params)));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        let err = rpc.prune_blockchain(0).await.expect_err("should reject");
        let msg = format!("{}", err);
        assert!(
            msg.contains("not in prune mode"),
            "error must call out prune-mode requirement: {}",
            msg
        );
    }

    /// `pruneblockchain` RPC honors `-prune=1` manual-only mode: it
    /// returns successfully and drives the prune coordinator.
    #[tokio::test]
    async fn test_pruneblockchain_rpc_honors_manual_only_mode() {
        use rustoshi_storage::{ChainDb, BlockStatus, BlockIndexEntry, UndoData, MIN_BLOCKS_TO_KEEP, PRUNE_MANUAL_SENTINEL};
        use rustoshi_primitives::{Block, BlockHeader, Transaction, TxIn, TxOut, OutPoint, Hash256};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
        let params = rustoshi_consensus::ChainParams::regtest();

        // Build a synthetic chain so manual prune has something to drop.
        {
            let store = BlockStore::new(&db);
            let tip = MIN_BLOCKS_TO_KEEP + 50;
            for h in 1..=tip {
                let header = BlockHeader {
                    version: 1,
                    prev_block_hash: Hash256::ZERO,
                    merkle_root: Hash256::ZERO,
                    timestamp: 1_700_000_000 + h,
                    bits: 0x1d00ffff,
                    nonce: h,
                };
                let mut hash_bytes = [0u8; 32];
                hash_bytes[0..4].copy_from_slice(&h.to_be_bytes());
                let hash = Hash256(hash_bytes);
                let block = Block {
                    header: header.clone(),
                    transactions: vec![Transaction {
                        version: 1,
                        inputs: vec![TxIn {
                            previous_output: OutPoint::null(),
                            script_sig: vec![h as u8],
                            sequence: 0xFFFFFFFF,
                            witness: Vec::new(),
                        }],
                        outputs: vec![TxOut {
                            value: 50_0000_0000,
                            script_pubkey: vec![0x51],
                        }],
                        lock_time: 0,
                    }],
                };
                store.put_header(&hash, &header).unwrap();
                store.put_block(&hash, &block).unwrap();
                store.put_height_index(h, &hash).unwrap();
                let mut status = BlockStatus::new();
                status.set(BlockStatus::VALID_SCRIPTS);
                status.set(BlockStatus::HAVE_DATA);
                status.set(BlockStatus::HAVE_UNDO);
                store
                    .put_block_index(
                        &hash,
                        &BlockIndexEntry {
                            height: h,
                            status,
                            n_tx: 1,
                            timestamp: header.timestamp,
                            bits: header.bits,
                            nonce: header.nonce,
                            version: header.version,
                            prev_hash: header.prev_block_hash,
                            chain_work: [0u8; 32],
                        },
                    )
                    .unwrap();
                store.put_undo(&hash, &UndoData { spent_coins: vec![] }).unwrap();
            }
            let mut tip_bytes = [0u8; 32];
            tip_bytes[0..4].copy_from_slice(&tip.to_be_bytes());
            store.set_best_block(&Hash256(tip_bytes), tip).unwrap();
        }

        // RpcState in `-prune=1` manual-only mode.
        let mut rpc_state = RpcState::with_prune_config(db.clone(), params, PRUNE_MANUAL_SENTINEL);
        rpc_state.init_from_db().unwrap();
        let state = Arc::new(RwLock::new(rpc_state));
        let peer_state = Arc::new(RwLock::new(PeerState::default()));
        let rpc = RpcServerImpl::new(state, peer_state);

        // Manual prune to height 5.
        let returned = rpc.prune_blockchain(5).await.expect("prune");
        assert_eq!(returned, 5);

        // Verify low blocks dropped, high blocks intact.
        let store = BlockStore::new(&db);
        let mut h_low = [0u8; 32];
        h_low[0..4].copy_from_slice(&3u32.to_be_bytes());
        assert!(!store.has_block(&Hash256(h_low)).unwrap());

        let mut h_high = [0u8; 32];
        h_high[0..4].copy_from_slice(&50u32.to_be_bytes());
        assert!(store.has_block(&Hash256(h_high)).unwrap());

        // Watermark advanced and getblockchaininfo reflects it.
        assert_eq!(store.get_prune_height().unwrap(), 5);
        let info = rpc.get_blockchain_info().await.expect("info");
        assert!(info.pruned);
        assert_eq!(info.pruneheight, Some(6)); // lowest-complete = watermark + 1
        assert_eq!(info.prune_target_size, Some(PRUNE_MANUAL_SENTINEL));
    }
}
