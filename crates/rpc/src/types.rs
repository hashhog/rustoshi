//! RPC response types and configuration.
//!
//! This module defines all the types used in JSON-RPC responses, matching
//! the Bitcoin Core RPC format for compatibility with existing tooling.

use serde::{Deserialize, Serialize};

// ============================================================
// RPC CONFIGURATION
// ============================================================

/// RPC server configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Address to bind to (e.g., "127.0.0.1:8332").
    pub bind_address: String,
    /// Optional HTTP Basic Auth username.
    pub auth_user: Option<String>,
    /// Optional HTTP Basic Auth password.
    pub auth_password: Option<String>,
    /// Cookie secret generated at startup for cookie-based auth.
    /// This is the raw hex string that was written to the .cookie file
    /// (i.e. the password half of `__cookie__:<secret>`).
    pub cookie_secret: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8332".to_string(),
            auth_user: None,
            auth_password: None,
            cookie_secret: None,
        }
    }
}

impl RpcConfig {
    /// Create configuration for testnet4.
    pub fn testnet4() -> Self {
        Self {
            bind_address: "127.0.0.1:48332".to_string(),
            auth_user: None,
            auth_password: None,
            cookie_secret: None,
        }
    }

    /// Create configuration for mainnet.
    pub fn mainnet() -> Self {
        Self {
            bind_address: "127.0.0.1:8332".to_string(),
            auth_user: None,
            auth_password: None,
            cookie_secret: None,
        }
    }
}

// ============================================================
// BLOCKCHAIN INFO
// ============================================================

/// Response for `getblockchaininfo` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockchainInfo {
    /// The current network (main, test, regtest).
    pub chain: String,
    /// Current number of validated blocks.
    pub blocks: u32,
    /// Current number of validated headers.
    pub headers: u32,
    /// Hash of the current best block.
    pub bestblockhash: String,
    /// Current difficulty.
    pub difficulty: f64,
    /// Median time of the last 11 blocks.
    pub mediantime: u64,
    /// Estimate of verification progress (0.0 to 1.0).
    pub verificationprogress: f64,
    /// Whether we are in initial block download mode.
    pub initialblockdownload: bool,
    /// Total accumulated chain work (hex string).
    pub chainwork: String,
    /// Estimated size of the block and undo files on disk.
    pub size_on_disk: u64,
    /// Whether the blockchain is pruned.
    pub pruned: bool,
    /// Soft fork deployment state, keyed by deployment name.
    /// Populated from the same canonical source as `getdeploymentinfo`.
    #[serde(default)]
    pub softforks: serde_json::Value,
    /// Any network and blockchain warnings.
    pub warnings: String,
}

// ============================================================
// BLOCK INFO
// ============================================================

/// Response for `getblock` RPC (verbose mode).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockInfo {
    /// Block hash.
    pub hash: String,
    /// Number of confirmations.
    pub confirmations: i32,
    /// Block size in bytes.
    pub size: u32,
    /// Block size in bytes (excluding witness data).
    pub strippedsize: u32,
    /// Block weight.
    pub weight: u32,
    /// Block height.
    pub height: u32,
    /// Block version.
    pub version: i32,
    /// Block version in hex.
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    /// Merkle root of the transactions.
    pub merkleroot: String,
    /// Transaction IDs in the block.
    pub tx: Vec<String>,
    /// Block timestamp.
    pub time: u32,
    /// Median time of the past 11 blocks.
    pub mediantime: u64,
    /// PoW nonce.
    pub nonce: u32,
    /// Compact difficulty target (bits).
    pub bits: String,
    /// Current difficulty.
    pub difficulty: f64,
    /// Total chain work up to this block (hex).
    pub chainwork: String,
    /// Number of transactions in the block.
    #[serde(rename = "nTx")]
    pub n_tx: u32,
    /// Hash of the previous block.
    pub previousblockhash: Option<String>,
    /// Hash of the next block (if available).
    pub nextblockhash: Option<String>,
}

/// Response for `getblockheader` RPC (verbose mode).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeaderInfo {
    /// Block hash.
    pub hash: String,
    /// Number of confirmations.
    pub confirmations: i32,
    /// Block height.
    pub height: u32,
    /// Block version.
    pub version: i32,
    /// Block version in hex.
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    /// Merkle root.
    pub merkleroot: String,
    /// Block timestamp.
    pub time: u32,
    /// Median time of past 11 blocks.
    pub mediantime: u64,
    /// PoW nonce.
    pub nonce: u32,
    /// Compact difficulty target.
    pub bits: String,
    /// Current difficulty.
    pub difficulty: f64,
    /// Total chain work (hex).
    pub chainwork: String,
    /// Number of transactions.
    #[serde(rename = "nTx")]
    pub n_tx: u32,
    /// Previous block hash.
    pub previousblockhash: Option<String>,
    /// Next block hash (if available).
    pub nextblockhash: Option<String>,
}

// ============================================================
// TRANSACTION INFO
// ============================================================

/// Response for `getrawtransaction` RPC (verbose mode).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionInfo {
    /// Transaction ID.
    pub txid: String,
    /// Witness transaction ID.
    pub wtxid: String,
    /// Transaction hash (same as txid for non-witness).
    pub hash: String,
    /// Transaction size in bytes.
    pub size: u32,
    /// Transaction size without witness (virtual size base).
    pub vsize: u32,
    /// Transaction weight.
    pub weight: u32,
    /// Transaction version.
    pub version: i32,
    /// Transaction locktime.
    pub locktime: u32,
    /// Transaction inputs.
    pub vin: Vec<TxInputInfo>,
    /// Transaction outputs.
    pub vout: Vec<TxOutputInfo>,
    /// Raw hex of the transaction.
    pub hex: String,
    /// Block hash containing this transaction.
    pub blockhash: Option<String>,
    /// Number of confirmations.
    pub confirmations: Option<u32>,
    /// Block time.
    pub blocktime: Option<u32>,
    /// Time transaction was received.
    pub time: Option<u32>,
}

/// Transaction input information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxInputInfo {
    /// Previous transaction ID (null for coinbase).
    pub txid: Option<String>,
    /// Previous output index (null for coinbase).
    pub vout: Option<u32>,
    /// Script signature info.
    #[serde(rename = "scriptSig")]
    pub script_sig: Option<ScriptSigInfo>,
    /// Coinbase data (for coinbase transactions).
    pub coinbase: Option<String>,
    /// Witness data.
    pub txinwitness: Option<Vec<String>>,
    /// Sequence number.
    pub sequence: u32,
}

/// ScriptSig information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScriptSigInfo {
    /// Disassembled script.
    pub asm: String,
    /// Raw hex.
    pub hex: String,
}

/// Transaction output information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxOutputInfo {
    /// Value in BTC.
    pub value: f64,
    /// Output index.
    pub n: u32,
    /// ScriptPubKey information.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: ScriptPubKeyInfo,
}

/// ScriptPubKey information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScriptPubKeyInfo {
    /// Disassembled script.
    pub asm: String,
    /// Raw hex.
    pub hex: String,
    /// Script type (pubkeyhash, scripthash, witness_v0_keyhash, etc.).
    #[serde(rename = "type")]
    pub script_type: String,
    /// Address (if applicable).
    pub address: Option<String>,
}

// ============================================================
// MEMPOOL INFO
// ============================================================

/// Response for `getmempoolinfo` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolInfo {
    /// Whether the mempool is loaded.
    pub loaded: bool,
    /// Number of transactions in mempool.
    pub size: usize,
    /// Total size of all transactions in bytes.
    pub bytes: usize,
    /// Total memory usage in bytes.
    pub usage: usize,
    /// Total fees in BTC.
    pub total_fee: f64,
    /// Maximum mempool size in bytes.
    pub maxmempool: usize,
    /// Minimum fee rate to enter mempool (BTC/kvB).
    pub mempoolminfee: f64,
    /// Minimum relay fee rate (BTC/kvB).
    pub minrelaytxfee: f64,
    /// Minimum fee rate increment for mempool limiting or replacement (BTC/kvB).
    pub incrementalrelayfee: f64,
    /// Number of transactions not depending on others.
    pub unbroadcastcount: usize,
    /// Whether the mempool accepts RBF without signaling.
    pub fullrbf: bool,
}

/// Entry in mempool for `getrawmempool` verbose mode.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolEntry {
    /// Virtual size of transaction.
    pub vsize: u32,
    /// Transaction weight.
    pub weight: u32,
    /// Transaction fee in BTC.
    pub fee: f64,
    /// Modified fee for mining prioritization.
    pub modifiedfee: f64,
    /// Time transaction entered mempool.
    pub time: u64,
    /// Block height when entered mempool.
    pub height: u32,
    /// Number of descendant transactions.
    pub descendantcount: u32,
    /// Total size of descendants.
    pub descendantsize: u32,
    /// Total fees of descendants.
    pub descendantfees: u64,
    /// Number of ancestor transactions.
    pub ancestorcount: u32,
    /// Total size of ancestors.
    pub ancestorsize: u32,
    /// Total fees of ancestors.
    pub ancestorfees: u64,
    /// Witness transaction ID.
    pub wtxid: String,
    /// Transaction IDs this depends on.
    pub depends: Vec<String>,
    /// Transaction IDs that depend on this.
    pub spentby: Vec<String>,
    /// Whether transaction is BIP125-replaceable.
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bool,
    /// Whether this transaction has been broadcast.
    pub unbroadcast: bool,
}

// ============================================================
// FEE ESTIMATION
// ============================================================

/// Response for `estimatesmartfee` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FeeEstimateResult {
    /// Estimated fee rate in BTC/kvB.
    pub feerate: Option<f64>,
    /// Errors during estimation.
    pub errors: Option<Vec<String>>,
    /// Target number of blocks for confirmation.
    pub blocks: u32,
}

// ============================================================
// MINING INFO
// ============================================================

/// Response for `getmininginfo` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiningInfo {
    /// Current block height.
    pub blocks: u32,
    /// Current difficulty.
    pub difficulty: f64,
    /// Estimated network hash rate.
    pub networkhashps: f64,
    /// Number of transactions in mempool.
    pub pooledtx: usize,
    /// Current network.
    pub chain: String,
    /// Any warnings.
    pub warnings: String,
}

/// Response for `getblocktemplate` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockTemplateResult {
    /// Block version.
    pub version: i32,
    /// Supported version bits rules.
    pub rules: Vec<String>,
    /// Version bits available for voting.
    pub vbavailable: serde_json::Value,
    /// Version bits required to be set.
    pub vbrequired: u32,
    /// Previous block hash.
    pub previousblockhash: String,
    /// Transactions to include.
    pub transactions: Vec<BlockTemplateTransaction>,
    /// Coinbase auxiliary data.
    pub coinbaseaux: serde_json::Value,
    /// Maximum block value for coinbase.
    pub coinbasevalue: u64,
    /// Long poll ID for monitoring new templates.
    pub longpollid: String,
    /// Compact target (bits).
    pub target: String,
    /// Minimum valid timestamp.
    pub mintime: u32,
    /// Mutable fields.
    pub mutable: Vec<String>,
    /// Suggested nonce range.
    pub noncerange: String,
    /// Block sigops limit.
    pub sigoplimit: u32,
    /// Block size limit.
    pub sizelimit: u32,
    /// Block weight limit.
    pub weightlimit: u32,
    /// Current time.
    pub curtime: u32,
    /// Compact target bits.
    pub bits: String,
    /// Block height.
    pub height: u32,
    /// Default witness commitment.
    pub default_witness_commitment: Option<String>,
}

/// Transaction in a block template.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockTemplateTransaction {
    /// Transaction data in hex.
    pub data: String,
    /// Transaction ID.
    pub txid: String,
    /// Witness transaction ID.
    pub hash: String,
    /// Indices of dependent transactions.
    pub depends: Vec<u32>,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Sigops count.
    pub sigops: u32,
    /// Transaction weight.
    pub weight: u32,
}

// ============================================================
// PEER INFO
// ============================================================

/// Response for `getpeerinfo` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfoRpc {
    /// Peer index.
    pub id: u64,
    /// Peer address.
    pub addr: String,
    /// Bound local address.
    pub addrbind: Option<String>,
    /// Local address as seen by peer.
    pub addrlocal: Option<String>,
    /// Network type (ipv4, ipv6, onion).
    pub network: String,
    /// Services offered.
    pub services: String,
    /// Services offered (hex).
    pub servicesnames: Vec<String>,
    /// Whether peer relays transactions.
    pub relaytxes: bool,
    /// Time of last send.
    pub lastsend: u64,
    /// Time of last receive.
    pub lastrecv: u64,
    /// Total bytes sent.
    pub bytessent: u64,
    /// Total bytes received.
    pub bytesrecv: u64,
    /// Connection time.
    pub conntime: u64,
    /// Time offset in seconds.
    pub timeoffset: i64,
    /// Ping time in seconds.
    pub pingtime: Option<f64>,
    /// Minimum observed ping time.
    pub minping: Option<f64>,
    /// Ping wait time.
    pub pingwait: Option<f64>,
    /// Protocol version.
    pub version: i32,
    /// User agent string.
    pub subver: String,
    /// Whether this is an inbound connection.
    pub inbound: bool,
    /// Whether using BIP152 high bandwidth mode (sending).
    pub bip152_hb_to: bool,
    /// Whether using BIP152 high bandwidth mode (receiving).
    pub bip152_hb_from: bool,
    /// Starting height when connected.
    pub startingheight: i32,
    /// Current synced headers.
    pub synced_headers: i32,
    /// Current synced blocks.
    pub synced_blocks: i32,
    /// Connection type.
    pub connection_type: String,
}

/// Response for `getnetworkinfo` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInfo {
    /// Node version number.
    pub version: u32,
    /// Node subversion string.
    pub subversion: String,
    /// Protocol version.
    pub protocolversion: i32,
    /// Local services.
    pub localservices: String,
    /// Local services names.
    pub localservicesnames: Vec<String>,
    /// Whether relay is enabled.
    pub localrelay: bool,
    /// Time offset in seconds.
    pub timeoffset: i64,
    /// Total number of connections.
    pub connections: u32,
    /// Number of inbound connections.
    pub connections_in: u32,
    /// Number of outbound connections.
    pub connections_out: u32,
    /// Whether network is active.
    pub networkactive: bool,
    /// List of network interfaces.
    pub networks: Vec<NetworkInterface>,
    /// Minimum relay fee.
    pub relayfee: f64,
    /// Incremental relay fee.
    pub incrementalfee: f64,
    /// Local addresses.
    pub localaddresses: Vec<LocalAddress>,
    /// Any warnings.
    pub warnings: String,
}

/// Network interface information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    /// Network name (ipv4, ipv6, onion).
    pub name: String,
    /// Whether limited.
    pub limited: bool,
    /// Whether reachable.
    pub reachable: bool,
    /// Network proxy.
    pub proxy: String,
    /// Whether randomized credentials per proxy.
    pub proxy_randomize_credentials: bool,
}

/// Local address information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalAddress {
    /// Local address.
    pub address: String,
    /// Port.
    pub port: u16,
    /// Score.
    pub score: i32,
}

// ============================================================
// VALIDATION
// ============================================================

/// Response for `validateaddress` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidateAddressResult {
    /// Whether the address is valid.
    pub isvalid: bool,
    /// The address (if valid).
    pub address: Option<String>,
    /// The scriptPubKey (hex).
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: Option<String>,
    /// Whether it's a script address.
    pub isscript: Option<bool>,
    /// Whether it's a witness address.
    pub iswitness: Option<bool>,
    /// Witness version (0-16).
    pub witness_version: Option<u8>,
    /// Witness program (hex).
    pub witness_program: Option<String>,
}

// ============================================================
// UTXO INFO
// ============================================================

/// Response for `gettxout` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxOutResult {
    /// Best block hash when this was queried.
    pub bestblock: String,
    /// Number of confirmations.
    pub confirmations: u32,
    /// Value in BTC.
    pub value: f64,
    /// ScriptPubKey info.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: ScriptPubKeyInfo,
    /// Whether from a coinbase transaction.
    pub coinbase: bool,
}

// ============================================================
// RAW TRANSACTION
// ============================================================

/// Response for `decoderawtransaction` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodedRawTransaction {
    /// Transaction ID.
    pub txid: String,
    /// Witness transaction ID.
    pub hash: String,
    /// Transaction size.
    pub size: u32,
    /// Virtual size.
    pub vsize: u32,
    /// Weight.
    pub weight: u32,
    /// Version.
    pub version: i32,
    /// Locktime.
    pub locktime: u32,
    /// Inputs.
    pub vin: Vec<TxInputInfo>,
    /// Outputs.
    pub vout: Vec<TxOutputInfo>,
}

// ============================================================
// BAN INFO
// ============================================================

/// Entry in the banned list returned by `listbanned` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BannedInfo {
    /// The banned IP address.
    pub address: String,
    /// Unix timestamp when the ban was created.
    pub ban_created: u64,
    /// Unix timestamp when the ban expires.
    pub ban_until: u64,
    /// Reason for the ban.
    pub ban_reason: String,
}

// ============================================================
// PACKAGE RELAY
// ============================================================

/// Per-transaction result in a package submission.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageTxResultRpc {
    /// Transaction ID.
    pub txid: String,
    /// Witness transaction ID.
    pub wtxid: String,
    /// Virtual size in bytes.
    pub vsize: u64,
    /// Fee in BTC.
    pub fees: PackageFees,
    /// Whether this transaction was already in the mempool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    /// Error message if validation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

/// Fee information for a transaction in a package.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageFees {
    /// Base fee in BTC.
    pub base: f64,
    /// Effective fee rate in BTC/kvB.
    #[serde(rename = "effective-feerate")]
    pub effective_feerate: f64,
    /// List of transaction IDs this effective fee rate applies to.
    #[serde(rename = "effective-includes")]
    pub effective_includes: Vec<String>,
}

/// Response for `submitpackage` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubmitPackageResult {
    /// Aggregate package fee rate in BTC/kvB.
    pub package_feerate: Option<f64>,
    /// Message describing the result.
    pub package_msg: String,
    /// Per-transaction results, keyed by wtxid.
    #[serde(rename = "tx-results")]
    pub tx_results: std::collections::HashMap<String, PackageTxResultRpc>,
    /// List of txids that were replaced (RBF).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_transactions: Option<Vec<String>>,
}

// ============================================================
// PRUNING
// ============================================================

/// Response for `pruneblockchain` RPC.
///
/// Returns the last block height that was pruned.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PruneBlockchainResult {
    /// The last block height that was pruned (or would be pruned).
    pub pruneheight: u32,
}

// ============================================================
// DESCRIPTORS
// ============================================================

/// Response for `getdescriptorinfo` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DescriptorInfoResult {
    /// The descriptor string (without checksum).
    pub descriptor: String,
    /// The checksum.
    pub checksum: String,
    /// Whether this is a ranged descriptor.
    pub isrange: bool,
    /// Whether this descriptor requires private keys for solving.
    pub issolvable: bool,
    /// Whether this descriptor has private key data.
    pub hasprivatekeys: bool,
}

/// Response for `deriveaddresses` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeriveAddressesResult {
    /// The derived addresses.
    pub addresses: Vec<String>,
}

/// Request for `importdescriptors` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImportDescriptorRequest {
    /// The descriptor string.
    pub desc: String,
    /// Whether this descriptor has signing keys.
    #[serde(default)]
    pub active: bool,
    /// Optional range for ranged descriptors [start, end] or just end.
    #[serde(default)]
    pub range: Option<serde_json::Value>,
    /// Timestamp for rescanning (0 for genesis, "now" for no rescan).
    #[serde(default)]
    pub timestamp: serde_json::Value,
    /// Whether this is an internal (change) descriptor.
    #[serde(default)]
    pub internal: bool,
    /// Optional label for the addresses.
    #[serde(default)]
    pub label: Option<String>,
}

/// Response for `importdescriptors` RPC (per-descriptor result).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImportDescriptorResult {
    /// Whether the import was successful.
    pub success: bool,
    /// Any warnings during import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    /// Error message if import failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ImportDescriptorError>,
}

/// Error info for failed descriptor import.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImportDescriptorError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

// ============================================================
// PSBT (BIP-174)
// ============================================================

/// Input for `createpsbt` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreatePsbtInput {
    /// Previous transaction ID.
    pub txid: String,
    /// Previous output index.
    pub vout: u32,
    /// Optional sequence number.
    pub sequence: Option<u32>,
}

/// Response for `decodepsbt` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodePsbtResult {
    /// The underlying unsigned transaction.
    pub tx: DecodedRawTransaction,
    /// Global extended public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_xpubs: Option<Vec<GlobalXpub>>,
    /// PSBT version (0 if not specified).
    pub psbt_version: u32,
    /// Unknown global key-value pairs (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown: Option<serde_json::Value>,
    /// Input information.
    pub inputs: Vec<DecodePsbtInput>,
    /// Output information.
    pub outputs: Vec<DecodePsbtOutput>,
    /// Transaction fee in BTC (if calculable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<f64>,
}

/// Global extended public key in decoded PSBT.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GlobalXpub {
    /// Extended public key (base58).
    pub xpub: String,
    /// Master key fingerprint.
    pub master_fingerprint: String,
    /// Derivation path.
    pub path: String,
}

/// Input in decoded PSBT.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodePsbtInput {
    /// Non-witness UTXO (full previous transaction).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_witness_utxo: Option<serde_json::Value>,
    /// Witness UTXO.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_utxo: Option<WitnessUtxo>,
    /// Partial signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_signatures: Option<serde_json::Value>,
    /// Sighash type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sighash: Option<String>,
    /// Redeem script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<ScriptInfo>,
    /// Witness script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<ScriptInfo>,
    /// BIP32 derivation paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip32_derivs: Option<Vec<Bip32Deriv>>,
    /// Final scriptSig.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_scriptsig: Option<ScriptInfo>,
    /// Final scriptWitness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_scriptwitness: Option<Vec<String>>,
    /// Unknown key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown: Option<serde_json::Value>,
}

/// Witness UTXO in decoded PSBT input.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WitnessUtxo {
    /// Amount in BTC.
    pub amount: f64,
    /// Script pubkey info.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: ScriptPubKeyInfo,
}

/// Script information for PSBT.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScriptInfo {
    /// Disassembled script.
    pub asm: String,
    /// Raw hex.
    pub hex: String,
    /// Script type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub script_type: Option<String>,
}

/// BIP32 derivation path information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip32Deriv {
    /// Public key (hex).
    pub pubkey: String,
    /// Master key fingerprint.
    pub master_fingerprint: String,
    /// Derivation path.
    pub path: String,
}

/// Output in decoded PSBT.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecodePsbtOutput {
    /// Redeem script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<ScriptInfo>,
    /// Witness script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<ScriptInfo>,
    /// BIP32 derivation paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip32_derivs: Option<Vec<Bip32Deriv>>,
    /// Unknown key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown: Option<serde_json::Value>,
}

/// Response for `finalizepsbt` RPC.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinalizePsbtResult {
    /// The base64-encoded PSBT (if not extractable or extract is false).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psbt: Option<String>,
    /// The hex-encoded network transaction (if extractable and extract is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    /// Whether the PSBT is complete (all inputs finalized).
    pub complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.bind_address, "127.0.0.1:8332");
        assert!(config.auth_user.is_none());
        assert!(config.auth_password.is_none());
    }

    #[test]
    fn test_rpc_config_testnet4() {
        let config = RpcConfig::testnet4();
        assert_eq!(config.bind_address, "127.0.0.1:48332");
    }

    #[test]
    fn test_blockchain_info_serialization() {
        let info = BlockchainInfo {
            chain: "test".to_string(),
            blocks: 100,
            headers: 100,
            bestblockhash: "000000".to_string(),
            difficulty: 1.0,
            mediantime: 1234567890,
            verificationprogress: 1.0,
            initialblockdownload: false,
            chainwork: "00000000".to_string(),
            size_on_disk: 1000000,
            pruned: false,
            softforks: serde_json::Value::Object(serde_json::Map::new()),
            warnings: "".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"blocks\":100"));
        assert!(json.contains("\"chain\":\"test\""));
    }

    #[test]
    fn test_mempool_info_serialization() {
        let info = MempoolInfo {
            loaded: true,
            size: 100,
            bytes: 50000,
            usage: 100000,
            total_fee: 0.001,
            maxmempool: 300000000,
            mempoolminfee: 0.00001,
            minrelaytxfee: 0.00001,
            incrementalrelayfee: 0.00001,
            unbroadcastcount: 0,
            fullrbf: false,
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: MempoolInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.size, 100);
        assert_eq!(parsed.loaded, true);
    }

    #[test]
    fn test_fee_estimate_result_with_feerate() {
        let result = FeeEstimateResult {
            feerate: Some(0.00001),
            errors: None,
            blocks: 6,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"feerate\""));
        assert!(json.contains("\"blocks\":6"));
    }

    #[test]
    fn test_fee_estimate_result_with_errors() {
        let result = FeeEstimateResult {
            feerate: None,
            errors: Some(vec!["Insufficient data".to_string()]),
            blocks: 2,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"errors\""));
        assert!(json.contains("Insufficient data"));
    }

    #[test]
    fn test_peer_info_rpc_serialization() {
        let peer = PeerInfoRpc {
            id: 1,
            addr: "192.168.1.1:8333".to_string(),
            addrbind: Some("0.0.0.0:8333".to_string()),
            addrlocal: None,
            network: "ipv4".to_string(),
            services: "0000000000000409".to_string(),
            servicesnames: vec!["NETWORK".to_string(), "WITNESS".to_string()],
            relaytxes: true,
            lastsend: 1234567890,
            lastrecv: 1234567891,
            bytessent: 10000,
            bytesrecv: 20000,
            conntime: 1234567800,
            timeoffset: 0,
            pingtime: Some(0.05),
            minping: Some(0.04),
            pingwait: None,
            version: 70016,
            subver: "/Satoshi:25.0.0/".to_string(),
            inbound: false,
            bip152_hb_to: false,
            bip152_hb_from: false,
            startingheight: 100000,
            synced_headers: 100000,
            synced_blocks: 99999,
            connection_type: "outbound-full-relay".to_string(),
        };

        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("\"version\":70016"));
    }

    #[test]
    fn test_validate_address_result() {
        let valid = ValidateAddressResult {
            isvalid: true,
            address: Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string()),
            script_pubkey: Some("0014751e76e8199196d454941c45d1b3a323f1433bd6".to_string()),
            isscript: Some(false),
            iswitness: Some(true),
            witness_version: Some(0),
            witness_program: Some("751e76e8199196d454941c45d1b3a323f1433bd6".to_string()),
        };

        let json = serde_json::to_string(&valid).unwrap();
        assert!(json.contains("\"isvalid\":true"));
        assert!(json.contains("\"witness_version\":0"));
    }

    #[test]
    fn test_validate_address_result_invalid() {
        let invalid = ValidateAddressResult {
            isvalid: false,
            address: None,
            script_pubkey: None,
            isscript: None,
            iswitness: None,
            witness_version: None,
            witness_program: None,
        };

        let json = serde_json::to_string(&invalid).unwrap();
        assert!(json.contains("\"isvalid\":false"));
    }

    #[test]
    fn test_tx_out_result() {
        let result = TxOutResult {
            bestblock: "000000000000".to_string(),
            confirmations: 100,
            value: 1.5,
            script_pubkey: ScriptPubKeyInfo {
                asm: "OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG".to_string(),
                hex: "76a914...88ac".to_string(),
                script_type: "pubkeyhash".to_string(),
                address: Some("1A...".to_string()),
            },
            coinbase: false,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"confirmations\":100"));
        assert!(json.contains("\"value\":1.5"));
    }

    #[test]
    fn test_mining_info() {
        let info = MiningInfo {
            blocks: 800000,
            difficulty: 55621444139429.57,
            networkhashps: 450000000000000000.0,
            pooledtx: 5000,
            chain: "main".to_string(),
            warnings: "".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"blocks\":800000"));
        assert!(json.contains("\"chain\":\"main\""));
    }

    #[test]
    fn test_network_info() {
        let info = NetworkInfo {
            version: 250000,
            subversion: "/Satoshi:25.0.0/".to_string(),
            protocolversion: 70016,
            localservices: "0000000000000409".to_string(),
            localservicesnames: vec!["NETWORK".to_string(), "WITNESS".to_string()],
            localrelay: true,
            timeoffset: 0,
            connections: 10,
            connections_in: 2,
            connections_out: 8,
            networkactive: true,
            networks: vec![],
            relayfee: 0.00001,
            incrementalfee: 0.00001,
            localaddresses: vec![],
            warnings: "".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"connections\":10"));
        assert!(json.contains("\"networkactive\":true"));
    }

    // ============================================================
    // GETBLOCKCHAININFO TESTS
    // ============================================================

    #[test]
    fn test_getblockchaininfo_response_fields() {
        let info = BlockchainInfo {
            chain: "main".to_string(),
            blocks: 850000,
            headers: 850000,
            bestblockhash: "0000000000000000000265abc123def456789012345678901234567890123456"
                .to_string(),
            difficulty: 95672703408666.97,
            mediantime: 1710000000,
            verificationprogress: 0.9999999,
            initialblockdownload: false,
            chainwork: "00000000000000000000000000000000000000007b0e".to_string(),
            size_on_disk: 600_000_000_000,
            pruned: false,
            softforks: serde_json::Value::Object(serde_json::Map::new()),
            warnings: String::new(),
        };

        let json = serde_json::to_string(&info).unwrap();

        // Verify all required fields are present
        assert!(json.contains("\"chain\":\"main\""));
        assert!(json.contains("\"blocks\":850000"));
        assert!(json.contains("\"headers\":850000"));
        assert!(json.contains("\"bestblockhash\":"));
        assert!(json.contains("\"difficulty\":"));
        assert!(json.contains("\"mediantime\":"));
        assert!(json.contains("\"verificationprogress\":"));
        assert!(json.contains("\"initialblockdownload\":false"));
        assert!(json.contains("\"chainwork\":"));
        assert!(json.contains("\"pruned\":false"));
    }

    #[test]
    fn test_getblockchaininfo_testnet_chain() {
        let info = BlockchainInfo {
            chain: "test4".to_string(),
            blocks: 50000,
            headers: 50000,
            bestblockhash: "00000000".repeat(8),
            difficulty: 1.0,
            mediantime: 1700000000,
            verificationprogress: 1.0,
            initialblockdownload: false,
            chainwork: "0".repeat(64),
            size_on_disk: 1_000_000_000,
            pruned: false,
            softforks: serde_json::Value::Object(serde_json::Map::new()),
            warnings: String::new(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"chain\":\"test4\""));
    }

    // ============================================================
    // GETBLOCKTEMPLATE TESTS
    // ============================================================

    #[test]
    fn test_getblocktemplate_response_bip22() {
        let template = BlockTemplateResult {
            version: 0x20000000,
            rules: vec!["csv".to_string(), "segwit".to_string()],
            vbavailable: serde_json::json!({}),
            vbrequired: 0,
            previousblockhash: "00000000".repeat(8),
            transactions: vec![],
            coinbaseaux: serde_json::json!({}),
            coinbasevalue: 312500000,
            longpollid: "someblockid:850000".to_string(),
            target: "0000000000000000000abc".to_string(),
            mintime: 1710000000 - 7200,
            mutable: vec![
                "time".to_string(),
                "transactions".to_string(),
                "prevblock".to_string(),
            ],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1710000000,
            bits: "1d00ffff".to_string(),
            height: 850001,
            default_witness_commitment: None,
        };

        let json = serde_json::to_string(&template).unwrap();

        // BIP22/23 required fields
        assert!(json.contains("\"version\":"));
        assert!(json.contains("\"rules\":"));
        assert!(json.contains("\"previousblockhash\":"));
        assert!(json.contains("\"transactions\":"));
        assert!(json.contains("\"coinbasevalue\":"));
        assert!(json.contains("\"target\":"));
        assert!(json.contains("\"mintime\":"));
        assert!(json.contains("\"mutable\":"));
        assert!(json.contains("\"noncerange\":"));
        assert!(json.contains("\"sigoplimit\":80000"));
        assert!(json.contains("\"sizelimit\":4000000"));
        assert!(json.contains("\"weightlimit\":4000000"));
        assert!(json.contains("\"curtime\":"));
        assert!(json.contains("\"bits\":"));
        assert!(json.contains("\"height\":"));
    }

    #[test]
    fn test_getblocktemplate_transaction_entry() {
        let tx = BlockTemplateTransaction {
            data: "0100000001".to_string(),
            txid: "abcd".repeat(16),
            hash: "efgh".repeat(16),
            depends: vec![0, 1],
            fee: 5000,
            sigops: 4,
            weight: 500,
        };

        let json = serde_json::to_string(&tx).unwrap();
        assert!(json.contains("\"data\":"));
        assert!(json.contains("\"txid\":"));
        assert!(json.contains("\"hash\":"));
        assert!(json.contains("\"depends\":[0,1]"));
        assert!(json.contains("\"fee\":5000"));
        assert!(json.contains("\"sigops\":4"));
        assert!(json.contains("\"weight\":500"));
    }

    // ============================================================
    // GETMEMPOOLINFO TESTS
    // ============================================================

    #[test]
    fn test_getmempoolinfo_response_fields() {
        let info = MempoolInfo {
            loaded: true,
            size: 5000,
            bytes: 2_500_000,
            usage: 5_000_000,
            total_fee: 0.05,
            maxmempool: 300_000_000,
            mempoolminfee: 0.00001,
            minrelaytxfee: 0.00001,
            incrementalrelayfee: 0.00001,
            unbroadcastcount: 10,
            fullrbf: false,
        };

        let json = serde_json::to_string(&info).unwrap();

        // All required Bitcoin Core fields
        assert!(json.contains("\"loaded\":true"));
        assert!(json.contains("\"size\":5000"));
        assert!(json.contains("\"bytes\":2500000"));
        assert!(json.contains("\"usage\":5000000"));
        assert!(json.contains("\"maxmempool\":300000000"));
        assert!(json.contains("\"mempoolminfee\":"));
        assert!(json.contains("\"minrelaytxfee\":"));
        assert!(json.contains("\"unbroadcastcount\":10"));
    }

    // ============================================================
    // GETRAWMEMPOOL VERBOSE TESTS
    // ============================================================

    #[test]
    fn test_getrawmempool_verbose_entry() {
        let entry = MempoolEntry {
            vsize: 250,
            weight: 1000,
            fee: 0.000025,
            modifiedfee: 0.000025,
            time: 1710000000,
            height: 850000,
            descendantcount: 1,
            descendantsize: 250,
            descendantfees: 2500,
            ancestorcount: 0,
            ancestorsize: 0,
            ancestorfees: 0,
            wtxid: "abcd".repeat(16),
            depends: vec!["1234".repeat(16)],
            spentby: vec![],
            bip125_replaceable: true,
            unbroadcast: false,
        };

        let json = serde_json::to_string(&entry).unwrap();

        // Bitcoin Core mempool entry fields
        assert!(json.contains("\"vsize\":250"));
        assert!(json.contains("\"weight\":1000"));
        assert!(json.contains("\"fee\":"));
        assert!(json.contains("\"modifiedfee\":"));
        assert!(json.contains("\"time\":"));
        assert!(json.contains("\"height\":850000"));
        assert!(json.contains("\"descendantcount\":1"));
        assert!(json.contains("\"ancestorcount\":0"));
        assert!(json.contains("\"wtxid\":"));
        assert!(json.contains("\"depends\":"));
        assert!(json.contains("\"spentby\":"));
        assert!(json.contains("\"bip125-replaceable\":true"));
        assert!(json.contains("\"unbroadcast\":false"));
    }

    // ============================================================
    // ESTIMATESMARTFEE TESTS
    // ============================================================

    #[test]
    fn test_estimatesmartfee_success() {
        let result = FeeEstimateResult {
            feerate: Some(0.00015),
            errors: None,
            blocks: 6,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"feerate\":0.00015"));
        assert!(json.contains("\"blocks\":6"));
        // errors should be null, not present
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["errors"].is_null());
    }

    #[test]
    fn test_estimatesmartfee_no_estimate() {
        let result = FeeEstimateResult {
            feerate: None,
            errors: Some(vec![
                "Insufficient data for fee estimation".to_string(),
                "No feerate found".to_string(),
            ]),
            blocks: 2,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"blocks\":2"));
        assert!(json.contains("\"errors\":"));
        assert!(json.contains("Insufficient data"));
        // feerate should be null
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["feerate"].is_null());
    }

    // ============================================================
    // VALIDATEADDRESS TESTS
    // ============================================================

    #[test]
    fn test_validateaddress_p2wpkh_mainnet() {
        let result = ValidateAddressResult {
            isvalid: true,
            address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()),
            script_pubkey: Some("0014751e76e8199196d454941c45d1b3a323f1433bd6".to_string()),
            isscript: Some(false),
            iswitness: Some(true),
            witness_version: Some(0),
            witness_program: Some("751e76e8199196d454941c45d1b3a323f1433bd6".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"isvalid\":true"));
        assert!(json.contains("\"iswitness\":true"));
        assert!(json.contains("\"witness_version\":0"));
    }

    #[test]
    fn test_validateaddress_p2tr() {
        let result = ValidateAddressResult {
            isvalid: true,
            address: Some(
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_string(),
            ),
            script_pubkey: Some(
                "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c".to_string(),
            ),
            isscript: Some(true),
            iswitness: Some(true),
            witness_version: Some(1),
            witness_program: Some(
                "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c".to_string(),
            ),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"isvalid\":true"));
        assert!(json.contains("\"witness_version\":1"));
    }

    #[test]
    fn test_validateaddress_legacy_p2pkh() {
        let result = ValidateAddressResult {
            isvalid: true,
            address: Some("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string()),
            script_pubkey: Some(
                "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac".to_string(),
            ),
            isscript: Some(false),
            iswitness: Some(false),
            witness_version: None,
            witness_program: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"isvalid\":true"));
        assert!(json.contains("\"iswitness\":false"));
        assert!(json.contains("\"witness_version\":null"));
    }

    // ============================================================
    // GETPEERINFO TESTS
    // ============================================================

    #[test]
    fn test_getpeerinfo_outbound_full_relay() {
        let peer = PeerInfoRpc {
            id: 5,
            addr: "192.168.1.100:8333".to_string(),
            addrbind: Some("192.168.1.1:48888".to_string()),
            addrlocal: Some("192.168.1.1:48888".to_string()),
            network: "ipv4".to_string(),
            services: "0000000000000409".to_string(),
            servicesnames: vec![
                "NETWORK".to_string(),
                "WITNESS".to_string(),
                "NETWORK_LIMITED".to_string(),
            ],
            relaytxes: true,
            lastsend: 1710000000,
            lastrecv: 1710000001,
            bytessent: 150000,
            bytesrecv: 200000,
            conntime: 1709990000,
            timeoffset: -1,
            pingtime: Some(0.025),
            minping: Some(0.020),
            pingwait: None,
            version: 70016,
            subver: "/Satoshi:25.0.0/".to_string(),
            inbound: false,
            bip152_hb_to: true,
            bip152_hb_from: true,
            startingheight: 850000,
            synced_headers: 850010,
            synced_blocks: 850005,
            connection_type: "outbound-full-relay".to_string(),
        };

        let json = serde_json::to_string(&peer).unwrap();

        // All Bitcoin Core required fields
        assert!(json.contains("\"id\":5"));
        assert!(json.contains("\"addr\":\"192.168.1.100:8333\""));
        assert!(json.contains("\"services\":"));
        assert!(json.contains("\"servicesnames\":"));
        assert!(json.contains("\"relaytxes\":true"));
        assert!(json.contains("\"lastsend\":"));
        assert!(json.contains("\"lastrecv\":"));
        assert!(json.contains("\"bytessent\":150000"));
        assert!(json.contains("\"bytesrecv\":200000"));
        assert!(json.contains("\"conntime\":"));
        assert!(json.contains("\"pingtime\":"));
        assert!(json.contains("\"version\":70016"));
        assert!(json.contains("\"subver\":\"/Satoshi:25.0.0/\""));
        assert!(json.contains("\"inbound\":false"));
        assert!(json.contains("\"synced_headers\":850010"));
        assert!(json.contains("\"synced_blocks\":850005"));
        assert!(json.contains("\"connection_type\":\"outbound-full-relay\""));
    }

    #[test]
    fn test_getpeerinfo_inbound() {
        let peer = PeerInfoRpc {
            id: 10,
            addr: "10.0.0.50:45678".to_string(),
            addrbind: None,
            addrlocal: None,
            network: "ipv4".to_string(),
            services: "0000000000000001".to_string(),
            servicesnames: vec!["NETWORK".to_string()],
            relaytxes: true,
            lastsend: 0,
            lastrecv: 0,
            bytessent: 0,
            bytesrecv: 0,
            conntime: 0,
            timeoffset: 0,
            pingtime: None,
            minping: None,
            pingwait: None,
            version: 70015,
            subver: "/CustomClient:1.0/".to_string(),
            inbound: true,
            bip152_hb_to: false,
            bip152_hb_from: false,
            startingheight: 0,
            synced_headers: 0,
            synced_blocks: 0,
            connection_type: "inbound".to_string(),
        };

        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains("\"inbound\":true"));
        assert!(json.contains("\"connection_type\":\"inbound\""));
    }

    // ============================================================
    // NETWORK INTERFACE TESTS
    // ============================================================

    #[test]
    fn test_network_interface_serialization() {
        let iface = NetworkInterface {
            name: "onion".to_string(),
            limited: false,
            reachable: true,
            proxy: "127.0.0.1:9050".to_string(),
            proxy_randomize_credentials: true,
        };

        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"name\":\"onion\""));
        assert!(json.contains("\"reachable\":true"));
        assert!(json.contains("\"proxy\":\"127.0.0.1:9050\""));
        assert!(json.contains("\"proxy_randomize_credentials\":true"));
    }
}
