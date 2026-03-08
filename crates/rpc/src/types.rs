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
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8332".to_string(),
            auth_user: None,
            auth_password: None,
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
        }
    }

    /// Create configuration for mainnet.
    pub fn mainnet() -> Self {
        Self {
            bind_address: "127.0.0.1:8332".to_string(),
            auth_user: None,
            auth_password: None,
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
    /// Number of transactions not depending on others.
    pub unbroadcastcount: usize,
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
            unbroadcastcount: 0,
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
}
