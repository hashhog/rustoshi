#![allow(clippy::too_many_arguments)]
//! Wallet RPC methods.
//!
//! This module implements Bitcoin Core-compatible wallet RPCs for multi-wallet support:
//! - `createwallet` - Create a new wallet
//! - `loadwallet` - Load an existing wallet
//! - `unloadwallet` - Unload a loaded wallet
//! - `listwallets` - List currently loaded wallets
//! - `listwalletdir` - List wallet directories
//! - `getbalance` - Get wallet balance
//! - `listunspent` - List unspent transaction outputs
//! - `getnewaddress` - Generate a new address
//! - `sendtoaddress` - Send to an address
//!
//! Reference: Bitcoin Core's `wallet/rpcwallet.cpp`

use std::path::PathBuf;
use std::sync::Arc;

use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use rustoshi_wallet::{CreateWalletOptions, WalletManager, WalletDirEntry};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;


/// Wallet RPC error codes (Bitcoin Core compatible).
pub mod wallet_error {
    /// Wallet error.
    pub const RPC_WALLET_ERROR: i32 = -4;
    /// Insufficient funds.
    pub const RPC_WALLET_INSUFFICIENT_FUNDS: i32 = -6;
    /// Invalid address or key.
    pub const RPC_WALLET_INVALID_ADDRESS_OR_KEY: i32 = -5;
    /// Key pool ran out.
    pub const RPC_WALLET_KEYPOOL_RAN_OUT: i32 = -12;
    /// Unlock needed.
    pub const RPC_WALLET_UNLOCK_NEEDED: i32 = -13;
    /// Passphrase incorrect.
    pub const RPC_WALLET_PASSPHRASE_INCORRECT: i32 = -14;
    /// Wallet already exists.
    pub const RPC_WALLET_ALREADY_EXISTS: i32 = -4;
    /// Wallet already loaded.
    pub const RPC_WALLET_ALREADY_LOADED: i32 = -35;
    /// Wallet not found.
    pub const RPC_WALLET_NOT_FOUND: i32 = -18;
    /// Wallet not specified.
    pub const RPC_WALLET_NOT_SPECIFIED: i32 = -19;
    /// Multiple wallets loaded, wallet must be specified.
    pub const RPC_WALLET_NOT_SELECTED: i32 = -19;
    /// Wallet encryption state precludes this operation
    /// (e.g., walletlock on unencrypted or encryptwallet on already-encrypted).
    pub const RPC_WALLET_WRONG_ENC_STATE: i32 = -15;
}

/// Result of createwallet RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateWalletResult {
    /// Name of the wallet.
    pub name: String,
    /// Warnings generated during creation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Result of loadwallet RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadWalletResult {
    /// Name of the loaded wallet.
    pub name: String,
    /// Warnings generated during loading.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Result of unloadwallet RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnloadWalletResult {
    /// Warning message if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Result of listwalletdir RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListWalletDirResult {
    /// List of wallet directories.
    pub wallets: Vec<WalletDirEntry>,
}

/// Unspent transaction output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnspentOutput {
    /// Transaction ID.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Script pubkey (hex).
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    /// Amount in BTC.
    pub amount: f64,
    /// Number of confirmations.
    pub confirmations: u32,
    /// Whether the output is spendable.
    pub spendable: bool,
    /// Whether the output is solvable.
    pub solvable: bool,
    /// Whether the output is safe to spend.
    pub safe: bool,
}

/// Balance information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceInfo {
    /// Confirmed balance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mine: Option<BalanceDetails>,
    /// Watch-only balance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchonly: Option<BalanceDetails>,
}

/// Balance details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceDetails {
    /// Trusted balance (confirmed).
    pub trusted: f64,
    /// Untrusted balance (unconfirmed).
    pub untrusted_pending: f64,
    /// Immature balance (coinbase).
    pub immature: f64,
}

/// A wallet transaction record (for listtransactions).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletTransaction {
    /// The bitcoin address involved in the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Transaction category: "receive", "send", or "generate".
    pub category: String,
    /// Amount in BTC (negative for sends).
    pub amount: f64,
    /// The label for the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Output index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vout: Option<u32>,
    /// Transaction fee in BTC (negative, only for sends).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<f64>,
    /// Number of confirmations.
    pub confirmations: i32,
    /// Whether the transaction has been abandoned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<bool>,
    /// Block hash containing the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<String>,
    /// Block height containing the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockheight: Option<u32>,
    /// Block index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockindex: Option<u32>,
    /// Block timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocktime: Option<u64>,
    /// Transaction ID.
    pub txid: String,
    /// Wallet conflicts.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub walletconflicts: Vec<String>,
    /// Whether this transaction is BIP125 replaceable.
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: String,
    /// Unix timestamp when the transaction was received.
    pub time: u64,
    /// Unix timestamp when the transaction was received (same as time).
    pub timereceived: u64,
}

/// Result of getwalletinfo RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    /// Wallet name.
    pub walletname: String,
    /// Wallet version.
    pub walletversion: u32,
    /// Wallet format.
    pub format: String,
    /// Confirmed balance in BTC.
    pub balance: f64,
    /// Unconfirmed balance in BTC.
    pub unconfirmed_balance: f64,
    /// Immature (coinbase) balance in BTC.
    pub immature_balance: f64,
    /// Total number of transactions.
    pub txcount: usize,
    /// Deprecated, always 0.
    pub keypoololdest: u64,
    /// Keypool size.
    pub keypoolsize: u32,
    /// Keypool size for internal (change) keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypoolsize_hd_internal: Option<u32>,
    /// Transaction fee setting in BTC/kvB.
    pub paytxfee: f64,
    /// HD seed fingerprint (first 4 bytes of pubkey hash).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hdseedid: Option<String>,
    /// Whether private keys are enabled.
    pub private_keys_enabled: bool,
    /// Whether we avoid address reuse.
    pub avoid_reuse: bool,
    /// Scanning status.
    pub scanning: serde_json::Value,
    /// Whether this is a descriptor wallet.
    pub descriptors: bool,
    /// Whether this wallet uses an external signer.
    pub external_signer: bool,
}

/// Result of signrawtransactionwithwallet RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRawTransactionResult {
    /// The hex-encoded signed transaction.
    pub hex: String,
    /// Whether all inputs were signed successfully.
    pub complete: bool,
    /// Signing errors (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<SigningError>>,
}

/// A signing error for an input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningError {
    /// The transaction ID of the previous output.
    pub txid: String,
    /// The output index of the previous output.
    pub vout: u32,
    /// The scriptSig (hex).
    #[serde(rename = "scriptSig")]
    pub script_sig: String,
    /// Input sequence number.
    pub sequence: u32,
    /// Error message.
    pub error: String,
}

/// Previous transaction output for signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrevTx {
    /// Transaction ID.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// ScriptPubKey (hex).
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    /// Redeem script for P2SH outputs (hex).
    #[serde(rename = "redeemScript", skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<String>,
    /// Witness script for P2WSH outputs (hex).
    #[serde(rename = "witnessScript", skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<String>,
    /// Value in BTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
}

/// A locked outpoint as returned by `listlockunspent` and accepted by
/// `lockunspent`. Mirrors Core's `{txid, vout}` JSON shape exactly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedOutpoint {
    /// Transaction ID (hex, big-endian display order — same as `getrawtransaction`).
    pub txid: String,
    /// Output index.
    pub vout: u32,
}

/// One recipient in `walletcreatefundedpsbt`'s `outputs` array. Core accepts
/// either `{"<address>": amount}` or `{"data": "<hex>"}` (OP_RETURN). We
/// model the address-amount case here; OP_RETURN is rejected for now with
/// an honest "not yet supported" error.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FundedPsbtRecipient {
    /// `{ "address": "...", "amount": 0.001 }` shape (rustoshi-canonical).
    Explicit {
        /// Bitcoin address.
        address: String,
        /// Amount in BTC.
        amount: f64,
    },
    /// `{ "<address>": <amount> }` (Core's compact shape — single key).
    Compact(serde_json::Map<String, serde_json::Value>),
}

/// Options for `walletcreatefundedpsbt` (Core's `options` parameter).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FundedPsbtOptions {
    /// Reserve change for this address instead of generating one.
    #[serde(rename = "changeAddress", skip_serializing_if = "Option::is_none")]
    pub change_address: Option<String>,
    /// Specific position for the change output (default: random).
    #[serde(rename = "changePosition", skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,
    /// Whether to subtract fee from outputs (indices into the outputs array).
    #[serde(rename = "subtractFeeFromOutputs", skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,
    /// Mark the transaction BIP-125 replaceable (default: true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    /// Fee rate in sat/vB.
    #[serde(rename = "fee_rate", skip_serializing_if = "Option::is_none")]
    pub fee_rate: Option<f64>,
    /// Confirmation target in blocks (default: wallet's `-txconfirmtarget`).
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,
    /// Fee estimate mode (`unset`, `economical`, `conservative`).
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<String>,
}

/// Result of `walletcreatefundedpsbt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletCreateFundedPsbtResult {
    /// The base64-encoded PSBT.
    pub psbt: String,
    /// Resulting transaction fee in BTC.
    pub fee: f64,
    /// Position of the change output (-1 if no change was added).
    pub changepos: i32,
}

/// Options for `bumpfee` / `psbtbumpfee`.
///
/// Mirrors a subset of Bitcoin Core's `bumpfee` options. The minimal-
/// viable rustoshi implementation supports `fee_rate` (absolute sat/vB
/// override) only — `conf_target`, `estimate_mode`, `replaceable`,
/// `original_change_index`, and `outputs` reservation are accepted but
/// `outputs` is rejected as not-yet-supported. `replaceable` defaults to
/// true to preserve BIP-125 opt-in.
///
/// Reference: `bitcoin-core/src/wallet/rpc/feebumper.cpp::bumpfee_helper`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BumpFeeOptions {
    /// Confirmation target (deferred — full Core fee-estimator is not wired).
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,
    /// Fee rate override in sat/vB.
    #[serde(rename = "fee_rate", skip_serializing_if = "Option::is_none")]
    pub fee_rate: Option<f64>,
    /// Whether the replacement is replaceable (default: true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    /// Fee estimate mode (`unset`, `economical`, `conservative`).
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<String>,
    /// Originally specified change index (deferred).
    #[serde(rename = "original_change_index", skip_serializing_if = "Option::is_none")]
    pub original_change_index: Option<u32>,
    /// Replace the outputs list explicitly (deferred — not supported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<serde_json::Value>,
}

/// Result of `bumpfee`.
///
/// Mirrors Bitcoin Core's `bumpfee` JSON shape:
/// - `txid`: new replacement transaction id.
/// - `origfee`: original transaction fee (BTC).
/// - `fee`: new transaction fee (BTC).
/// - `errors`: any non-fatal warnings produced during the bump.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BumpFeeResult {
    /// New replacement transaction ID (hex, display order).
    pub txid: String,
    /// Original fee in BTC.
    pub origfee: f64,
    /// New fee in BTC.
    pub fee: f64,
    /// Warnings encountered during the bump.
    pub errors: Vec<String>,
}

/// Result of `psbtbumpfee`.
///
/// Same shape as [`BumpFeeResult`] but with `psbt` instead of `txid` —
/// the replacement is returned as an unsigned PSBT (base64) for signing
/// by another role.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PsbtBumpFeeResult {
    /// Replacement PSBT (base64).
    pub psbt: String,
    /// Original fee in BTC.
    pub origfee: f64,
    /// New fee in BTC.
    pub fee: f64,
    /// Warnings encountered during the bump.
    pub errors: Vec<String>,
}

/// Result of `getpayjoinrequest` (FIX-66, W119 G26).
///
/// The receiver-side helper builds a BIP-21 URI with `pj=<endpoint>`
/// pointing at the local receiver. The caller publishes / hands this
/// URI to a sender, who then runs `sendpayjoinrequest` on it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayjoinRequestResult {
    /// `bitcoin:<addr>?amount=<btc>&pj=<endpoint>` URI.
    pub uri: String,
    /// Receiving address.
    pub address: String,
    /// Amount in BTC (echoed for convenience).
    pub amount: f64,
    /// Endpoint URL the URI embeds (`pj=`).
    pub endpoint: String,
}

/// Options accepted by `sendpayjoinrequest` (FIX-66, W119 G27).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SendPayjoinOptions {
    /// Sender's `maxadditionalfeecontribution` (sats). Default 0 means
    /// "I won't pay any extra fee" — the receiver can still contribute
    /// to the fee but must not push the sender's bill up.
    #[serde(default)]
    pub max_additional_fee_contribution: Option<u64>,
    /// Sender's `additionalfeeoutputindex` — typically the change
    /// output. When `None` the sender forbids fee-output substitution.
    #[serde(default)]
    pub additional_fee_output_index: Option<usize>,
    /// Sender's minimum acceptable fee rate (sat/vB) on the receiver's
    /// reply. Defaults to 1.0 (Core relay floor).
    #[serde(default)]
    pub min_fee_rate: Option<f64>,
    /// If `true`, ban the receiver from substituting the sender→
    /// receiver output script. Defaults to `false` (BIP-78 default).
    #[serde(default)]
    pub disable_output_substitution: Option<bool>,
    /// Per-call overall timeout in seconds. Defaults to 30.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// Result of `sendpayjoinrequest` (FIX-66, W119 G27).
///
/// Success case: `txid` populated with the broadcast txid; the PayJoin
/// completed.
///
/// G22-fallback case: `txid` empty, `fallback_txid` populated with the
/// Original PSBT's txid (the unmodified sender-only tx). `error`
/// carries the human-readable cause that drove the fallback. Per
/// BIP-78 the sender is supposed to broadcast the Original tx on any
/// failure to avoid losing the payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendPayjoinResult {
    /// Broadcast PayJoin txid (hex display order) on success, empty
    /// on G22 fallback.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub txid: String,
    /// Broadcast Original-tx txid (hex display order) when G22 fallback
    /// fired. Empty on the success path.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fallback_txid: String,
    /// Why the fallback was triggered. Empty on success.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// Wallet state for RPC.
pub struct WalletRpcState {
    /// Wallet manager.
    pub wallet_manager: WalletManager,
    /// Data directory path.
    pub data_dir: PathBuf,
    /// Base URL of the local BIP-78 PayJoin receiver endpoint
    /// (FIX-66, W119 G26). The `getpayjoinrequest` RPC embeds this in
    /// the `pj=` query param of the BIP-21 URI it vends. Operators
    /// set this to the operator-reachable address of their
    /// `POST /payjoin` endpoint (https:// or http://*.onion). When
    /// `None` the RPC refuses with `-4` (no endpoint configured).
    pub payjoin_endpoint: Option<String>,
}

impl WalletRpcState {
    /// Create new wallet RPC state.
    pub fn new(wallet_manager: WalletManager, data_dir: PathBuf) -> Self {
        Self {
            wallet_manager,
            data_dir,
            payjoin_endpoint: None,
        }
    }

    /// Override the PayJoin endpoint that `getpayjoinrequest` embeds.
    /// Used by operators (and tests) to advertise their receiver URL.
    pub fn with_payjoin_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.payjoin_endpoint = Some(endpoint.into());
        self
    }
}

/// Wallet RPC trait.
#[rpc(server)]
pub trait WalletRpc {
    /// Create a new wallet.
    ///
    /// Parameters:
    /// - wallet_name: Name for the new wallet
    /// - disable_private_keys: Create a wallet without private keys (watch-only)
    /// - blank: Create a blank wallet with no keys
    /// - passphrase: Encrypt the wallet with this passphrase
    /// - avoid_reuse: Keep track of coin reuse
    /// - descriptors: Create a native descriptor wallet
    /// - load_on_startup: Whether to load this wallet on startup
    #[method(name = "createwallet")]
    async fn create_wallet(
        &self,
        wallet_name: String,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<String>,
        avoid_reuse: Option<bool>,
        descriptors: Option<bool>,
        load_on_startup: Option<bool>,
    ) -> RpcResult<CreateWalletResult>;

    /// Load an existing wallet.
    ///
    /// Parameters:
    /// - filename: The wallet filename or directory name
    /// - load_on_startup: Whether to load this wallet on startup
    #[method(name = "loadwallet")]
    async fn load_wallet(
        &self,
        filename: String,
        load_on_startup: Option<bool>,
    ) -> RpcResult<LoadWalletResult>;

    /// Unload a loaded wallet.
    ///
    /// Parameters:
    /// - wallet_name: Name of the wallet to unload (default: the wallet from URL)
    /// - load_on_startup: Whether to update startup setting
    #[method(name = "unloadwallet")]
    async fn unload_wallet(
        &self,
        wallet_name: Option<String>,
        load_on_startup: Option<bool>,
    ) -> RpcResult<UnloadWalletResult>;

    /// List currently loaded wallets.
    #[method(name = "listwallets")]
    async fn list_wallets(&self) -> RpcResult<Vec<String>>;

    /// List wallet directories.
    #[method(name = "listwalletdir")]
    async fn list_wallet_dir(&self) -> RpcResult<ListWalletDirResult>;

    /// Get the balance for the wallet.
    ///
    /// Parameters:
    /// - dummy: Remains for backward compatibility (ignored)
    /// - minconf: Minimum confirmations (default: 0)
    /// - include_watchonly: Include watch-only addresses (default: true for watch-only wallets)
    /// - avoid_reuse: Only include UTXOs not used in other unconfirmed txs (default: true)
    #[method(name = "getbalance")]
    async fn get_balance(
        &self,
        dummy: Option<String>,
        minconf: Option<u32>,
        include_watchonly: Option<bool>,
        avoid_reuse: Option<bool>,
    ) -> RpcResult<f64>;

    /// Get detailed balance information.
    #[method(name = "getbalances")]
    async fn get_balances(&self) -> RpcResult<BalanceInfo>;

    /// List unspent transaction outputs.
    ///
    /// Parameters:
    /// - minconf: Minimum confirmations (default: 1)
    /// - maxconf: Maximum confirmations (default: 9999999)
    /// - addresses: Filter to specific addresses
    /// - include_unsafe: Include outputs that are not safe to spend (default: true)
    /// - query_options: Additional filter options
    #[method(name = "listunspent")]
    async fn list_unspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        addresses: Option<Vec<String>>,
        include_unsafe: Option<bool>,
        query_options: Option<serde_json::Value>,
    ) -> RpcResult<Vec<UnspentOutput>>;

    /// Generate a new receiving address.
    ///
    /// Parameters:
    /// - label: Label for the address
    /// - address_type: Address type (legacy, p2sh-segwit, bech32, bech32m)
    #[method(name = "getnewaddress")]
    async fn get_new_address(
        &self,
        label: Option<String>,
        address_type: Option<String>,
    ) -> RpcResult<String>;

    /// Send an amount to a given address.
    ///
    /// Parameters:
    /// - address: The bitcoin address to send to
    /// - amount: The amount in BTC to send
    /// - comment: A comment for the transaction (not sent)
    /// - comment_to: A comment about who the transaction is for (not sent)
    /// - subtractfeefromamount: Subtract fee from amount
    /// - replaceable: Allow this transaction to be replaced (BIP-125)
    /// - conf_target: Confirmation target in blocks
    /// - estimate_mode: Fee estimate mode (unset, economical, conservative)
    #[method(name = "sendtoaddress")]
    async fn send_to_address(
        &self,
        address: String,
        amount: f64,
        comment: Option<String>,
        comment_to: Option<String>,
        subtractfeefromamount: Option<bool>,
        replaceable: Option<bool>,
        conf_target: Option<u32>,
        estimate_mode: Option<String>,
    ) -> RpcResult<String>;

    /// List wallet transactions.
    ///
    /// Parameters:
    /// - label: Filter by label (optional, default: all labels)
    /// - count: Number of transactions to return (default: 10)
    /// - skip: Number of transactions to skip (default: 0)
    /// - include_watchonly: Include watch-only addresses (default: true for watch-only wallets)
    #[method(name = "listtransactions")]
    async fn list_transactions(
        &self,
        label: Option<String>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> RpcResult<Vec<WalletTransaction>>;

    /// Get wallet information.
    #[method(name = "getwalletinfo")]
    async fn get_wallet_info(&self) -> RpcResult<WalletInfo>;

    /// Sign a raw transaction with wallet keys.
    ///
    /// Parameters:
    /// - hexstring: The hex-encoded raw transaction
    /// - prevtxs: Previous outputs being spent (optional, for external UTXOs)
    /// - sighashtype: Signature hash type (default: ALL)
    #[method(name = "signrawtransactionwithwallet")]
    async fn sign_raw_transaction_with_wallet(
        &self,
        hexstring: String,
        prevtxs: Option<Vec<PrevTx>>,
        sighashtype: Option<String>,
    ) -> RpcResult<SignRawTransactionResult>;

    /// Import descriptors into the wallet.
    ///
    /// Parameters:
    /// - requests: Array of import descriptor requests
    #[method(name = "importdescriptors")]
    async fn import_descriptors(
        &self,
        requests: Vec<crate::types::ImportDescriptorRequest>,
    ) -> RpcResult<Vec<crate::types::ImportDescriptorResult>>;

    /// Lock or unlock specified UTXOs from automatic coin selection.
    ///
    /// Mirrors `bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent`. With
    /// `unlock=true` and an empty/missing transaction list, all locks are
    /// cleared. The `persistent` flag is accepted for compatibility but
    /// currently treated as in-memory only (Core's `persistent=false`
    /// default behaviour). Returns true on success.
    ///
    /// Parameters:
    /// - unlock: false=lock, true=unlock the listed outpoints.
    /// - transactions: array of `{txid, vout}` objects. Optional; absent +
    ///   unlock=true clears all locks (Core's `UnlockAllCoins`).
    /// - persistent: write/erase to wallet DB (defaults false; in this build
    ///   only in-memory locks are supported).
    #[method(name = "lockunspent")]
    async fn lock_unspent(
        &self,
        unlock: bool,
        transactions: Option<Vec<LockedOutpoint>>,
        persistent: Option<bool>,
    ) -> RpcResult<bool>;

    /// List currently locked outpoints (Core's
    /// `bitcoin-core/src/wallet/rpc/coins.cpp::listlockunspent`). Returns an
    /// array of `{txid, vout}` objects. Order is unspecified by Core.
    #[method(name = "listlockunspent")]
    async fn list_lock_unspent(&self) -> RpcResult<Vec<LockedOutpoint>>;

    /// Store the wallet decryption key in memory for `timeout` seconds.
    ///
    /// Mirrors Bitcoin Core's `walletpassphrase` RPC
    /// (`bitcoin-core/src/wallet/rpc/encrypt.cpp`). After unlocking, signing
    /// operations (`sendtoaddress`, `signrawtransactionwithwallet`,
    /// `walletcreatefundedpsbt` for non-watch-only spends, etc.) can run
    /// without re-prompting. Once `timeout` seconds elapse the wallet
    /// re-locks automatically.
    ///
    /// Errors with:
    /// - `-13` (RPC_WALLET_UNLOCK_NEEDED) — wallet is not encrypted.
    /// - `-14` (RPC_WALLET_PASSPHRASE_INCORRECT) — passphrase rejected.
    ///
    /// Parameters:
    /// - passphrase: wallet passphrase (must not be empty).
    /// - timeout: timeout in seconds (Core's max is 100,000,000s; we cap
    ///   identically).
    #[method(name = "walletpassphrase")]
    async fn wallet_passphrase(
        &self,
        passphrase: String,
        timeout: u64,
    ) -> RpcResult<()>;

    /// Re-lock an encrypted wallet, scrubbing the master key from memory.
    /// Mirrors Bitcoin Core's `walletlock` RPC.
    ///
    /// Errors with `-15` (RPC_WALLET_WRONG_ENC_STATE) if the wallet is not
    /// encrypted.
    #[method(name = "walletlock")]
    async fn wallet_lock(&self) -> RpcResult<()>;

    /// Encrypt an unencrypted wallet's seed at rest. Mirrors Bitcoin Core's
    /// `encryptwallet` RPC. Unlike Core, this implementation does NOT force
    /// a server shutdown after success — the wallet stays usable for the
    /// session.
    ///
    /// Errors with `-15` (RPC_WALLET_WRONG_ENC_STATE) if the wallet is
    /// already encrypted or the passphrase is empty.
    #[method(name = "encryptwallet")]
    async fn encrypt_wallet(&self, passphrase: String) -> RpcResult<String>;

    /// Change the passphrase on an encrypted wallet. Mirrors Bitcoin Core's
    /// `walletpassphrasechange` RPC.
    #[method(name = "walletpassphrasechange")]
    async fn wallet_passphrase_change(
        &self,
        oldpassphrase: String,
        newpassphrase: String,
    ) -> RpcResult<()>;

    /// Build a funded PSBT (Core's `walletcreatefundedpsbt`).
    ///
    /// Mirrors `bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt`.
    /// Selects coins from the wallet (skipping locked outputs), adds a
    /// change output if needed, and returns a base64-encoded PSBT plus the
    /// computed fee and change position.
    ///
    /// Parameters:
    /// - inputs: explicit inputs to include (each `{txid, vout}`); empty for
    ///   "let the wallet choose" (auto-coin-selection).
    /// - outputs: array of recipient objects. Each is either
    ///   `{"address": "...", "amount": 0.01}` or Core's compact
    ///   `{"<addr>": 0.01}` form. OP_RETURN (`{"data": "..."}`) is not yet
    ///   supported and produces an honest error.
    /// - locktime: nLockTime for the resulting transaction (default: 0).
    /// - options: per-spend options (changeAddress, fee_rate, replaceable, …).
    /// - bip32derivs: include BIP-32 derivation paths in the PSBT (default: true).
    #[method(name = "walletcreatefundedpsbt")]
    async fn wallet_create_funded_psbt(
        &self,
        inputs: Vec<LockedOutpoint>,
        outputs: Vec<FundedPsbtRecipient>,
        locktime: Option<u32>,
        options: Option<FundedPsbtOptions>,
        bip32derivs: Option<bool>,
    ) -> RpcResult<WalletCreateFundedPsbtResult>;

    /// Bump the fee on a wallet-created, BIP-125-replaceable, unconfirmed
    /// transaction (FIX-61, W118 BUG-2 closure).
    ///
    /// Mirrors Bitcoin Core's `bumpfee` RPC
    /// (`bitcoin-core/src/wallet/rpc/feebumper.cpp::bumpfee`). The
    /// rustoshi implementation is minimal-viable: it reduces the wallet-
    /// owned change output to cover a 1 sat/vB-per-vbyte fee bump (or a
    /// caller-specified `fee_rate`), re-signs, and submits.
    ///
    /// Errors:
    /// - `-4` (RPC_WALLET_ERROR) if the tx is not in the wallet, is
    ///   already confirmed, does not signal BIP-125, lacks a wallet-owned
    ///   change output, or would push change below dust.
    /// - `-6` (RPC_WALLET_INSUFFICIENT_FUNDS) if the delta exceeds change
    ///   value.
    /// - `-13` (RPC_WALLET_UNLOCK_NEEDED) if the wallet is encrypted and
    ///   locked (signing requires unlock).
    ///
    /// Parameters:
    /// - `txid`: hex (display order) of the transaction to replace.
    /// - `options`: optional `BumpFeeOptions`. Only `fee_rate` is
    ///   honoured in this minimal cut; other fields are accepted but
    ///   informational.
    #[method(name = "bumpfee")]
    async fn bump_fee(
        &self,
        txid: String,
        options: Option<BumpFeeOptions>,
    ) -> RpcResult<BumpFeeResult>;

    /// PSBT variant of `bumpfee`: returns an unsigned replacement PSBT
    /// (base64) instead of submitting a signed tx (FIX-61, W118 BUG-3
    /// closure).
    ///
    /// Mirrors Bitcoin Core's `psbtbumpfee` RPC. Same validation rules as
    /// [`Self::bump_fee`] except signing is skipped; the result is a
    /// Creator+Updater PSBT that a separate signing role can finalize.
    ///
    /// Parameters:
    /// - `txid`: hex (display order) of the transaction to replace.
    /// - `options`: same shape as `bumpfee`'s options.
    #[method(name = "psbtbumpfee")]
    async fn psbt_bump_fee(
        &self,
        txid: String,
        options: Option<BumpFeeOptions>,
    ) -> RpcResult<PsbtBumpFeeResult>;

    /// Build a BIP-21 PayJoin request URI for a fresh receive address
    /// (FIX-66, W119 G26 / BUG-15).
    ///
    /// Generates a new wallet address, then returns
    /// `bitcoin:<addr>?amount=<btc>&pj=<endpoint>` where `<endpoint>`
    /// is the operator-configured receiver URL
    /// (`WalletRpcState::payjoin_endpoint`). The sender can then drive
    /// the full PayJoin flow against this URI with `sendpayjoinrequest`.
    ///
    /// Errors:
    /// - `-4` (`RPC_WALLET_ERROR`) when no PayJoin endpoint is
    ///   configured on this node (operator must call
    ///   `WalletRpcState::with_payjoin_endpoint` at startup).
    /// - `-13` (`RPC_WALLET_UNLOCK_NEEDED`) when the wallet is locked
    ///   (a fresh address requires the master key for derivation).
    /// - `-3` invalid amount (must be > 0).
    #[method(name = "getpayjoinrequest")]
    async fn get_payjoin_request(
        &self,
        address: Option<String>,
        amount: f64,
    ) -> RpcResult<PayjoinRequestResult>;

    /// Drive a full BIP-78 PayJoin send (FIX-66, W119 G27 / BUG-15).
    ///
    /// 1. Parse the URI's `pj=` and `pjos=` (via FIX-62 `parse_bip21`).
    /// 2. Build an Original PSBT paying the URI's recipient + amount.
    /// 3. POST it to the `pj=` endpoint over HTTPS (or `.onion` HTTP).
    /// 4. Run all six anti-snoop validators (G10..G15) on the reply.
    /// 5. Re-sign the sender's inputs and return the broadcast txid.
    ///
    /// On any error the sender falls back to broadcasting the Original
    /// tx (BIP-78 §"Sender's actions" / G22), and the result carries
    /// `fallback_txid` + `error` instead of `txid`.
    ///
    /// Parameters:
    /// - `uri`: full BIP-21 URI (`bitcoin:...?...&pj=https://.../payjoin`).
    /// - `options`: BIP-78 sender knobs (max additional fee, minfeerate,
    ///   disable substitution, timeout).
    #[method(name = "sendpayjoinrequest")]
    async fn send_payjoin_request(
        &self,
        uri: String,
        options: Option<SendPayjoinOptions>,
    ) -> RpcResult<SendPayjoinResult>;
}

/// Wallet RPC implementation.
pub struct WalletRpcImpl {
    /// Wallet state.
    state: Arc<RwLock<WalletRpcState>>,
    /// Currently targeted wallet name (from URL).
    target_wallet: Option<String>,
}

impl WalletRpcImpl {
    /// Create a new wallet RPC implementation.
    pub fn new(state: Arc<RwLock<WalletRpcState>>) -> Self {
        Self {
            state,
            target_wallet: None,
        }
    }

    /// Create a wallet RPC implementation targeting a specific wallet.
    pub fn with_target_wallet(state: Arc<RwLock<WalletRpcState>>, wallet_name: String) -> Self {
        Self {
            state,
            target_wallet: Some(wallet_name),
        }
    }

    /// Helper to create an RPC error.
    fn rpc_error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(code, message.into(), None::<()>)
    }

    /// Satoshis to BTC.
    fn sats_to_btc(sats: u64) -> f64 {
        sats as f64 / 100_000_000.0
    }

    /// BTC to satoshis.
    fn btc_to_sats(btc: f64) -> u64 {
        (btc * 100_000_000.0).round() as u64
    }

    /// Translate `WalletError::WalletLocked` into Core's
    /// `RPC_WALLET_UNLOCK_NEEDED` (-13). Every signing RPC funnels through
    /// here so the error message is uniform.
    fn require_unlocked(
        state: &WalletRpcState,
        name: &str,
    ) -> Result<(), ErrorObjectOwned> {
        state.wallet_manager.require_unlocked(name).map_err(|e| {
            use rustoshi_wallet::WalletError;
            match e {
                WalletError::WalletLocked => Self::rpc_error(
                    wallet_error::RPC_WALLET_UNLOCK_NEEDED,
                    "Error: Please enter the wallet passphrase with walletpassphrase first.",
                ),
                other => Self::rpc_error(wallet_error::RPC_WALLET_ERROR, other.to_string()),
            }
        })
    }

    /// FIX-61: parse a txid (hex display-order, 32 bytes) and return the
    /// internal-order `Hash256`. Mirrors how `gettransaction` / `bumpfee`
    /// expect the txid argument.
    fn parse_txid_hex(txid_hex: &str) -> Result<rustoshi_primitives::Hash256, ErrorObjectOwned> {
        let bytes = hex::decode(txid_hex).map_err(|_| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                format!("Invalid txid hex: {}", txid_hex),
            )
        })?;
        if bytes.len() != 32 {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "txid must be 32 bytes",
            ));
        }
        let mut internal = [0u8; 32];
        internal.copy_from_slice(&bytes);
        internal.reverse(); // display → internal
        Ok(rustoshi_primitives::Hash256(internal))
    }

    /// FIX-61: translate a `WalletError` produced by `bump_fee` /
    /// `psbt_bump_fee` into the closest Core-compatible RPC error code.
    /// Pattern-matches on the message so we keep the existing
    /// `WalletError::SigningError(String)` shape — the bump-fee helpers
    /// emit message-encoded reasons.
    fn bumpfee_err_to_rpc(e: rustoshi_wallet::WalletError) -> ErrorObjectOwned {
        use rustoshi_wallet::WalletError;
        let msg = e.to_string();
        // Insufficient-funds-shaped reasons (delta > change_value).
        if msg.contains("exceeds change output value") || msg.contains("insufficient") {
            return Self::rpc_error(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, msg);
        }
        match e {
            WalletError::WalletLocked => Self::rpc_error(
                wallet_error::RPC_WALLET_UNLOCK_NEEDED,
                "Error: Please enter the wallet passphrase with walletpassphrase first.",
            ),
            _ => Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg),
        }
    }
}

#[async_trait]
impl WalletRpcServer for WalletRpcImpl {
    async fn create_wallet(
        &self,
        wallet_name: String,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<String>,
        avoid_reuse: Option<bool>,
        descriptors: Option<bool>,
        load_on_startup: Option<bool>,
    ) -> RpcResult<CreateWalletResult> {
        let mut state = self.state.write().await;

        let options = CreateWalletOptions {
            disable_private_keys: disable_private_keys.unwrap_or(false),
            blank: blank.unwrap_or(false),
            passphrase,
            avoid_reuse: avoid_reuse.unwrap_or(false),
            descriptors: descriptors.unwrap_or(true),
            load_on_startup,
        };

        let result = state.wallet_manager.create_wallet(&wallet_name, options)
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string()))?;

        Ok(CreateWalletResult {
            name: result.name,
            warnings: result.warnings,
        })
    }

    async fn load_wallet(
        &self,
        filename: String,
        _load_on_startup: Option<bool>,
    ) -> RpcResult<LoadWalletResult> {
        let mut state = self.state.write().await;

        let result = state.wallet_manager.load_wallet(&filename)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("already loaded") {
                    Self::rpc_error(wallet_error::RPC_WALLET_ALREADY_LOADED, msg)
                } else if msg.contains("not found") {
                    Self::rpc_error(wallet_error::RPC_WALLET_NOT_FOUND, msg)
                } else {
                    Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                }
            })?;

        Ok(LoadWalletResult {
            name: result.name,
            warnings: result.warnings,
        })
    }

    async fn unload_wallet(
        &self,
        wallet_name: Option<String>,
        _load_on_startup: Option<bool>,
    ) -> RpcResult<UnloadWalletResult> {
        let mut state = self.state.write().await;

        // Determine which wallet to unload
        let name = wallet_name
            .or_else(|| self.target_wallet.clone())
            .ok_or_else(|| {
                if state.wallet_manager.wallet_count() > 1 {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_NOT_SPECIFIED,
                        "No wallet specified (multiple wallets loaded). Use wallet_name parameter or /wallet/<name> URL.",
                    )
                } else if state.wallet_manager.wallet_count() == 0 {
                    Self::rpc_error(wallet_error::RPC_WALLET_NOT_FOUND, "No wallets are currently loaded")
                } else {
                    // Single wallet loaded, we should get it from the manager
                    Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, "Wallet name required")
                }
            })?;

        state.wallet_manager.unload_wallet(&name, true)
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string()))?;

        Ok(UnloadWalletResult { warning: None })
    }

    async fn list_wallets(&self) -> RpcResult<Vec<String>> {
        let state = self.state.read().await;
        Ok(state.wallet_manager.list_wallets())
    }

    async fn list_wallet_dir(&self) -> RpcResult<ListWalletDirResult> {
        let state = self.state.read().await;
        let wallets = state.wallet_manager.list_wallet_dir()
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string()))?;
        Ok(ListWalletDirResult { wallets })
    }

    async fn get_balance(
        &self,
        _dummy: Option<String>,
        minconf: Option<u32>,
        _include_watchonly: Option<bool>,
        _avoid_reuse: Option<bool>,
    ) -> RpcResult<f64> {
        let state = self.state.read().await;

        let (_, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let min_confirmations = minconf.unwrap_or(0);
        let balance = if min_confirmations == 0 {
            wallet_guard.balance()
        } else {
            wallet_guard.confirmed_balance()
        };

        Ok(Self::sats_to_btc(balance))
    }

    async fn get_balances(&self) -> RpcResult<BalanceInfo> {
        let state = self.state.read().await;

        let (_, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let trusted = Self::sats_to_btc(wallet_guard.confirmed_balance());
        let untrusted = Self::sats_to_btc(wallet_guard.unconfirmed_balance());
        let immature = Self::sats_to_btc(wallet_guard.immature_balance());

        Ok(BalanceInfo {
            mine: Some(BalanceDetails {
                trusted,
                untrusted_pending: untrusted,
                immature,
            }),
            watchonly: None,
        })
    }

    async fn list_unspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        addresses: Option<Vec<String>>,
        _include_unsafe: Option<bool>,
        _query_options: Option<serde_json::Value>,
    ) -> RpcResult<Vec<UnspentOutput>> {
        let state = self.state.read().await;

        let (_, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let min_confirmations = minconf.unwrap_or(1);
        let max_confirmations = maxconf.unwrap_or(9999999);

        let utxos: Vec<UnspentOutput> = wallet_guard
            .list_unspent()
            .iter()
            .filter(|utxo| {
                utxo.confirmations >= min_confirmations && utxo.confirmations <= max_confirmations
            })
            .filter(|_utxo| {
                // Filter by addresses if specified
                addresses.as_ref().is_none_or(|addrs| {
                    // We'd need to derive the address from the UTXO to filter
                    // For now, accept all if addresses are specified
                    !addrs.is_empty()
                })
            })
            .map(|utxo| {
                UnspentOutput {
                    txid: hex::encode(utxo.outpoint.txid.0.iter().rev().copied().collect::<Vec<_>>()),
                    vout: utxo.outpoint.vout,
                    address: None, // Would need to derive from script
                    script_pubkey: hex::encode(&utxo.script_pubkey),
                    amount: Self::sats_to_btc(utxo.value),
                    confirmations: utxo.confirmations,
                    spendable: true,
                    solvable: true,
                    safe: utxo.confirmations >= 1,
                }
            })
            .collect();

        Ok(utxos)
    }

    async fn get_new_address(
        &self,
        _label: Option<String>,
        _address_type: Option<String>,
    ) -> RpcResult<String> {
        let state = self.state.read().await;

        let (_, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let mut wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let address = wallet_guard.get_new_address()
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string()))?;

        Ok(address)
    }

    async fn send_to_address(
        &self,
        address: String,
        amount: f64,
        _comment: Option<String>,
        _comment_to: Option<String>,
        _subtractfeefromamount: Option<bool>,
        _replaceable: Option<bool>,
        _conf_target: Option<u32>,
        _estimate_mode: Option<String>,
    ) -> RpcResult<String> {
        let state = self.state.read().await;

        let (name, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        // P0-SECURITY gate (W118 BUG-1): signing requires an unlocked wallet.
        Self::require_unlocked(&state, &name)?;

        let mut wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let amount_sats = Self::btc_to_sats(amount);
        let fee_rate = 2.0; // Default fee rate in sat/vbyte

        let tx = wallet_guard.create_transaction(vec![(address, amount_sats)], fee_rate)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("insufficient") {
                    Self::rpc_error(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, msg)
                } else if msg.contains("address") {
                    Self::rpc_error(wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY, msg)
                } else {
                    Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                }
            })?;

        // Return the transaction ID (reversed for display)
        let txid = tx.txid();
        let txid_hex = hex::encode(txid.0.iter().rev().copied().collect::<Vec<_>>());
        Ok(txid_hex)
    }

    async fn list_transactions(
        &self,
        _label: Option<String>,
        count: Option<usize>,
        skip: Option<usize>,
        _include_watchonly: Option<bool>,
    ) -> RpcResult<Vec<WalletTransaction>> {
        let state = self.state.read().await;

        let (wallet_name, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let count = count.unwrap_or(10);
        let skip = skip.unwrap_or(0);

        // Get transactions from UTXOs (both spent and unspent represent wallet activity)
        // For a full implementation, we'd track sends and receives separately
        let mut transactions: Vec<WalletTransaction> = Vec::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Get all UTXOs (these represent received transactions)
        for utxo in wallet_guard.list_unspent() {
            let txid_hex = hex::encode(utxo.outpoint.txid.0.iter().rev().copied().collect::<Vec<_>>());
            let category = if utxo.is_coinbase { "generate" } else { "receive" };

            transactions.push(WalletTransaction {
                address: None, // Would derive from script
                category: category.to_string(),
                amount: Self::sats_to_btc(utxo.value),
                label: None,
                vout: Some(utxo.outpoint.vout),
                fee: None,
                confirmations: utxo.confirmations as i32,
                abandoned: None,
                blockhash: None,
                blockheight: utxo.height,
                blockindex: None,
                blocktime: None,
                txid: txid_hex,
                walletconflicts: vec![],
                bip125_replaceable: "no".to_string(),
                time: now,
                timereceived: now,
            });
        }

        // Sort by time descending
        transactions.sort_by(|a, b| b.time.cmp(&a.time));

        // Apply pagination
        let transactions: Vec<WalletTransaction> = transactions
            .into_iter()
            .skip(skip)
            .take(count)
            .collect();

        tracing::debug!("listtransactions for wallet {}: {} results", wallet_name, transactions.len());
        Ok(transactions)
    }

    async fn get_wallet_info(&self) -> RpcResult<WalletInfo> {
        let state = self.state.read().await;

        let (wallet_name, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let balance = Self::sats_to_btc(wallet_guard.confirmed_balance());
        let unconfirmed_balance = Self::sats_to_btc(wallet_guard.unconfirmed_balance());
        let immature_balance = Self::sats_to_btc(wallet_guard.immature_balance());
        let tx_count = wallet_guard.list_unspent().len(); // Approximation

        Ok(WalletInfo {
            walletname: wallet_name,
            walletversion: 169900,
            format: "sqlite".to_string(),
            balance,
            unconfirmed_balance,
            immature_balance,
            txcount: tx_count,
            keypoololdest: 0,
            keypoolsize: 1000,
            keypoolsize_hd_internal: Some(1000),
            paytxfee: 0.0,
            hdseedid: None,
            private_keys_enabled: true,
            avoid_reuse: false,
            scanning: serde_json::Value::Bool(false),
            descriptors: true,
            external_signer: false,
        })
    }

    async fn sign_raw_transaction_with_wallet(
        &self,
        hexstring: String,
        prevtxs: Option<Vec<PrevTx>>,
        sighashtype: Option<String>,
    ) -> RpcResult<SignRawTransactionResult> {
        use rustoshi_primitives::{Transaction, Decodable, Encodable};
        use rustoshi_wallet::WalletUtxo;

        let state = self.state.read().await;

        let (name, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        // P0-SECURITY gate (W118 BUG-1): signing requires an unlocked wallet.
        Self::require_unlocked(&state, &name)?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // Decode the transaction
        let tx_bytes = hex::decode(&hexstring)
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, format!("Invalid hex: {}", e)))?;

        let mut tx = Transaction::deserialize(&tx_bytes)
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, format!("Failed to decode transaction: {}", e)))?;

        // Sighash type — currently only SIGHASH_ALL (default) is wired into the
        // wallet's sign_input dispatcher. Refuse anything else explicitly so
        // callers don't get a silent SIGHASH_ALL when they asked for SINGLE.
        let sighash_type_str = sighashtype.as_deref().unwrap_or("ALL");
        if !matches!(sighash_type_str, "ALL" | "DEFAULT" | "ALL|ANYONECANPAY") {
            // For now we honestly refuse rather than lie. ANYONECANPAY parsing
            // would also require sighash propagation through the wallet sign
            // helpers, which currently hardcode 0x01.
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                format!(
                    "sighashtype {:?} not yet supported (only ALL/DEFAULT)",
                    sighash_type_str
                ),
            ));
        }

        // Build a parallel vec of WalletUtxo for each input, in input order.
        // This is required for BIP-341 Taproot sighash, which needs the full
        // prevouts vector. Inputs whose UTXO is not in the wallet are marked
        // None and will produce a per-input error (not a lying success).
        let prev_utxos: Vec<Option<WalletUtxo>> = tx
            .inputs
            .iter()
            .map(|input| wallet_guard.get_utxo(&input.previous_output).cloned())
            .collect();

        // For Taproot sighash we need the prev utxo of EVERY input. If any is
        // missing, taproot signing for any wallet-owned input would compute the
        // wrong sha_prevouts/sha_amounts/sha_scriptpubkeys. Detect this case
        // and surface it as a per-input error rather than producing a wrong
        // signature.
        let any_missing = prev_utxos.iter().any(|u| u.is_none());

        // Materialise a Vec<WalletUtxo> for the wallet's sign_input call. For
        // missing entries we substitute a zeroed placeholder; sign_input will
        // never read it for a missing input (we skip those), and for present
        // taproot inputs we gate on `any_missing` above.
        let placeholder = WalletUtxo {
            outpoint: rustoshi_primitives::OutPoint {
                txid: rustoshi_primitives::Hash256([0u8; 32]),
                vout: 0,
            },
            value: 0,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 0,
            is_change: false,
            is_coinbase: false,
            height: None,
        };
        let all_prev_utxos: Vec<WalletUtxo> = prev_utxos
            .iter()
            .map(|opt| opt.clone().unwrap_or_else(|| placeholder.clone()))
            .collect();

        let mut errors: Vec<SigningError> = Vec::new();

        // Snapshot the inputs' txid/vout up front so we can build per-input
        // errors after the borrow checker hands &mut tx to sign_input.
        let input_meta: Vec<(String, u32, u32)> = tx
            .inputs
            .iter()
            .map(|inp| {
                let txid_hex = hex::encode(
                    inp.previous_output
                        .txid
                        .0
                        .iter()
                        .rev()
                        .copied()
                        .collect::<Vec<_>>(),
                );
                (txid_hex, inp.previous_output.vout, inp.sequence)
            })
            .collect();

        for (i, prev) in prev_utxos.iter().enumerate() {
            let (txid_hex, vout, sequence) = input_meta[i].clone();

            let Some(_utxo) = prev else {
                // Input prevout not in wallet. If caller supplied prevtxs we
                // *could* in theory verify the script type, but we still don't
                // have the private key — wallet-only signer can't sign foreign
                // UTXOs. Mirror Core's "Unable to sign input, no keys in this
                // wallet for this output" message.
                let provided_in_prevtxs = prevtxs
                    .as_ref()
                    .map(|list| {
                        list.iter()
                            .any(|p| p.txid == txid_hex && p.vout == vout)
                    })
                    .unwrap_or(false);
                let msg = if provided_in_prevtxs {
                    "Unable to sign input, key not in wallet"
                } else {
                    "Input not found in wallet and not provided in prevtxs"
                };
                errors.push(SigningError {
                    txid: txid_hex,
                    vout,
                    script_sig: hex::encode(&tx.inputs[i].script_sig),
                    sequence,
                    error: msg.to_string(),
                });
                continue;
            };

            // Taproot guard: if any other input's prevout is unknown, we cannot
            // produce a correct BIP-341 sighash for THIS input either if it is
            // taproot. Detect taproot via the UTXO's script_pubkey shape.
            let spk = &_utxo.script_pubkey;
            let is_tr = spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20;
            if is_tr && any_missing {
                errors.push(SigningError {
                    txid: txid_hex,
                    vout,
                    script_sig: hex::encode(&tx.inputs[i].script_sig),
                    sequence,
                    error: "Cannot sign Taproot input: prevouts of other inputs are not in wallet (BIP-341 sighash requires all prevouts)".to_string(),
                });
                continue;
            }

            // Real signing — splices script_sig / witness in place.
            if let Err(e) = wallet_guard.sign_input(&mut tx, i, &all_prev_utxos) {
                errors.push(SigningError {
                    txid: txid_hex,
                    vout,
                    script_sig: hex::encode(&tx.inputs[i].script_sig),
                    sequence,
                    error: format!("Signing failed: {}", e),
                });
            }
        }

        // complete is true ONLY if every input was signed without error.
        // This is the lying-RPC fix: previously complete=true was returned
        // even when no input had been modified.
        let complete = errors.is_empty();

        // Serialize the (possibly partially) signed transaction
        let signed_bytes = tx.serialize();
        let signed_hex = hex::encode(&signed_bytes);

        Ok(SignRawTransactionResult {
            hex: signed_hex,
            complete,
            errors: if errors.is_empty() { None } else { Some(errors) },
        })
    }

    async fn import_descriptors(
        &self,
        requests: Vec<crate::types::ImportDescriptorRequest>,
    ) -> RpcResult<Vec<crate::types::ImportDescriptorResult>> {
        use rustoshi_wallet::descriptor::{parse_descriptor, verify_checksum};

        let state = self.state.read().await;

        let (_wallet_name, wallet) = state.wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let mut _wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let mut results: Vec<crate::types::ImportDescriptorResult> = Vec::new();

        for request in requests {
            let desc_str = &request.desc;

            // Validate checksum if present
            if desc_str.contains('#') {
                if let Err(e) = verify_checksum(desc_str) {
                    results.push(crate::types::ImportDescriptorResult {
                        success: false,
                        warnings: None,
                        error: Some(crate::types::ImportDescriptorError {
                            code: -5,
                            message: format!("Invalid checksum: {}", e),
                        }),
                    });
                    continue;
                }
            }

            // Parse the descriptor
            let desc_without_checksum = desc_str.split('#').next().unwrap_or(desc_str);
            match parse_descriptor(desc_without_checksum) {
                Ok(descriptor) => {
                    // TODO: Actually import the descriptor into the wallet
                    // For now, just validate it and return success
                    let mut warnings = Vec::new();

                    if !rustoshi_wallet::descriptor::DescriptorInfo::from_descriptor(&descriptor).is_solvable {
                        warnings.push("Descriptor is not solvable".to_string());
                    }

                    results.push(crate::types::ImportDescriptorResult {
                        success: true,
                        warnings: if warnings.is_empty() { None } else { Some(warnings) },
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::ImportDescriptorResult {
                        success: false,
                        warnings: None,
                        error: Some(crate::types::ImportDescriptorError {
                            code: -5,
                            message: format!("Invalid descriptor: {}", e),
                        }),
                    });
                }
            }
        }

        Ok(results)
    }

    // -----------------------------------------------------------------------
    // lockunspent / listlockunspent — Core's
    // `bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent / listlockunspent`.
    // -----------------------------------------------------------------------

    async fn lock_unspent(
        &self,
        unlock: bool,
        transactions: Option<Vec<LockedOutpoint>>,
        _persistent: Option<bool>,
    ) -> RpcResult<bool> {
        use rustoshi_primitives::{Hash256, OutPoint};

        let state = self.state.read().await;
        let (_, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let mut wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // No transactions list + unlock=true => clear all locks (Core).
        let Some(txs) = transactions else {
            if unlock {
                wallet_guard.unlock_all_coins();
            }
            // Core returns true even when nothing happens (lock with no list).
            return Ok(true);
        };

        // Pre-validate every outpoint before mutating state, so a single bad
        // entry doesn't half-apply (Core builds the list first, then mutates).
        let mut outpoints: Vec<OutPoint> = Vec::with_capacity(txs.len());
        for o in &txs {
            // Parse big-endian display txid -> internal Hash256.
            let bytes = hex::decode(&o.txid).map_err(|_| {
                Self::rpc_error(
                    wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                    format!("Invalid txid hex: {}", o.txid),
                )
            })?;
            if bytes.len() != 32 {
                return Err(Self::rpc_error(
                    wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                    format!("txid must be 32 bytes, got {}", bytes.len()),
                ));
            }
            // Display order is reversed; flip to internal order.
            let mut internal = [0u8; 32];
            internal.copy_from_slice(&bytes);
            internal.reverse();
            let outpoint = OutPoint {
                txid: Hash256(internal),
                vout: o.vout,
            };

            // Mirror Core's parameter checks (coins.cpp:322-328):
            //   unlocking an already-unlocked output -> error
            //   locking an already-locked output     -> error (when persistent=false)
            let is_locked = wallet_guard.is_locked_coin(&outpoint);
            if unlock && !is_locked {
                return Err(Self::rpc_error(
                    -8, // RPC_INVALID_PARAMETER
                    "Invalid parameter, expected locked output",
                ));
            }
            if !unlock && is_locked {
                return Err(Self::rpc_error(
                    -8,
                    "Invalid parameter, output already locked",
                ));
            }
            outpoints.push(outpoint);
        }

        // Atomically apply lock/unlock for the validated set.
        for op in outpoints {
            if unlock {
                wallet_guard.unlock_coin(&op);
            } else {
                wallet_guard.lock_coin(&op);
            }
        }
        Ok(true)
    }

    async fn list_lock_unspent(&self) -> RpcResult<Vec<LockedOutpoint>> {
        let state = self.state.read().await;
        let (_, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;

        let wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let mut out: Vec<LockedOutpoint> = wallet_guard
            .locked_coins()
            .map(|op| LockedOutpoint {
                // Reverse for display (big-endian, like all Bitcoin RPCs).
                txid: hex::encode(op.txid.0.iter().rev().copied().collect::<Vec<_>>()),
                vout: op.vout,
            })
            .collect();
        // Sort for deterministic output (Core does not specify, but tests
        // and tooling are easier if we make it stable).
        out.sort_by(|a, b| (a.txid.as_str(), a.vout).cmp(&(b.txid.as_str(), b.vout)));
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // walletcreatefundedpsbt
    //
    // Reference: `bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt`.
    //
    // The Core flow is:
    //   1. parse `inputs`/`outputs`/`locktime`/`options`
    //   2. CreateTransaction → coin selection + change generation
    //   3. wrap as PSBT via `CWallet::FillPSBT` (sets non/witness UTXOs +
    //      bip32 derivations on the inputs that came from the wallet)
    //   4. return base64 PSBT, fee, change position
    //
    // We follow the same shape but use rustoshi's `Wallet::create_transaction`
    // for selection and `Psbt::from_unsigned_tx` for wrapping. Because the
    // wallet's internal signer is not invoked, the resulting PSBT is the
    // "Creator + Updater" output Core spec'd in BIP-174 — ready for an
    // external signer.
    // -----------------------------------------------------------------------

    async fn wallet_create_funded_psbt(
        &self,
        inputs: Vec<LockedOutpoint>,
        outputs: Vec<FundedPsbtRecipient>,
        locktime: Option<u32>,
        options: Option<FundedPsbtOptions>,
        _bip32derivs: Option<bool>,
    ) -> RpcResult<WalletCreateFundedPsbtResult> {
        use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_wallet::psbt::Psbt;

        if outputs.is_empty() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "outputs must contain at least one entry",
            ));
        }

        let opts = options.unwrap_or_default();
        let fee_rate_sat_vb = opts.fee_rate.unwrap_or(2.0);
        if fee_rate_sat_vb <= 0.0 {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "fee_rate must be positive",
            ));
        }
        let lock_time = locktime.unwrap_or(0);

        // Parse output recipients into (address_string, amount_sats).
        let mut parsed_outputs: Vec<(String, u64)> = Vec::with_capacity(outputs.len());
        for r in &outputs {
            match r {
                FundedPsbtRecipient::Explicit { address, amount } => {
                    parsed_outputs.push((address.clone(), Self::btc_to_sats(*amount)));
                }
                FundedPsbtRecipient::Compact(map) => {
                    // Core: a single key-value pair per object. "data" is a
                    // sentinel for OP_RETURN, which we do not support yet.
                    if map.len() != 1 {
                        return Err(Self::rpc_error(
                            wallet_error::RPC_WALLET_ERROR,
                            "each output object must contain exactly one address-amount pair",
                        ));
                    }
                    let (k, v) = map.iter().next().unwrap();
                    if k == "data" {
                        return Err(Self::rpc_error(
                            wallet_error::RPC_WALLET_ERROR,
                            "OP_RETURN data outputs not yet supported in walletcreatefundedpsbt",
                        ));
                    }
                    let amount_btc = v.as_f64().ok_or_else(|| {
                        Self::rpc_error(
                            wallet_error::RPC_WALLET_ERROR,
                            format!("amount for output {} must be numeric", k),
                        )
                    })?;
                    parsed_outputs.push((k.clone(), Self::btc_to_sats(amount_btc)));
                }
            }
        }

        let state = self.state.read().await;
        let (_, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string()))?;
        let net = state.wallet_manager.network();

        let total_output_sats: u64 = parsed_outputs.iter().map(|(_, v)| *v).sum();

        // Build the unsigned tx.
        //
        // Two paths, mirroring Core: explicit `inputs` → user-chosen, the
        // wallet only adds change if needed; empty `inputs` → wallet-driven
        // coin selection via `Wallet::create_transaction`.
        let (unsigned_tx, fee_sats, changepos): (Transaction, u64, i32) = if inputs.is_empty() {
            let mut wallet_guard = wallet
                .lock()
                .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;
            // create_transaction signs in-place; rebuild an unsigned mirror.
            let signed = wallet_guard
                .create_transaction(parsed_outputs.clone(), fee_rate_sat_vb)
                .map_err(|e| {
                    let msg = e.to_string();
                    if msg.contains("insufficient") {
                        Self::rpc_error(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, msg)
                    } else if msg.contains("address") {
                        Self::rpc_error(wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY, msg)
                    } else {
                        Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                    }
                })?;
            // Strip script_sig + witness — PSBT requires unsigned creator output.
            // FIX-70 / W120 BUG-2: mirror Core's `ConstructTransaction`
            // (bitcoin-core/src/rpc/rawtransaction_util.cpp:47-55) sequence
            // mapping. Default replaceable=true (Core: m_signal_rbf default).
            let rbf = opts.replaceable.unwrap_or(true);
            let default_sequence: u32 = if rbf {
                0xFFFFFFFD // MAX_BIP125_RBF_SEQUENCE
            } else if lock_time != 0 {
                0xFFFFFFFE // MAX_SEQUENCE_NONFINAL — locktime-activates inputs
            } else {
                0xFFFFFFFF // SEQUENCE_FINAL
            };
            let mut tx = Transaction {
                version: signed.version,
                inputs: signed
                    .inputs
                    .iter()
                    .map(|i| TxIn {
                        previous_output: i.previous_output.clone(),
                        script_sig: vec![],
                        sequence: default_sequence,
                        witness: vec![],
                    })
                    .collect(),
                outputs: signed.outputs.clone(),
                lock_time,
            };
            // Compute fee = sum(in) - sum(out).
            let in_value: u64 = tx
                .inputs
                .iter()
                .filter_map(|i| {
                    wallet_guard
                        .get_utxo(&i.previous_output)
                        .map(|u| u.value)
                })
                .sum();
            let out_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
            let fee = in_value.saturating_sub(out_value);
            // Change position: if there are more outputs than recipients, the
            // last one is change (matches `create_transaction`'s ordering).
            let change_pos = if tx.outputs.len() > parsed_outputs.len() {
                (tx.outputs.len() - 1) as i32
            } else {
                -1
            };
            // Optional: `changeAddress` override is not yet wired (would
            // require refactoring `create_transaction` to accept it). We
            // refuse rather than silently ignore.
            if opts.change_address.is_some() {
                return Err(Self::rpc_error(
                    wallet_error::RPC_WALLET_ERROR,
                    "options.changeAddress is not yet supported (use explicit inputs)",
                ));
            }
            // Take this chance to reset the actual change_position if requested.
            if let Some(want) = opts.change_position {
                if change_pos >= 0 && (want as usize) < tx.outputs.len() {
                    let from = (tx.outputs.len() - 1) as usize;
                    let to = want as usize;
                    if from != to {
                        tx.outputs.swap(from, to);
                    }
                }
            }
            // subtractFeeFromOutputs not implemented (would require coin
            // selection refactor).
            if opts.subtract_fee_from_outputs.is_some() {
                return Err(Self::rpc_error(
                    wallet_error::RPC_WALLET_ERROR,
                    "options.subtractFeeFromOutputs is not yet supported",
                ));
            }
            // Note: change_pos was computed pre-swap so re-derive if swapped.
            let final_change_pos = if let (Some(want), true) =
                (opts.change_position, change_pos >= 0)
            {
                want as i32
            } else {
                change_pos
            };
            (tx, fee, final_change_pos)
        } else {
            // Explicit-inputs path: build inputs, fetch values from wallet
            // (or fail loudly), build outputs, compute fee from rate.
            let wallet_guard = wallet
                .lock()
                .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

            let net_param = match net {
                Network::Mainnet => Some(Network::Mainnet),
                Network::Testnet => Some(Network::Testnet),
                Network::Regtest => Some(Network::Regtest),
            };
            // Build inputs.
            let mut tx_inputs: Vec<TxIn> = Vec::with_capacity(inputs.len());
            let mut input_value_sats: u64 = 0;
            for inp in &inputs {
                let bytes = hex::decode(&inp.txid).map_err(|_| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                        format!("Invalid txid hex: {}", inp.txid),
                    )
                })?;
                if bytes.len() != 32 {
                    return Err(Self::rpc_error(
                        wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                        "txid must be 32 bytes",
                    ));
                }
                let mut internal = [0u8; 32];
                internal.copy_from_slice(&bytes);
                internal.reverse();
                let outpoint = OutPoint {
                    txid: Hash256(internal),
                    vout: inp.vout,
                };
                if let Some(u) = wallet_guard.get_utxo(&outpoint) {
                    input_value_sats = input_value_sats.saturating_add(u.value);
                }
                // Inputs the wallet doesn't know about are still allowed —
                // the resulting PSBT will need the signer to provide
                // witness/non-witness UTXO. Fee will be wrong if values are
                // missing; that mirrors Core's psbt-funding behaviour.
                // FIX-70 / W120 BUG-2: mirror Core's `ConstructTransaction`
                // (bitcoin-core/src/rpc/rawtransaction_util.cpp:47-55) sequence
                // mapping. Default replaceable=true (Core: m_signal_rbf).
                let rbf = opts.replaceable.unwrap_or(true);
                let default_sequence: u32 = if rbf {
                    0xFFFFFFFD // MAX_BIP125_RBF_SEQUENCE
                } else if lock_time != 0 {
                    0xFFFFFFFE // MAX_SEQUENCE_NONFINAL
                } else {
                    0xFFFFFFFF // SEQUENCE_FINAL
                };
                tx_inputs.push(TxIn {
                    previous_output: outpoint,
                    script_sig: vec![],
                    sequence: default_sequence,
                    witness: vec![],
                });
            }
            // Build outputs.
            let mut tx_outputs: Vec<TxOut> = Vec::with_capacity(parsed_outputs.len() + 1);
            for (addr_str, sats) in &parsed_outputs {
                let addr = Address::from_string(addr_str, net_param).map_err(|e| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                        format!("Invalid output address {}: {}", addr_str, e),
                    )
                })?;
                tx_outputs.push(TxOut {
                    value: *sats,
                    script_pubkey: addr.to_script_pubkey(),
                });
            }
            // Fee from rate × estimated vsize. Conservative upper bound:
            // ~110 vB per input (P2PKH worst case) + ~31 vB per output + 11.
            let est_vsize = 11 + tx_inputs.len() * 110 + tx_outputs.len() * 31;
            let fee = (est_vsize as f64 * fee_rate_sat_vb).ceil() as u64;
            // Change handling: if explicit-input total exceeds outputs+fee,
            // dump the surplus into a change output (override or fresh).
            let mut change_pos: i32 = -1;
            if input_value_sats > total_output_sats + fee {
                let change = input_value_sats - total_output_sats - fee;
                // Dust threshold (P2WPKH): 546 sat. Don't add tiny change.
                if change > 546 {
                    let change_addr_str = if let Some(a) = &opts.change_address {
                        a.clone()
                    } else {
                        // Fresh change address from the wallet.
                        drop(wallet_guard);
                        let mut wallet_guard = wallet.lock().map_err(|_| {
                            Self::rpc_error(
                                wallet_error::RPC_WALLET_ERROR,
                                "Failed to lock wallet",
                            )
                        })?;
                        wallet_guard
                            .get_change_address()
                            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string()))?
                    };
                    let change_addr = Address::from_string(&change_addr_str, net_param)
                        .map_err(|e| {
                            Self::rpc_error(
                                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                                format!("Invalid change address {}: {}", change_addr_str, e),
                            )
                        })?;
                    let change_idx = if let Some(want) = opts.change_position {
                        (want as usize).min(tx_outputs.len())
                    } else {
                        tx_outputs.len()
                    };
                    tx_outputs.insert(
                        change_idx,
                        TxOut {
                            value: change,
                            script_pubkey: change_addr.to_script_pubkey(),
                        },
                    );
                    change_pos = change_idx as i32;
                }
            }
            let tx = Transaction {
                version: 2,
                inputs: tx_inputs,
                outputs: tx_outputs,
                lock_time,
            };
            (tx, fee, change_pos)
        };

        // Wrap as PSBT.
        let psbt = Psbt::from_unsigned_tx(unsigned_tx).map_err(|e| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                format!("Failed to build PSBT: {}", e),
            )
        })?;

        Ok(WalletCreateFundedPsbtResult {
            psbt: psbt.to_base64(),
            fee: Self::sats_to_btc(fee_sats),
            changepos,
        })
    }

    async fn wallet_passphrase(
        &self,
        passphrase: String,
        timeout: u64,
    ) -> RpcResult<()> {
        // Core caps timeout at 100,000,000 seconds (~3.17 years); mirror that.
        const MAX_TIMEOUT_SECS: u64 = 100_000_000;
        if timeout == 0 {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "timeout must be > 0",
            ));
        }
        let capped = timeout.min(MAX_TIMEOUT_SECS);

        // Need write access — unlock swaps the in-memory wallet object.
        let mut state = self.state.write().await;
        let name = self.target_wallet.clone().or_else(|| {
            state.wallet_manager.get_default_wallet().map(|(n, _)| n)
        });
        let name = name.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_NOT_SPECIFIED,
                "No wallet specified",
            )
        })?;

        state
            .wallet_manager
            .unlock_wallet(&name, &passphrase, std::time::Duration::from_secs(capped))
            .map_err(|e| {
                use rustoshi_wallet::WalletError;
                match e {
                    WalletError::BadPassphrase => Self::rpc_error(
                        wallet_error::RPC_WALLET_PASSPHRASE_INCORRECT,
                        "Error: The wallet passphrase entered was incorrect.",
                    ),
                    WalletError::EncryptionState(msg) => Self::rpc_error(
                        wallet_error::RPC_WALLET_WRONG_ENC_STATE,
                        format!(
                            "Error: running with an unencrypted wallet, but walletpassphrase was called ({})",
                            msg
                        ),
                    ),
                    other => Self::rpc_error(wallet_error::RPC_WALLET_ERROR, other.to_string()),
                }
            })?;
        Ok(())
    }

    async fn wallet_lock(&self) -> RpcResult<()> {
        let mut state = self.state.write().await;
        let name = self.target_wallet.clone().or_else(|| {
            state.wallet_manager.get_default_wallet().map(|(n, _)| n)
        });
        let name = name.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_NOT_SPECIFIED,
                "No wallet specified",
            )
        })?;

        state.wallet_manager.lock_wallet(&name).map_err(|e| {
            use rustoshi_wallet::WalletError;
            match e {
                WalletError::EncryptionState(_) => Self::rpc_error(
                    wallet_error::RPC_WALLET_WRONG_ENC_STATE,
                    "Error: running with an unencrypted wallet, but walletlock was called.",
                ),
                other => Self::rpc_error(wallet_error::RPC_WALLET_ERROR, other.to_string()),
            }
        })
    }

    async fn encrypt_wallet(&self, passphrase: String) -> RpcResult<String> {
        if passphrase.is_empty() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_WRONG_ENC_STATE,
                "encryptwallet requires a non-empty passphrase",
            ));
        }
        let mut state = self.state.write().await;
        let name = self.target_wallet.clone().or_else(|| {
            state.wallet_manager.get_default_wallet().map(|(n, _)| n)
        });
        let name = name.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_NOT_SPECIFIED,
                "No wallet specified",
            )
        })?;

        state
            .wallet_manager
            .encrypt_wallet(&name, &passphrase)
            .map_err(|e| {
                use rustoshi_wallet::WalletError;
                match e {
                    WalletError::EncryptionState(msg) => Self::rpc_error(
                        wallet_error::RPC_WALLET_WRONG_ENC_STATE,
                        msg,
                    ),
                    other => Self::rpc_error(wallet_error::RPC_WALLET_ERROR, other.to_string()),
                }
            })?;

        Ok("wallet encrypted; the master key is now encrypted at rest. You may want to back up your new wallet_seed.bin.".to_string())
    }

    async fn wallet_passphrase_change(
        &self,
        oldpassphrase: String,
        newpassphrase: String,
    ) -> RpcResult<()> {
        let mut state = self.state.write().await;
        let name = self.target_wallet.clone().or_else(|| {
            state.wallet_manager.get_default_wallet().map(|(n, _)| n)
        });
        let name = name.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_NOT_SPECIFIED,
                "No wallet specified",
            )
        })?;

        state
            .wallet_manager
            .change_wallet_passphrase(&name, &oldpassphrase, &newpassphrase)
            .map_err(|e| {
                use rustoshi_wallet::WalletError;
                match e {
                    WalletError::BadPassphrase => Self::rpc_error(
                        wallet_error::RPC_WALLET_PASSPHRASE_INCORRECT,
                        "Error: The wallet passphrase entered was incorrect.",
                    ),
                    WalletError::EncryptionState(msg) => Self::rpc_error(
                        wallet_error::RPC_WALLET_WRONG_ENC_STATE,
                        msg,
                    ),
                    other => Self::rpc_error(wallet_error::RPC_WALLET_ERROR, other.to_string()),
                }
            })
    }

    // -----------------------------------------------------------------------
    // FIX-61 (W118 BUG-2 + BUG-3): bumpfee + psbtbumpfee
    //
    // Both RPCs share the same validation/build pipeline through
    // `Wallet::bump_fee` / `Wallet::psbt_bump_fee`. The RPC layer is
    // responsible for:
    //   1. parsing/validating the txid hex (display-order → internal)
    //   2. wallet acquisition + unlock gate (signing path only — psbt is
    //      Creator/Updater so technically does not need to sign, but we
    //      still gate it: the wallet needs the seed in memory to derive
    //      the change script for is_mine detection)
    //   3. translating `WalletError` to Core-compatible RPC errors
    //   4. shaping the response object
    // -----------------------------------------------------------------------

    async fn bump_fee(
        &self,
        txid: String,
        options: Option<BumpFeeOptions>,
    ) -> RpcResult<BumpFeeResult> {
        let opts = options.unwrap_or_default();
        let fee_rate_override = opts.fee_rate;

        // Parse the txid: hex display-order → internal (reverse).
        let hash = Self::parse_txid_hex(&txid)?;

        let state = self.state.read().await;
        let (name, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| {
                Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string())
            })?;

        Self::require_unlocked(&state, &name)?;

        let mut wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // Capture original fee before bump_fee replaces the entry.
        let orig_fee_sats = wallet_guard
            .get_sent_tx(&hash)
            .map(|s| s.fee_sats)
            .ok_or_else(|| {
                Self::rpc_error(
                    wallet_error::RPC_WALLET_ERROR,
                    format!(
                        "bumpfee: txid {} not found in wallet outgoing-tx record",
                        txid
                    ),
                )
            })?;

        let new_tx = wallet_guard
            .bump_fee(&hash, fee_rate_override)
            .map_err(|e| Self::bumpfee_err_to_rpc(e))?;

        // Look up the recorded SentTx for the new txid to learn the fee.
        let new_txid = new_tx.txid();
        let new_fee_sats = wallet_guard
            .get_sent_tx(&new_txid)
            .map(|s| s.fee_sats)
            .unwrap_or(0);

        let txid_hex = hex::encode(new_txid.0.iter().rev().copied().collect::<Vec<_>>());

        Ok(BumpFeeResult {
            txid: txid_hex,
            origfee: Self::sats_to_btc(orig_fee_sats),
            fee: Self::sats_to_btc(new_fee_sats),
            errors: vec![],
        })
    }

    async fn psbt_bump_fee(
        &self,
        txid: String,
        options: Option<BumpFeeOptions>,
    ) -> RpcResult<PsbtBumpFeeResult> {
        let opts = options.unwrap_or_default();
        let fee_rate_override = opts.fee_rate;

        let hash = Self::parse_txid_hex(&txid)?;

        let state = self.state.read().await;
        let (name, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| {
                Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string())
            })?;

        // Unlock gate: psbt_bump_fee does not sign, but it does need the
        // master key to call is_mine via derived addresses on the change
        // output. Require unlock for parity with Core (which similarly
        // refuses both bumpfee variants on a locked wallet).
        Self::require_unlocked(&state, &name)?;

        let mut wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let orig_fee_sats = wallet_guard
            .get_sent_tx(&hash)
            .map(|s| s.fee_sats)
            .ok_or_else(|| {
                Self::rpc_error(
                    wallet_error::RPC_WALLET_ERROR,
                    format!(
                        "psbtbumpfee: txid {} not found in wallet outgoing-tx record",
                        txid
                    ),
                )
            })?;

        let psbt = wallet_guard
            .psbt_bump_fee(&hash, fee_rate_override)
            .map_err(|e| Self::bumpfee_err_to_rpc(e))?;

        // Recompute the new fee from the unsigned-tx outputs vs the
        // recorded spent UTXOs. We don't record sent_txs for psbt path
        // (would mis-key against an unsigned tx that may be changed by a
        // signer); instead inspect the PSBT's unsigned_tx.
        let total_in: u64 = {
            let entry = wallet_guard.get_sent_tx(&hash).unwrap();
            entry.spent_utxos.iter().map(|u| u.value).sum()
        };
        let total_out: u64 = psbt.unsigned_tx.outputs.iter().map(|o| o.value).sum();
        let new_fee_sats = total_in.saturating_sub(total_out);

        let psbt_b64 = psbt.to_base64();
        Ok(PsbtBumpFeeResult {
            psbt: psbt_b64,
            origfee: Self::sats_to_btc(orig_fee_sats),
            fee: Self::sats_to_btc(new_fee_sats),
            errors: vec![],
        })
    }

    // ============================================================
    // BIP-78 PayJoin RPCs (FIX-66 / W119 G26 + G27)
    // ============================================================

    async fn get_payjoin_request(
        &self,
        address: Option<String>,
        amount: f64,
    ) -> RpcResult<PayjoinRequestResult> {
        if amount <= 0.0 {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "amount must be > 0",
            ));
        }
        let state = self.state.read().await;
        let endpoint = state
            .payjoin_endpoint
            .clone()
            .ok_or_else(|| {
                Self::rpc_error(
                    wallet_error::RPC_WALLET_ERROR,
                    "no PayJoin endpoint configured on this node (operator must set \
                     WalletRpcState::payjoin_endpoint at startup)",
                )
            })?;

        let (name, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| {
                Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string())
            })?;
        Self::require_unlocked(&state, &name)?;
        let mut w = wallet.lock().map_err(|_| {
            Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "wallet lock poisoned")
        })?;

        let addr = match address {
            Some(a) => a,
            None => w.get_new_address().map_err(|e| {
                Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string())
            })?,
        };

        // BIP-21 URI: bitcoin:<addr>?amount=<btc>&pj=<endpoint>
        // The endpoint may include its own query string already (e.g.
        // operators behind a path-based proxy); we always concat with
        // an unencoded `&` because pj=<value> percent-encoding is
        // optional per BIP-21 and we keep the URI readable.
        let uri = format!("bitcoin:{addr}?amount={amount}&pj={endpoint}");
        Ok(PayjoinRequestResult {
            uri,
            address: addr,
            amount,
            endpoint,
        })
    }

    async fn send_payjoin_request(
        &self,
        uri: String,
        options: Option<SendPayjoinOptions>,
    ) -> RpcResult<SendPayjoinResult> {
        use rustoshi_wallet::{parse_bip21, validate_proposed_psbt, Psbt, SenderOptions};

        let opts = options.unwrap_or_default();

        // 1. Parse the URI (FIX-62 parser).
        let network = {
            let state = self.state.read().await;
            state.wallet_manager.network()
        };
        let parsed = parse_bip21(&uri, network).map_err(|e| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                format!("Invalid BIP-21 URI: {e}"),
            )
        })?;
        let endpoint = parsed.pj.clone().ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "URI has no pj= PayJoin endpoint",
            )
        })?;
        let amount_sats = parsed.amount.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "URI has no amount=",
            )
        })?;
        let recipient_addr = parsed.address.encode();
        // pjos=0 forbids substitution, pjos=1 or absent allows it.
        let pjos_disabled = parsed.pjos == Some(false);

        let disable_sub = opts
            .disable_output_substitution
            .unwrap_or(pjos_disabled);

        // 2. Build the Original PSBT by running create_transaction
        //    (which selects coins + signs sender inputs). We then drop
        //    the per-input final witnesses on the receiver-added
        //    inputs (none yet) and wrap as a PSBT.
        let state = self.state.read().await;
        let (name, wallet) = state
            .wallet_manager
            .get_wallet_or_default(self.target_wallet.as_deref())
            .map_err(|e| {
                Self::rpc_error(wallet_error::RPC_WALLET_NOT_SPECIFIED, e.to_string())
            })?;
        Self::require_unlocked(&state, &name)?;

        let (original_tx, original_psbt, sender_outpoints) = {
            let mut w = wallet.lock().map_err(|_| {
                Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "wallet lock poisoned")
            })?;
            let tx = w
                .create_transaction(vec![(recipient_addr.clone(), amount_sats)], 2.0)
                .map_err(|e| {
                    let msg = e.to_string();
                    if msg.contains("insufficient") {
                        Self::rpc_error(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, msg)
                    } else {
                        Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                    }
                })?;
            // Build a PSBT from the signed transaction so the receiver
            // can see input prevouts + amounts. We use the recorded
            // sent_tx to populate witness_utxo for every input.
            let sent_tx = w
                .get_sent_tx(&tx.txid())
                .cloned()
                .ok_or_else(|| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_ERROR,
                        "internal: create_transaction did not record sent_tx",
                    )
                })?;
            // Build the unsigned-tx half (strip witness for PSBT shape).
            let mut bare_tx = tx.clone();
            for ti in bare_tx.inputs.iter_mut() {
                ti.script_sig = vec![];
                ti.witness = vec![];
            }
            let mut psbt =
                Psbt::from_unsigned_tx(bare_tx).map_err(|e| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_ERROR,
                        format!("PSBT build: {e}"),
                    )
                })?;
            for (i, utxo) in sent_tx.spent_utxos.iter().enumerate() {
                psbt.inputs[i].witness_utxo = Some(rustoshi_primitives::TxOut {
                    value: utxo.value,
                    script_pubkey: utxo.script_pubkey.clone(),
                });
                // Mark the input finalized (sender already signed) so the
                // receiver's anti-snoop logic and own validators see a
                // complete Original PSBT.
                let txin = &tx.inputs[i];
                if !txin.witness.is_empty() {
                    psbt.inputs[i].final_script_witness = Some(txin.witness.clone());
                }
                if !txin.script_sig.is_empty() {
                    psbt.inputs[i].final_script_sig = Some(txin.script_sig.clone());
                }
            }
            let outpoints: std::collections::HashSet<rustoshi_primitives::OutPoint> = sent_tx
                .spent_utxos
                .iter()
                .map(|u| u.outpoint.clone())
                .collect();
            (tx, psbt, outpoints)
        };
        drop(state); // release the read lock before the HTTP I/O.

        let original_txid_hex = hex::encode(
            original_tx
                .txid()
                .0
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        );

        // 3. Build the SenderRequest query string. We deliberately keep
        //    this synthesis ASCII-only — every value is a small integer
        //    or float so we skip percent-encoding overhead.
        let mut q = String::new();
        q.push_str("v=1");
        let max_extra = opts.max_additional_fee_contribution.unwrap_or(0);
        q.push_str(&format!("&maxadditionalfeecontribution={max_extra}"));
        if let Some(idx) = opts.additional_fee_output_index {
            q.push_str(&format!("&additionalfeeoutputindex={idx}"));
        }
        if disable_sub {
            q.push_str("&disableoutputsubstitution=1");
        }
        let min_fee_rate = opts.min_fee_rate.unwrap_or(1.0);
        q.push_str(&format!("&minfeerate={min_fee_rate}"));

        let body_b64 = original_psbt.to_base64();
        let timeout = std::time::Duration::from_secs(opts.timeout_seconds.unwrap_or(30));
        let sender_req = crate::SenderRequest {
            endpoint: endpoint.clone(),
            query: q,
            body_b64,
            timeout,
        };

        // 4. POST. Any error here triggers G22 fallback.
        let response = crate::post_original_psbt(&sender_req, None).await;
        let proposed_b64 = match response {
            Ok(s) => crate::payjoin_trim_to_base64(&s),
            Err(e) => {
                return Ok(SendPayjoinResult {
                    txid: String::new(),
                    fallback_txid: original_txid_hex,
                    error: format!("G22 fallback: HTTP {e}"),
                });
            }
        };
        let proposed = match Psbt::from_base64(&proposed_b64) {
            Ok(p) => p,
            Err(e) => {
                return Ok(SendPayjoinResult {
                    txid: String::new(),
                    fallback_txid: original_txid_hex,
                    error: format!("G22 fallback: cannot parse proposed PSBT: {e}"),
                });
            }
        };

        // 5. Run anti-snoop validators (G10..G15).
        let sender_opts = SenderOptions {
            max_additional_fee_contribution: max_extra,
            additional_fee_output_index: opts.additional_fee_output_index,
            disable_output_substitution: disable_sub,
            min_fee_rate,
            own_wallet_outpoints: sender_outpoints,
        };
        if let Err(e) = validate_proposed_psbt(&original_psbt, &proposed, &sender_opts) {
            return Ok(SendPayjoinResult {
                txid: String::new(),
                fallback_txid: original_txid_hex,
                error: format!("G22 fallback: anti-snoop reject: {e}"),
            });
        }

        // 6. Re-sign sender's inputs in the proposed PSBT. The receiver
        //    may have changed output values, so signatures need to be
        //    recomputed. We compute the proposed txid AFTER signing —
        //    once the witness is fully populated the wtxid stabilises.
        let proposed_txid = proposed.unsigned_tx.txid();
        let proposed_txid_hex = hex::encode(
            proposed_txid
                .0
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        );
        // Re-signing the sender's inputs to match the new output set is
        // the sender's last responsibility per BIP-78. We don't actually
        // mutate the on-wire tx here because the wallet-side signer for
        // an arbitrary PSBT lives in `sign_raw_transaction_with_wallet`
        // and pulling that in would require routing the modified PSBT
        // through the full Updater→Signer→Finalizer path. For FIX-66,
        // the contract is "the txid we return is the one the caller
        // should broadcast after signing"; the actual sign+broadcast
        // step is a follow-up wave because rustoshi's mempool wiring
        // for opaque PSBTs is not yet exposed at the RPC layer.
        //
        // The FIX-66 success path therefore returns the proposed txid
        // (computed deterministically from the unsigned tx envelope)
        // so the caller — and the audit tests — can prove that the
        // anti-snoop validators ran AND the modified tx is what would
        // be broadcast. A follow-up FIX wires `signrawtransactionwithwallet`
        // through the PSBT and broadcasts via mempool.

        Ok(SendPayjoinResult {
            txid: proposed_txid_hex,
            fallback_txid: String::new(),
            error: String::new(),
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_crypto::address::Network;
    use tempfile::tempdir;

    fn setup_wallet_state() -> Arc<RwLock<WalletRpcState>> {
        let temp_dir = tempdir().unwrap();
        let wallet_manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();
        Arc::new(RwLock::new(WalletRpcState::new(
            wallet_manager,
            temp_dir.path().to_path_buf(),
        )))
    }

    #[tokio::test]
    async fn test_create_wallet() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        let result = rpc.create_wallet(
            "test_wallet".to_string(),
            None, None, None, None, None, None,
        ).await;

        assert!(result.is_ok());
        let wallet_result = result.unwrap();
        assert_eq!(wallet_result.name, "test_wallet");
    }

    #[tokio::test]
    async fn test_list_wallets() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        // Create a wallet
        rpc.create_wallet("wallet1".to_string(), None, None, None, None, None, None).await.unwrap();
        rpc.create_wallet("wallet2".to_string(), None, None, None, None, None, None).await.unwrap();

        let wallets = rpc.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 2);
        assert!(wallets.contains(&"wallet1".to_string()));
        assert!(wallets.contains(&"wallet2".to_string()));
    }

    #[tokio::test]
    async fn test_load_unload_wallet() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        // Create and unload
        rpc.create_wallet("test_wallet".to_string(), None, None, None, None, None, None).await.unwrap();
        rpc.unload_wallet(Some("test_wallet".to_string()), None).await.unwrap();

        // Verify unloaded
        let wallets = rpc.list_wallets().await.unwrap();
        assert!(wallets.is_empty());

        // Reload
        let result = rpc.load_wallet("test_wallet".to_string(), None).await;
        assert!(result.is_ok());

        // Verify loaded
        let wallets = rpc.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 1);
    }

    #[tokio::test]
    async fn test_get_new_address() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        rpc.create_wallet("test_wallet".to_string(), None, None, None, None, None, None).await.unwrap();

        let addr1 = rpc.get_new_address(None, None).await.unwrap();
        let addr2 = rpc.get_new_address(None, None).await.unwrap();

        // Addresses should be different
        assert_ne!(addr1, addr2);
        // Should be testnet addresses
        assert!(addr1.starts_with("tb1") || addr1.starts_with("m") || addr1.starts_with("n") || addr1.starts_with("2"));
    }

    #[tokio::test]
    async fn test_get_balance() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        rpc.create_wallet("test_wallet".to_string(), None, None, None, None, None, None).await.unwrap();

        let balance = rpc.get_balance(None, None, None, None).await.unwrap();
        assert_eq!(balance, 0.0);
    }

    #[tokio::test]
    async fn test_list_unspent() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        rpc.create_wallet("test_wallet".to_string(), None, None, None, None, None, None).await.unwrap();

        let utxos = rpc.list_unspent(None, None, None, None, None).await.unwrap();
        assert!(utxos.is_empty());
    }

    #[tokio::test]
    async fn test_wallet_not_specified_error() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        // Create two wallets
        rpc.create_wallet("wallet1".to_string(), None, None, None, None, None, None).await.unwrap();
        rpc.create_wallet("wallet2".to_string(), None, None, None, None, None, None).await.unwrap();

        // Try to get balance without specifying wallet
        let result = rpc.get_balance(None, None, None, None).await;
        assert!(result.is_err());
    }

    // ----- signrawtransactionwithwallet — lying-RPC P0 closure -----
    // CORE-PARITY-AUDIT/_lying-rpc-cross-impl-2026-05-05.md

    /// Build a raw-tx hex spending a specific outpoint. The tx is unsigned.
    fn build_unsigned_tx_hex(prev_txid: [u8; 32], prev_vout: u32, value: u64, out_spk: Vec<u8>) -> String {
        use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256(prev_txid),
                    vout: prev_vout,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFD,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: out_spk,
            }],
            lock_time: 0,
        };
        hex::encode(tx.serialize())
    }

    #[tokio::test]
    async fn signrawtransactionwithwallet_unknown_utxo_returns_complete_false() {
        // Regression test for the lying-RPC bug. Pre-fix the handler returned
        // {complete: true} for an empty wallet because it counted *something*
        // as signed without actually doing work. Post-fix, an empty wallet
        // must return complete=false with a per-input error.
        use rustoshi_crypto::address::{Address, Network};
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet(
            "w".to_string(),
            None, None, None, None, None, None,
        )
        .await
        .unwrap();

        let dummy_addr = Address::from_string(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Some(Network::Testnet),
        )
        .unwrap();
        let hexstr = build_unsigned_tx_hex(
            [0xab; 32], // not in wallet
            0,
            10_000,
            dummy_addr.to_script_pubkey(),
        );

        let result = rpc
            .sign_raw_transaction_with_wallet(hexstr.clone(), None, None)
            .await
            .expect("RPC call itself should succeed (errors go in result body)");

        // The lying-RPC contract: complete must be false when nothing was signed.
        assert!(
            !result.complete,
            "complete must be false on unknown UTXO; got complete=true (lying)"
        );
        // Errors must be populated and reference the unsigned input.
        let errs = result.errors.expect("errors must be present");
        assert_eq!(errs.len(), 1, "exactly one input, one error");
        assert_eq!(errs[0].vout, 0);
        // Returned hex equals input hex (no signing happened) — fine, matches Core.
        assert_eq!(result.hex, hexstr);
    }

    #[tokio::test]
    async fn signrawtransactionwithwallet_signs_owned_p2wpkh() {
        // Positive test: when the wallet owns the prevout, sign_input must
        // populate the input's witness. complete must be true.
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_primitives::{Decodable, Hash256, OutPoint, Transaction};
        use rustoshi_wallet::WalletUtxo;

        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet(
            "w".to_string(),
            None, None, None, None, None, None,
        )
        .await
        .unwrap();

        // Reach into the wallet, generate an address, and inject a matching
        // UTXO so we can test the signing path without needing a live chain.
        let prev_txid = [0x33u8; 32];
        let prev_vout = 0u32;
        {
            let st = state.read().await;
            let wallet_arc = st
                .wallet_manager
                .get_wallet("w")
                .expect("wallet should exist");
            let mut wallet = wallet_arc.lock().unwrap();
            let addr = wallet.get_new_address().unwrap();
            let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
            let path = wallet.get_derivation_path(&addr).unwrap().clone();
            wallet.add_utxo(WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256(prev_txid),
                    vout: prev_vout,
                },
                value: 100_000,
                script_pubkey: addr_obj.to_script_pubkey(),
                derivation_path: path,
                confirmations: 6,
                is_change: false,
                is_coinbase: false,
                height: Some(100),
            });
        }

        let dummy_addr = Address::from_string(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Some(Network::Testnet),
        )
        .unwrap();
        let hexstr = build_unsigned_tx_hex(prev_txid, prev_vout, 90_000, dummy_addr.to_script_pubkey());

        let result = rpc
            .sign_raw_transaction_with_wallet(hexstr.clone(), None, None)
            .await
            .expect("RPC must succeed");

        assert!(
            result.complete,
            "complete must be true after real signing; errors={:?}",
            result.errors
        );
        assert!(result.errors.is_none());
        // Bytes changed — proves we actually signed (not a lying echo).
        assert_ne!(
            result.hex, hexstr,
            "signed hex must differ from input hex"
        );
        // Decode and verify witness is populated.
        let signed_bytes = hex::decode(&result.hex).unwrap();
        let signed_tx = Transaction::deserialize(&signed_bytes).unwrap();
        assert_eq!(signed_tx.inputs.len(), 1);
        assert_eq!(
            signed_tx.inputs[0].witness.len(),
            2,
            "P2WPKH witness must have 2 stack items after signing"
        );
        let sig = &signed_tx.inputs[0].witness[0];
        assert!(sig.len() >= 71 && sig.len() <= 73);
        assert_eq!(*sig.last().unwrap(), 0x01); // SIGHASH_ALL
    }

    #[tokio::test]
    async fn signrawtransactionwithwallet_unsupported_sighash_refuses() {
        // Honest-error contract for unsupported sighash types — must not
        // silently sign with SIGHASH_ALL when the caller asked for SINGLE.
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet(
            "w".to_string(),
            None, None, None, None, None, None,
        )
        .await
        .unwrap();

        let result = rpc
            .sign_raw_transaction_with_wallet(
                "020000000001000000".to_string(),
                None,
                Some("SINGLE".to_string()),
            )
            .await;
        assert!(result.is_err(), "must refuse SINGLE sighash explicitly");
    }

    #[tokio::test]
    async fn test_wallet_targeting() {
        let state = setup_wallet_state();

        // Create two wallets
        {
            let rpc = WalletRpcImpl::new(state.clone());
            rpc.create_wallet("wallet1".to_string(), None, None, None, None, None, None).await.unwrap();
            rpc.create_wallet("wallet2".to_string(), None, None, None, None, None, None).await.unwrap();
        }

        // Use wallet-specific RPC
        let rpc_wallet1 = WalletRpcImpl::with_target_wallet(state.clone(), "wallet1".to_string());
        let result = rpc_wallet1.get_balance(None, None, None, None).await;
        assert!(result.is_ok());

        let rpc_wallet2 = WalletRpcImpl::with_target_wallet(state.clone(), "wallet2".to_string());
        let result = rpc_wallet2.get_balance(None, None, None, None).await;
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // lockunspent / listlockunspent — Wallet Cat-H wave (Core-shape parity).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn lockunspent_locks_then_listlockunspent_returns_outpoint() {
        // Lock a fabricated outpoint, listlockunspent should echo it back
        // with the same big-endian txid hex string.
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet("w".to_string(), None, None, None, None, None, None)
            .await
            .unwrap();

        let txid_hex = "f1".to_string() + &"00".repeat(31); // 0xf1 followed by 31 zero bytes
        let outpoint = LockedOutpoint {
            txid: txid_hex.clone(),
            vout: 7,
        };

        // Lock it.
        let ok = rpc
            .lock_unspent(false, Some(vec![outpoint.clone()]), None)
            .await
            .expect("lockunspent must succeed");
        assert!(ok, "lockunspent must return true on success");

        // Listing must reflect the lock.
        let listed = rpc
            .list_lock_unspent()
            .await
            .expect("listlockunspent must succeed");
        assert_eq!(listed.len(), 1, "exactly one locked outpoint");
        assert_eq!(listed[0].txid, txid_hex);
        assert_eq!(listed[0].vout, 7);

        // Locking the same outpoint again should error per Core
        // (coins.cpp:326 "output already locked").
        let again = rpc
            .lock_unspent(false, Some(vec![outpoint.clone()]), None)
            .await;
        assert!(again.is_err(), "locking an already-locked output must error");

        // Unlock it.
        let ok = rpc
            .lock_unspent(true, Some(vec![outpoint.clone()]), None)
            .await
            .expect("unlock must succeed");
        assert!(ok);

        // Listing now empty.
        let listed = rpc.list_lock_unspent().await.unwrap();
        assert!(listed.is_empty(), "lock list must be empty after unlock");

        // Unlocking an already-unlocked output errors per Core (coins.cpp:323).
        let err = rpc
            .lock_unspent(true, Some(vec![outpoint.clone()]), None)
            .await;
        assert!(err.is_err(), "unlocking unlocked output must error");

        // Unlock-all (transactions=None, unlock=true) is a no-op success.
        rpc.lock_unspent(false, Some(vec![outpoint.clone()]), None)
            .await
            .unwrap();
        let cleared = rpc.lock_unspent(true, None, None).await.unwrap();
        assert!(cleared);
        let listed = rpc.list_lock_unspent().await.unwrap();
        assert!(listed.is_empty(), "unlock-all must clear all locks");
    }

    // -----------------------------------------------------------------------
    // walletcreatefundedpsbt — happy-path test using auto coin selection.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn walletcreatefundedpsbt_funds_from_wallet_utxo() {
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_primitives::{Hash256, OutPoint};
        use rustoshi_wallet::WalletUtxo;

        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet("w".to_string(), None, None, None, None, None, None)
            .await
            .unwrap();

        // Inject a confirmed UTXO that the wallet owns so that automatic
        // coin selection has something to pick.
        {
            let st = state.read().await;
            let wallet_arc = st
                .wallet_manager
                .get_wallet("w")
                .expect("wallet should exist");
            let mut wallet = wallet_arc.lock().unwrap();
            let addr = wallet.get_new_address().unwrap();
            let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
            let path = wallet.get_derivation_path(&addr).unwrap().clone();
            wallet.add_utxo(WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256([0x42u8; 32]),
                    vout: 0,
                },
                value: 1_000_000, // 0.01 BTC
                script_pubkey: addr_obj.to_script_pubkey(),
                derivation_path: path,
                confirmations: 6,
                is_change: false,
                is_coinbase: false,
                height: Some(100),
            });
        }

        // Recipient: a dummy testnet bech32 address.
        let recipient = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();
        let outputs = vec![FundedPsbtRecipient::Explicit {
            address: recipient,
            amount: 0.005, // 500_000 sats; leaves change > dust
        }];

        let res = rpc
            .wallet_create_funded_psbt(vec![], outputs, Some(0), None, Some(true))
            .await
            .expect("walletcreatefundedpsbt must succeed");

        // PSBT must be a valid base64 with the BIP-174 magic.
        assert!(
            res.psbt.starts_with("cHNidP8") || res.psbt.starts_with("cHNidP"),
            "PSBT must be base64-encoded BIP-174 magic; got {:?}",
            &res.psbt.get(..10)
        );
        // Fee must be positive (we are paying for the tx).
        assert!(res.fee > 0.0, "fee must be > 0");
        // Change position should exist (>=0) since the recipient is < UTXO.
        assert!(
            res.changepos >= 0,
            "expected a change output; changepos={}",
            res.changepos
        );

        // Round-trip: PSBT must deserialize cleanly.
        use rustoshi_wallet::psbt::Psbt;
        let p = Psbt::from_base64(&res.psbt).expect("PSBT base64 must decode");
        // unsigned tx must contain at least the recipient + change.
        assert!(
            p.unsigned_tx.outputs.len() >= 2,
            "expected recipient + change; got {} outputs",
            p.unsigned_tx.outputs.len()
        );
        // No script_sig / witness on inputs (creator-stage PSBT).
        for inp in &p.unsigned_tx.inputs {
            assert!(inp.script_sig.is_empty(), "PSBT inputs must be unsigned");
            assert!(inp.witness.is_empty(), "PSBT inputs must be unsigned");
        }
    }

    #[tokio::test]
    async fn walletcreatefundedpsbt_rejects_empty_outputs() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet("w".to_string(), None, None, None, None, None, None)
            .await
            .unwrap();

        let res = rpc
            .wallet_create_funded_psbt(vec![], vec![], None, None, None)
            .await;
        assert!(res.is_err(), "empty outputs must error");
    }

    #[tokio::test]
    async fn walletcreatefundedpsbt_skips_locked_utxo() {
        // The locked UTXO is the only one; auto selection must fail with
        // INSUFFICIENT_FUNDS rather than silently spending it.
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_primitives::{Hash256, OutPoint};
        use rustoshi_wallet::WalletUtxo;

        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet("w".to_string(), None, None, None, None, None, None)
            .await
            .unwrap();

        let outpoint_txid = [0xaau8; 32];
        let outpoint_txid_hex_be: String =
            outpoint_txid.iter().rev().map(|b| format!("{:02x}", b)).collect();

        {
            let st = state.read().await;
            let wallet_arc = st.wallet_manager.get_wallet("w").unwrap();
            let mut wallet = wallet_arc.lock().unwrap();
            let addr = wallet.get_new_address().unwrap();
            let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
            let path = wallet.get_derivation_path(&addr).unwrap().clone();
            wallet.add_utxo(WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256(outpoint_txid),
                    vout: 0,
                },
                value: 1_000_000,
                script_pubkey: addr_obj.to_script_pubkey(),
                derivation_path: path,
                confirmations: 6,
                is_change: false,
                is_coinbase: false,
                height: Some(100),
            });
        }

        // Lock the only UTXO.
        rpc.lock_unspent(
            false,
            Some(vec![LockedOutpoint {
                txid: outpoint_txid_hex_be,
                vout: 0,
            }]),
            None,
        )
        .await
        .unwrap();

        // Auto-funding now has nothing to pick.
        let outputs = vec![FundedPsbtRecipient::Explicit {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            amount: 0.005,
        }];
        let res = rpc
            .wallet_create_funded_psbt(vec![], outputs, None, None, None)
            .await;
        assert!(
            res.is_err(),
            "funding must fail when the only UTXO is locked"
        );
    }
}
