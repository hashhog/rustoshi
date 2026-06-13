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
use rustoshi_storage::block_store::BlockStore;
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
    /// There is already a wallet with the same name
    /// (`bitcoin-core/src/rpc/protocol.h::RPC_WALLET_ALREADY_EXISTS = -36`).
    /// Distinct from `RPC_WALLET_ERROR = -4`; the previous -4 here collided
    /// with that generic code.
    pub const RPC_WALLET_ALREADY_EXISTS: i32 = -36;
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
    /// Failed to encrypt the wallet (Core's RPC_WALLET_ENCRYPTION_FAILED,
    /// e.g. encryptwallet on a wallet with private keys disabled).
    pub const RPC_WALLET_ENCRYPTION_FAILED: i32 = -16;
    /// Error parsing or validating structure in raw format
    /// (Core's RPC_DESERIALIZATION_ERROR), e.g. a malformed base64 PSBT in
    /// `walletprocesspsbt` (spend.cpp: "TX decode failed").
    pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
}

/// Extract a single (33-byte compressed pubkey, DER-sig+hashtype) partial-sig
/// pair from a freshly-signed input, for the `walletprocesspsbt`
/// sign=true/finalize=false path (records a `PSBT_IN_PARTIAL_SIG` instead of
/// finalizing). Handles the single-key shapes the wallet signer produces:
///   - P2WPKH / P2SH-P2WPKH witness: `[sig+hashtype, pubkey(33)]`
///   - P2PKH scriptSig: `push(sig+hashtype) push(pubkey(33))`
/// Returns None for multi-element or unrecognised shapes (Taproot key-path
/// sigs are not partial-sig records and are left to the finalize path).
fn extract_single_partial_sig(
    input: &rustoshi_primitives::TxIn,
) -> Option<([u8; 33], Vec<u8>)> {
    // Witness shape (P2WPKH / P2SH-P2WPKH): [sig, pubkey33].
    if input.witness.len() == 2 {
        let sig = &input.witness[0];
        let pk = &input.witness[1];
        if pk.len() == 33 && (pk[0] == 0x02 || pk[0] == 0x03) {
            let mut pk33 = [0u8; 33];
            pk33.copy_from_slice(pk);
            return Some((pk33, sig.clone()));
        }
    }
    // Legacy P2PKH scriptSig: <push sig> <push pubkey33>.
    let ss = &input.script_sig;
    if !ss.is_empty() {
        let sig_len = ss[0] as usize;
        if 1 + sig_len < ss.len() {
            let sig = ss[1..1 + sig_len].to_vec();
            let pk_off = 1 + sig_len;
            let pk_len = ss[pk_off] as usize;
            if pk_len == 33 && pk_off + 1 + pk_len <= ss.len() {
                let pk = &ss[pk_off + 1..pk_off + 1 + pk_len];
                if pk[0] == 0x02 || pk[0] == 0x03 {
                    let mut pk33 = [0u8; 33];
                    pk33.copy_from_slice(pk);
                    return Some((pk33, sig));
                }
            }
        }
    }
    None
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
    /// Only present (and `true`) when the transaction's only input is a
    /// coinbase one. Mirrors Core's `generated` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
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

/// A single line item in a `gettransaction` `details[]` array.
///
/// Mirrors one element of Core's `gettransaction` details (see
/// `wallet/rpc/transactions.cpp`): a per-output receive/generate or a
/// per-recipient send.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDetail {
    /// The address involved (recipient for a send, own address for a receive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// "send" | "receive" | "generate" | "immature".
    pub category: String,
    /// Amount in BTC. NEGATIVE for the `send` category.
    pub amount: f64,
    /// Output index.
    pub vout: u32,
    /// Fee in BTC (NEGATIVE), present only for `send` line items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<f64>,
}

/// Result of the `gettransaction` RPC.
///
/// Mirrors Bitcoin Core's `gettransaction` response shape
/// (`wallet/rpc/transactions.cpp`): the net wallet `amount`, the `fee` (sends
/// only, negative), confirmation + block context, the `details[]` breakdown,
/// and the raw `hex`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTransactionResult {
    /// Net amount to the wallet in BTC (`nNet - nFee` in Core terms).
    pub amount: f64,
    /// Fee in BTC (NEGATIVE), present only when the wallet sent this tx.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<f64>,
    /// Number of confirmations.
    pub confirmations: i32,
    /// Only present (`true`) for coinbase transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    /// Block hash containing the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<String>,
    /// Block height containing the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockheight: Option<u32>,
    /// Block timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocktime: Option<u64>,
    /// Transaction ID (display / reversed byte order).
    pub txid: String,
    /// Wallet conflicts.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub walletconflicts: Vec<String>,
    /// BIP-125 replaceability status.
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: String,
    /// Unix timestamp when the transaction was received.
    pub time: u64,
    /// Unix timestamp when the transaction was received (same as time).
    pub timereceived: u64,
    /// Per-output / per-recipient line items.
    pub details: Vec<TransactionDetail>,
    /// The raw transaction, hex-encoded (full witness serialization).
    pub hex: String,
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

/// Result of `walletprocesspsbt`.
///
/// Mirrors `bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt`
/// (v31.99): always `{psbt, complete}`, and `hex` ONLY when `complete`
/// (the finalized network transaction, hex-encoded — Core gates the `hex`
/// push on `if (complete)`, NOT on the `finalize` flag, because `complete`
/// already implies finalizability).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletProcessPsbtResult {
    /// The base64-encoded (partially) signed PSBT.
    pub psbt: String,
    /// True iff every input is now signed AND finalizable into a complete
    /// network transaction.
    pub complete: bool,
    /// The hex-encoded finalized network transaction. Present ONLY when
    /// `complete` is true (Core: `result.pushKV("hex", ...)` inside
    /// `if (complete)`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

/// Options for `fundrawtransaction` (Core's `options` parameter).
///
/// Mirrors a subset of Bitcoin Core's `fundrawtransaction` options
/// (`bitcoin-core/src/wallet/rpc/spend.cpp::FundTransaction`). The default
/// (no-options) path is fully supported. `changeAddress`, `changePosition`,
/// `feeRate` (BTC/kvB) / `fee_rate` (sat/vB), and `subtractFeeFromOutputs`
/// are honoured where tractable; less-common knobs (`includeWatching`,
/// `lockUnspents`, `change_type`, `conf_target`, `estimate_mode`) are
/// accepted-and-ignored or refused honestly rather than silently
/// mis-applied.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FundRawTransactionOptions {
    /// The bitcoin address to receive the change.
    #[serde(rename = "changeAddress", alias = "change_address", skip_serializing_if = "Option::is_none")]
    pub change_address: Option<String>,
    /// The index of the change output.
    #[serde(rename = "changePosition", alias = "change_position", skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,
    /// Output indices whose amounts the fee should be subtracted from.
    #[serde(rename = "subtractFeeFromOutputs", alias = "subtract_fee_from_outputs", skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,
    /// Fee rate in sat/vB (Core `fee_rate`).
    #[serde(rename = "fee_rate", skip_serializing_if = "Option::is_none")]
    pub fee_rate: Option<f64>,
    /// Fee rate in BTC/kvB (Core `feeRate`). Converted to sat/vB internally.
    #[serde(rename = "feeRate", skip_serializing_if = "Option::is_none")]
    pub fee_rate_btc_kvb: Option<f64>,
    /// Mark the transaction BIP-125 replaceable (default: true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    /// (DEPRECATED in Core) No longer used; accepted for compatibility.
    #[serde(rename = "includeWatching", alias = "include_watching", skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    /// Lock selected unspent outputs (accepted; not yet applied).
    #[serde(rename = "lockUnspents", alias = "lock_unspents", skip_serializing_if = "Option::is_none")]
    pub lock_unspents: Option<bool>,
    /// Confirmation target in blocks (accepted; fee estimator not wired).
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,
    /// Fee estimate mode (`unset`, `economical`, `conservative`).
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<String>,
}

/// Result of `fundrawtransaction`.
///
/// Matches Core's JSON shape EXACTLY:
/// `{ "hex": <funded raw tx hex>, "fee": <BTC>, "changepos": <int or -1> }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FundRawTransactionResult {
    /// The resulting raw transaction (hex-encoded).
    pub hex: String,
    /// Fee in BTC the resulting transaction pays.
    pub fee: f64,
    /// Position of the added change output, or -1 if none was added.
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
    /// Shared core node state, wired in `start_rpc_server` so wallet-native
    /// spends (`sendtoaddress`) can broadcast the signed transaction into the
    /// node's mempool — the same path `sendrawtransaction` uses. `None` when
    /// the wallet RPC is constructed standalone (unit tests): `sendtoaddress`
    /// then builds + signs but cannot broadcast.
    pub node: Option<Arc<RwLock<crate::server::RpcState>>>,
}

impl WalletRpcState {
    /// Create new wallet RPC state.
    pub fn new(wallet_manager: WalletManager, data_dir: PathBuf) -> Self {
        Self {
            wallet_manager,
            data_dir,
            payjoin_endpoint: None,
            node: None,
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

    /// Get detailed information about an in-wallet transaction.
    ///
    /// Parameters:
    /// - txid: The transaction id (display / reversed byte order)
    /// - include_watchonly: Include watch-only addresses (default: true for
    ///   watch-only wallets)
    /// - verbose: Include the decoded transaction (currently ignored)
    #[method(name = "gettransaction")]
    async fn get_transaction(
        &self,
        txid: String,
        include_watchonly: Option<bool>,
        verbose: Option<bool>,
    ) -> RpcResult<GetTransactionResult>;

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

    /// Sign a raw transaction with the EXPLICIT private keys provided (no
    /// wallet). Core's `signrawtransactionwithkey`
    /// (`bitcoin-core/src/rpc/rawtransaction.cpp::signrawtransactionwithkey` ->
    /// `SignTransaction`): build a temporary keystore from the WIF keys, fill
    /// missing prevout info from `prevtxs` (and the chain/mempool), sign every
    /// input a provided key controls, and return `{hex, complete, errors?}`.
    ///
    /// REUSES the SAME BIP-143/BIP-341 sighash + ECDSA/Schnorr engine as
    /// `signrawtransactionwithwallet` / `walletprocesspsbt`
    /// (`Wallet::sign_input_with_key` -> the per-script signers in
    /// `crates/wallet/src/wallet.rs`); the only difference is the keystore is
    /// the supplied keys + prevtxs, not the wallet HD tree. Does NOT require a
    /// loaded/unlocked wallet.
    ///
    /// Parameters:
    /// - hexstring: the hex-encoded raw transaction.
    /// - privkeys: array of WIF-encoded base58check private keys.
    /// - prevtxs: previous outputs being spent (optional). Each `{txid, vout,
    ///   scriptPubKey, redeemScript?, witnessScript?, amount?}`.
    /// - sighashtype: signature hash type (default: ALL).
    #[method(name = "signrawtransactionwithkey")]
    async fn sign_raw_transaction_with_key(
        &self,
        hexstring: String,
        privkeys: Vec<String>,
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

    /// Return information about the given bitcoin address that the wallet
    /// knows (Core's `getaddressinfo`,
    /// `bitcoin-core/src/wallet/rpc/addresses.cpp:368-513`).
    ///
    /// Emits Core's field order: address, scriptPubKey, ismine, solvable,
    /// desc (only when solvable), parent_desc (when a wallet descriptor
    /// matches), iswatchonly (DEPRECATED — always false, addresses.cpp:478),
    /// script-class detail (isscript/iswitness/witness_version/
    /// witness_program), pubkey (when known), ischange, labels. `ismine` is
    /// TRUE for watch-only descriptor matches — descriptor wallets have no
    /// ismine/iswatchonly split.
    ///
    /// Errors: -5 with "Invalid address" when the address fails to decode
    /// (addresses.cpp:434-439).
    #[method(name = "getaddressinfo")]
    async fn get_address_info(&self, address: String) -> RpcResult<serde_json::Value>;

    /// Set (restore) the wallet's HD master seed deterministically.
    ///
    /// This is rustoshi's seed-only wallet-recovery entry point and mirrors
    /// the intent of Bitcoin Core's `sethdseed`
    /// (`bitcoin-core/src/wallet/rpc/backup.cpp`): replace the active wallet's
    /// HD chain so the SAME seed always re-derives byte-identical addresses.
    /// Combined with `scantxoutset`, this lets a wallet that lost its disk
    /// state recover 100% of its on-chain funds from the seed alone.
    ///
    /// Unlike Core (which takes a WIF private key), rustoshi's wallet is built
    /// directly from a BIP-39-style 64-byte master seed (see
    /// `rustoshi_wallet::Wallet::from_seed`), so the `seed` argument is the
    /// 128-hex-character (64-byte) master seed. The restored wallet inherits
    /// the existing wallet's network and address type, and the seed is
    /// persisted so a later `loadwallet` round-trips to the same keys.
    ///
    /// Parameters:
    /// - newkeypool: Core-compatibility flag; accepted but unused (rustoshi
    ///   always regenerates the keypool from index 0 on restore).
    /// - seed: 64-byte master seed, hex-encoded (128 hex chars). When omitted,
    ///   Core generates a fresh random seed; we require it explicitly here so
    ///   the call is unambiguously a *deterministic restore*.
    ///
    /// Returns the HD seed fingerprint (Core returns null; we return the
    /// first-4-bytes fingerprint hex so callers can confirm which seed is
    /// active).
    ///
    /// Errors:
    /// - `-5` (RPC_WALLET_INVALID_ADDRESS_OR_KEY) if `seed` is missing or not
    ///   exactly 64 bytes of valid hex.
    /// - `-4` (RPC_WALLET_ERROR) on any wallet/persistence failure.
    #[method(name = "sethdseed")]
    async fn set_hd_seed(
        &self,
        newkeypool: Option<bool>,
        seed: Option<String>,
    ) -> RpcResult<serde_json::Value>;

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

    /// Update, sign, and optionally finalize a PSBT with wallet data
    /// (Core's `walletprocesspsbt`, Updater + Signer + Finalizer roles).
    ///
    /// Mirrors `bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt`
    /// (v31.99). Decodes the base64 PSBT, fills in witness/non-witness UTXO,
    /// scripts, and BIP-32 derivations the wallet knows (Updater), signs every
    /// input the wallet holds a key for (Signer, `sign` default true) using the
    /// SAME BIP-143/BIP-341 sighash + ECDSA/Schnorr engine as
    /// `signrawtransactionwithwallet` (`Wallet::sign_input`), and finalizes
    /// completed inputs (`finalize` default true).
    ///
    /// Returns `{psbt, complete}`, plus `hex` (the finalized network tx) ONLY
    /// when `complete`.
    ///
    /// Parameters:
    /// - psbt: the base64 PSBT string.
    /// - sign: also sign the transaction (default: true).
    /// - sighashtype: signature hash type (default: ALL).
    /// - bip32derivs: include BIP-32 derivation paths in the PSBT (default: true).
    /// - finalize: also finalize inputs if possible (default: true).
    #[method(name = "walletprocesspsbt")]
    async fn wallet_process_psbt(
        &self,
        psbt: String,
        sign: Option<bool>,
        sighashtype: Option<String>,
        bip32derivs: Option<bool>,
        finalize: Option<bool>,
    ) -> RpcResult<WalletProcessPsbtResult>;

    /// Add inputs (and, if needed, a change output) to a raw transaction so
    /// the wallet funds all of its existing outputs plus the fee
    /// (Core's `fundrawtransaction`).
    ///
    /// Mirrors `bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction`,
    /// which decodes the raw tx hex, treats its existing outputs as the
    /// recipients, and calls the same `FundTransaction` coin-selection engine
    /// that backs `walletcreatefundedpsbt`. The raw-tx sibling: instead of
    /// wrapping the funded tx as a PSBT, it serialises the funded tx back to
    /// hex.
    ///
    /// Reuses rustoshi's `Wallet::create_transaction` (the same selector
    /// `walletcreatefundedpsbt`'s no-inputs path uses) to pick inputs and an
    /// economic change output, then grafts those onto the decoded tx's
    /// existing inputs/outputs (existing outputs are preserved byte-identical,
    /// per Core "No existing outputs will be modified").
    ///
    /// Parameters:
    /// - `hexstring`: the hex of the raw transaction to fund.
    /// - `options`: optional `FundRawTransactionOptions`
    ///   (changeAddress / changePosition / feeRate / fee_rate /
    ///   subtractFeeFromOutputs / replaceable / …).
    /// - `iswitness`: hint for witness vs non-witness decoding (heuristic if
    ///   omitted; rustoshi's `Transaction::deserialize` auto-detects).
    ///
    /// Returns `{ hex, fee, changepos }` with GENUINE values — real selected
    /// inputs, real computed fee, real change position.
    ///
    /// Errors:
    /// - `-6` (RPC_WALLET_INSUFFICIENT_FUNDS) if the wallet cannot cover
    ///   outputs + fee.
    /// - `-5` (RPC_WALLET_INVALID_ADDRESS_OR_KEY) for a bad changeAddress or
    ///   an output whose script is non-standard / un-fundable.
    /// - `-4` (RPC_WALLET_ERROR) on hex/decode failure or other errors.
    #[method(name = "fundrawtransaction")]
    async fn fund_raw_transaction(
        &self,
        hexstring: String,
        options: Option<FundRawTransactionOptions>,
        iswitness: Option<bool>,
    ) -> RpcResult<FundRawTransactionResult>;

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

    /// The wallet this request is pinned to: an explicitly-constructed target
    /// (tests / `with_target_wallet`) first, then the `/wallet/<name>` URL pin
    /// scoped by [`crate::wallet_route::WalletRouteLayer`]. `None` for
    /// bare-endpoint requests.
    fn effective_wallet(&self) -> Option<String> {
        self.target_wallet
            .clone()
            .or_else(crate::wallet_route::current_wallet_route)
    }

    /// Resolve the wallet this request operates on, mirroring Core's
    /// `GetWalletForJSONRPCRequest` (wallet/rpc/util.cpp:54-86) error
    /// contract exactly:
    /// - `/wallet/<name>` pinned but not loaded → `-18`
    ///   "Requested wallet does not exist or is not loaded" (util.cpp:71-72);
    /// - bare endpoint, no wallets loaded → `-18` long message
    ///   (util.cpp:80-83);
    /// - bare endpoint, exactly one wallet → that wallet (util.cpp:76-78);
    /// - bare endpoint, several wallets → `-19` (util.cpp:84-85). This is the
    ///   ONLY case that may return -19.
    fn resolve_wallet(
        &self,
        state: &WalletRpcState,
    ) -> Result<(String, Arc<std::sync::Mutex<rustoshi_wallet::Wallet>>), ErrorObjectOwned> {
        match self.effective_wallet() {
            Some(name) => state
                .wallet_manager
                .get_wallet(&name)
                .map(|w| (name, w))
                .ok_or_else(|| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_NOT_FOUND,
                        "Requested wallet does not exist or is not loaded",
                    )
                }),
            None => match state.wallet_manager.wallet_count() {
                0 => Err(Self::rpc_error(
                    wallet_error::RPC_WALLET_NOT_FOUND,
                    "No wallet is loaded. Load a wallet using loadwallet or create a new one \
                     with createwallet. (Note: A default wallet is no longer automatically \
                     created)",
                )),
                1 => state.wallet_manager.get_default_wallet().ok_or_else(|| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_NOT_FOUND,
                        "Requested wallet does not exist or is not loaded",
                    )
                }),
                _ => Err(Self::rpc_error(
                    wallet_error::RPC_WALLET_NOT_SPECIFIED,
                    "Multiple wallets are loaded. Please select which wallet to use by \
                     requesting the RPC through the /wallet/<walletname> URI path.",
                )),
            },
        }
    }

    /// Satoshis to BTC.
    fn sats_to_btc(sats: u64) -> f64 {
        sats as f64 / 100_000_000.0
    }

    /// Signed satoshis to BTC (preserves a negative sign for send amounts/fees).
    fn sats_to_btc_signed(sats: i64) -> f64 {
        sats as f64 / 100_000_000.0
    }

    /// BTC to satoshis.
    fn btc_to_sats(btc: f64) -> u64 {
        (btc * 100_000_000.0).round() as u64
    }

    /// Decode a raw transaction from bytes, mirroring Core's `DecodeHexTx`
    /// try-witness-then-no-witness heuristic
    /// (`bitcoin-core/src/core_io.h::DecodeHexTx`).
    ///
    /// rustoshi's `Transaction::deserialize` auto-detects the SegWit marker,
    /// which is ambiguous for a transaction with ZERO inputs: such a tx
    /// serialises as `version | 0x00 | <vout count> | …`, and the leading
    /// `0x00` is indistinguishable from the SegWit marker byte. That is
    /// exactly the shape `fundrawtransaction` is handed (a tx with outputs but
    /// no inputs), and precisely why Core takes the `iswitness` hint. We try
    /// the witness-permitting decode first; on failure (or when the caller
    /// passed `iswitness = Some(false)`) we fall back to a forced non-witness
    /// decode that always treats the post-version compact-size as the input
    /// count.
    fn decode_raw_tx_heuristic(
        bytes: &[u8],
        iswitness: Option<bool>,
    ) -> Result<rustoshi_primitives::Transaction, String> {
        use rustoshi_primitives::{Decodable, Transaction};

        // Honour an explicit `iswitness = false` by skipping the ambiguous
        // witness-permitting path entirely.
        if iswitness != Some(false) {
            if let Ok(tx) = Transaction::deserialize(bytes) {
                return Ok(tx);
            }
        }
        if iswitness == Some(true) {
            // Caller insisted on witness decoding and it failed.
            return Err("TX decode failed (witness)".to_string());
        }
        Self::decode_raw_tx_no_witness(bytes)
            .map_err(|e| format!("TX decode failed: {}", e))
    }

    /// Force a non-witness decode (no SegWit marker interpretation). Mirrors
    /// `Transaction::decode` but always reads the byte(s) after the version as
    /// the input count. Used as the `fundrawtransaction` fallback for the
    /// zero-input case (see `decode_raw_tx_heuristic`).
    fn decode_raw_tx_no_witness(
        bytes: &[u8],
    ) -> std::io::Result<rustoshi_primitives::Transaction> {
        use rustoshi_primitives::{read_compact_size, Decodable, OutPoint, Transaction, TxIn, TxOut};
        use std::io::Read;

        let mut reader = bytes;

        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = i32::from_le_bytes(version_bytes);

        let input_count = read_compact_size(&mut reader)?;
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            let previous_output = OutPoint::decode(&mut reader)?;
            let script_len = read_compact_size(&mut reader)?;
            let mut script_sig = vec![0u8; script_len as usize];
            reader.read_exact(&mut script_sig)?;
            let mut seq_bytes = [0u8; 4];
            reader.read_exact(&mut seq_bytes)?;
            let sequence = u32::from_le_bytes(seq_bytes);
            inputs.push(TxIn {
                previous_output,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }

        let output_count = read_compact_size(&mut reader)?;
        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            outputs.push(TxOut::decode(&mut reader)?);
        }

        let mut lock_bytes = [0u8; 4];
        reader.read_exact(&mut lock_bytes)?;
        let lock_time = u32::from_le_bytes(lock_bytes);

        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
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

    /// Core's `GetImportTimestamp` (wallet/rpc/backup.cpp:127-139): the
    /// `timestamp` field is REQUIRED per element and a missing or mistyped
    /// value is a TOP-LEVEL RPC_TYPE_ERROR (-3) throw — probe-confirmed
    /// against Core v31.99. Returns `Ok(None)` for `"now"`, `Ok(Some(ts))`
    /// for a numeric timestamp.
    fn parse_import_timestamp(
        value: &serde_json::Value,
    ) -> Result<Option<u64>, ErrorObjectOwned> {
        const RPC_TYPE_ERROR: i32 = -3;
        match value {
            serde_json::Value::Null => Err(Self::rpc_error(
                RPC_TYPE_ERROR,
                "Missing required timestamp field for key",
            )),
            serde_json::Value::String(s) if s == "now" => Ok(None),
            serde_json::Value::Number(n) => {
                // Negative timestamps clamp to 0 (then to the minimum of 1 by
                // the caller, matching Core's minimum_timestamp).
                Ok(Some(n.as_u64().unwrap_or(0)))
            }
            other => {
                let type_name = match other {
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                    _ => "null",
                };
                Err(Self::rpc_error(
                    RPC_TYPE_ERROR,
                    format!(
                        "Expected number or \"now\" timestamp value for key. got type {}",
                        type_name
                    ),
                ))
            }
        }
    }

    /// Core's `CheckChecksum` in REQUIRE mode
    /// (bitcoin-core/src/script/descriptor.cpp:2838-2869, reached via
    /// `Parse(..., require_checksum=true)` from backup.cpp:158): every
    /// importdescriptors descriptor MUST carry a valid checksum. Returns the
    /// payload (descriptor without checksum) or Core's exact error string.
    fn check_descriptor_checksum(desc: &str) -> Result<&str, String> {
        use rustoshi_wallet::descriptor::descriptor_checksum;

        let mut split = desc.split('#');
        let payload = split.next().unwrap_or(desc);
        let provided = match split.next() {
            // No '#' at all -> require mode fails (descriptor.cpp:2845-2848).
            None => return Err("Missing checksum".to_string()),
            Some(c) => c,
        };
        if split.next().is_some() {
            // descriptor.cpp:2841-2844.
            return Err("Multiple '#' symbols".to_string());
        }
        if provided.len() != 8 {
            // descriptor.cpp:2850-2853.
            return Err(format!(
                "Expected 8 character checksum, not {} characters",
                provided.len()
            ));
        }
        let computed = descriptor_checksum(payload)
            .ok_or_else(|| "Invalid characters in payload".to_string())?;
        if computed != provided {
            // descriptor.cpp:2860-2864.
            return Err(format!(
                "Provided checksum '{}' does not match computed checksum '{}'",
                provided, computed
            ));
        }
        Ok(payload)
    }

    /// Core's `ParseDescriptorRange` (rpc/util.cpp): a number is the
    /// inclusive end (begin 0), `[begin, end]` an explicit pair.
    fn parse_descriptor_range(value: &serde_json::Value) -> Result<(u32, u32), (i32, String)> {
        const RPC_INVALID_PARAMETER: i32 = -8;
        if let Some(n) = value.as_i64() {
            if n < 0 {
                return Err((
                    RPC_INVALID_PARAMETER,
                    "Range should be greater or equal than 0".into(),
                ));
            }
            if n >= 10_000_000 {
                return Err((RPC_INVALID_PARAMETER, "Range is too large".into()));
            }
            return Ok((0, n as u32));
        }
        if let Some(arr) = value.as_array() {
            if arr.len() == 2 {
                if let (Some(begin), Some(end)) = (arr[0].as_i64(), arr[1].as_i64()) {
                    if begin < 0 {
                        return Err((
                            RPC_INVALID_PARAMETER,
                            "Range should be greater or equal than 0".into(),
                        ));
                    }
                    if end < begin {
                        return Err((
                            RPC_INVALID_PARAMETER,
                            "Range specified as [begin,end] must not have begin after end".into(),
                        ));
                    }
                    if end >= 10_000_000 || end - begin >= 1_000_000 {
                        return Err((RPC_INVALID_PARAMETER, "Range is too large".into()));
                    }
                    return Ok((begin as u32, end as u32));
                }
            }
        }
        Err((
            RPC_INVALID_PARAMETER,
            "Range must be specified as end or as [begin,end]".into(),
        ))
    }

    /// One element of `importdescriptors`, mirroring Core's
    /// `ProcessDescriptorImport` (wallet/rpc/backup.cpp:141-300). Any error
    /// returns `(code, message)` which the caller embeds PER-ELEMENT as
    /// `{"success":false,"error":{...}}` (backup.cpp:293-297) — never a
    /// top-level RPC error. On success returns
    /// `(canonical_descriptor, label, range_end, warnings)`.
    fn process_descriptor_import(
        wallet: &mut rustoshi_wallet::Wallet,
        request: &crate::types::ImportDescriptorRequest,
    ) -> Result<(String, String, u32, Vec<String>), (i32, String)> {
        use rustoshi_wallet::descriptor::{
            descriptor_wif_secrets, parse_descriptor, DescriptorInfo,
        };
        const RPC_INVALID_PARAMETER: i32 = -8;

        let mut warnings: Vec<String> = Vec::new();
        let desc_str = request.desc.trim();

        // 1. Checksum is REQUIRED (Core backup.cpp:158 Parse with
        //    require_checksum=true; -5 on failure, backup.cpp:159-161).
        let payload = Self::check_descriptor_checksum(desc_str)
            .map_err(|msg| (wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY, msg))?;

        // 2. Parse the descriptor body.
        let parsed = parse_descriptor(payload).map_err(|e| {
            (
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                format!("{}", e),
            )
        })?;
        let info = DescriptorInfo::from_descriptor(&parsed);

        // 3. Range checks (backup.cpp:173-186).
        let range_end: u32 = if !parsed.is_range() {
            if request.range.is_some() {
                return Err((
                    RPC_INVALID_PARAMETER,
                    "Range should not be specified for an un-ranged descriptor".into(),
                ));
            }
            0
        } else {
            match &request.range {
                Some(v) => {
                    // NOTE: a [begin,end] range registers scripts 0..=end (a
                    // superset of Core's [begin,end] watch set) — rustoshi's
                    // watch registry has no begin offset yet.
                    let (_begin, end) = Self::parse_descriptor_range(v)?;
                    end
                }
                None => {
                    warnings.push("Range not given, using default keypool range".to_string());
                    // Core defaults to wallet.m_keypool_size (exclusive end);
                    // getwalletinfo reports keypoolsize 1000 -> inclusive 999.
                    999
                }
            }
        };
        if request.active && !parsed.is_range() {
            return Err((
                RPC_INVALID_PARAMETER,
                "Active descriptors must be ranged".into(),
            ));
        }
        if parsed.is_range() && request.label.is_some() {
            return Err((
                RPC_INVALID_PARAMETER,
                "Ranged descriptors should not have a label".into(),
            ));
        }

        // 4. Private-key gates (backup.cpp:224-226 and 259-262) — both -4.
        let privkeys_enabled = wallet.private_keys_enabled();
        if !privkeys_enabled && info.has_private_keys {
            return Err((
                wallet_error::RPC_WALLET_ERROR,
                "Cannot import private keys to a wallet with private keys disabled".into(),
            ));
        }
        if privkeys_enabled && !info.has_private_keys {
            return Err((
                wallet_error::RPC_WALLET_ERROR,
                "Cannot import descriptor without private keys to a wallet with private keys \
                 enabled"
                    .into(),
            ));
        }

        // 5. Register the descriptor's scripts into the watch set, and (for
        //    privkey-enabled wallets) import any WIF secrets so the funds are
        //    spendable, mirroring AddWalletDescriptor's key import.
        let label = request.label.clone().unwrap_or_default();
        let canonical = desc_str.to_string();
        wallet
            .register_descriptor(&canonical, &parsed, &label, range_end)
            .map_err(|e| {
                (
                    wallet_error::RPC_WALLET_ERROR,
                    format!("Could not add descriptor '{}': {}", desc_str, e),
                )
            })?;
        if privkeys_enabled && info.has_private_keys {
            let wifs = descriptor_wif_secrets(&parsed);
            if wifs.is_empty() {
                // xprv-bearing descriptor: scripts are watched, but extended
                // private key material is not yet stored for signing.
                warnings.push(
                    "Not all private keys provided. Some wallet functionality may return \
                     unexpected errors"
                        .to_string(),
                );
            }
            for secret in wifs {
                if let Err(e) = wallet.import_private_key(secret, label.clone()) {
                    warnings.push(format!("failed to import descriptor private key: {}", e));
                }
            }
        }

        Ok((canonical, label, range_end, warnings))
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
            .map_err(|e| {
                let msg = e.to_string();
                // Core's HandleWalletError (wallet/rpc/util.cpp:127-156) maps
                // DatabaseStatus::FAILED_ALREADY_LOADED -> RPC_WALLET_ALREADY_LOADED
                // (-35) and FAILED_ALREADY_EXISTS -> RPC_WALLET_ALREADY_EXISTS (-36),
                // both distinct from the generic RPC_WALLET_ERROR (-4). The manager
                // returns "already loaded" when the name is in memory and
                // "already exists" when the on-disk wallet dir is present.
                if msg.contains("already loaded") {
                    Self::rpc_error(wallet_error::RPC_WALLET_ALREADY_LOADED, msg)
                } else if msg.contains("already exists") {
                    Self::rpc_error(wallet_error::RPC_WALLET_ALREADY_EXISTS, msg)
                } else {
                    Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                }
            })?;

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

        // Determine which wallet to unload (explicit param, then the
        // /wallet/<name> URL pin)
        let name = wallet_name
            .or_else(|| self.effective_wallet())
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

        let (_, wallet) = self.resolve_wallet(&state)?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // Core's getbalance reports the TRUSTED, SPENDABLE balance: confirmed
        // and (for coinbase) mature. Immature coinbase and unconfirmed coins
        // are excluded — they show up under getbalances.mine.immature /
        // untrusted_pending instead. `minconf` raises the confirmation floor
        // above the default. (Reference: bitcoin-core wallet/rpc/coins.cpp
        // getbalance -> GetBalance().m_mine_trusted.)
        let min_confirmations = minconf.unwrap_or(0);
        let balance = if min_confirmations <= 1 {
            // Default / minconf<=1: mature, confirmed, spendable coins.
            wallet_guard.spendable_balance()
        } else {
            // Higher minconf: still spendable, but require >= minconf
            // confirmations (and coinbase maturity, enforced by is_spendable).
            wallet_guard
                .list_spendable_unspent()
                .iter()
                .filter(|u| u.confirmations >= min_confirmations)
                .map(|u| u.value)
                .sum()
        };

        Ok(Self::sats_to_btc(balance))
    }

    async fn get_balances(&self) -> RpcResult<BalanceInfo> {
        let state = self.state.read().await;

        let (_, wallet) = self.resolve_wallet(&state)?;

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

        let (_, wallet) = self.resolve_wallet(&state)?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let min_confirmations = minconf.unwrap_or(1);
        let max_confirmations = maxconf.unwrap_or(9999999);

        // Decode each UTXO's scriptPubKey back to its address so listunspent can
        // label + filter by address (Core's `out.pushKV("address", ...)`). The
        // wallet only holds wallet-owned coins, so this is `ExtractDestination`
        // over a known-standard script.
        let network = state.wallet_manager.network();
        let want_addrs: Option<std::collections::HashSet<String>> = addresses
            .as_ref()
            .filter(|a| !a.is_empty())
            .map(|a| a.iter().cloned().collect());

        let utxos: Vec<UnspentOutput> = wallet_guard
            .list_unspent()
            .iter()
            .filter(|utxo| {
                utxo.confirmations >= min_confirmations && utxo.confirmations <= max_confirmations
            })
            .filter_map(|utxo| {
                let addr = rustoshi_crypto::address::Address::from_script_pubkey(
                    &utxo.script_pubkey,
                    network,
                )
                .map(|a| a.encode());

                // Address filter: if the caller passed a non-empty address list,
                // only keep UTXOs whose decoded address is in it (Core's
                // `destinations` set check).
                if let Some(want) = &want_addrs {
                    match &addr {
                        Some(a) if want.contains(a) => {}
                        _ => return None,
                    }
                }

                // Immature coinbase is listed but flagged non-spendable, the
                // way Core's listunspent reports `spendable=false` for coins
                // that fail IsSpendable (incl. coinbase under 100 confs).
                let spendable = wallet_guard.is_spendable(utxo);
                // Watched (descriptor-imported) coins report their
                // descriptor's solvability — false for addr()/raw(), matching
                // Core's listunspent on a watch-only descriptor wallet
                // (spendable stays true: descriptor ISMINE).
                let solvable = wallet_guard
                    .watched_script(&utxo.script_pubkey)
                    .map(|w| w.solvable)
                    .unwrap_or(true);
                Some(UnspentOutput {
                    txid: hex::encode(utxo.outpoint.txid.0.iter().rev().copied().collect::<Vec<_>>()),
                    vout: utxo.outpoint.vout,
                    address: addr,
                    script_pubkey: hex::encode(&utxo.script_pubkey),
                    amount: Self::sats_to_btc(utxo.value),
                    confirmations: utxo.confirmations,
                    spendable,
                    solvable,
                    safe: utxo.confirmations >= 1,
                })
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

        let (_, wallet) = self.resolve_wallet(&state)?;

        let mut wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // Core: getnewaddress on a disable_private_keys wallet -> -4
        // "Error: This wallet has no available keys" (addresses.cpp:47 via
        // CanGetAddresses; probe-confirmed exact text).
        if !wallet_guard.private_keys_enabled() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "Error: This wallet has no available keys",
            ));
        }

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

        let (name, wallet) = self.resolve_wallet(&state)?;

        // Core SendMoney: -4 "Error: Private keys are disabled for this
        // wallet" (spend.cpp:177-178; probe-confirmed exact text).
        {
            let wallet_guard = wallet.lock().map_err(|_| {
                Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet")
            })?;
            if !wallet_guard.private_keys_enabled() {
                return Err(Self::rpc_error(
                    wallet_error::RPC_WALLET_ERROR,
                    "Error: Private keys are disabled for this wallet",
                ));
            }
        }

        // P0-SECURITY gate (W118 BUG-1): signing requires an unlocked wallet.
        Self::require_unlocked(&state, &name)?;

        let amount_sats = Self::btc_to_sats(amount);
        // Default fee rate in sat/vByte. Padded above the 1 sat/vB relay floor
        // so the wallet's vsize estimate (which can undershoot the final
        // witness-stack size by a byte or two) never lands the tx below the
        // mempool's minimum-relay-fee and gets rejected — the same fee-floor
        // fix the beamchain reference cell needed.
        let fee_rate = 5.0;

        // Build + sign the transaction under the wallet lock, then DROP the
        // wallet guard before touching the node mempool. The mining /
        // block-connect path takes node-write THEN wallet-lock; doing the
        // reverse here while holding the wallet lock would invert lock order.
        let tx = {
            let mut wallet_guard = wallet.lock().map_err(|_| {
                Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet")
            })?;
            wallet_guard
                .create_transaction(vec![(address, amount_sats)], fee_rate)
                .map_err(|e| {
                    let msg = e.to_string();
                    if msg.contains("nsufficient") {
                        Self::rpc_error(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, msg)
                    } else if msg.contains("address") {
                        Self::rpc_error(wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY, msg)
                    } else {
                        Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                    }
                })?
        };

        let txid = tx.txid();

        // Broadcast into the node mempool via the shared node handle (same
        // admission path as sendrawtransaction). Without this the signed tx
        // would never enter the mempool and never confirm. The node handle is
        // taken from WalletRpcState; release the WalletRpcState read-guard
        // first so we hold only the node write-lock during admission.
        let node = state.node.clone();
        drop(state);
        let node = node.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "wallet not wired to node mempool (sendtoaddress cannot broadcast)",
            )
        })?;
        {
            let mut node_state = node.write().await;
            crate::server::broadcast_signed_tx(&mut node_state, tx).map_err(|msg| {
                Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
            })?;
        }

        // Return the Core-style display txid (reversed).
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

        let (wallet_name, wallet) = self.resolve_wallet(&state)?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let count = count.unwrap_or(10);
        let skip = skip.unwrap_or(0);

        // Build one WalletTransaction per details[] line item across the
        // wallet's transaction history, mirroring Core's ListTransactions
        // (one entry per send recipient + one per received output). History is
        // recorded at block-connect time (Wallet::scan_block_at) so a SEND —
        // whose wallet UTXO was debited and removed from the live UTXO set —
        // is still reported. Confirmations + the coinbase generate/immature
        // split are recomputed against the current chain tip at read time.
        let mut transactions: Vec<WalletTransaction> = Vec::new();

        // Core orders listtransactions oldest-first then returns the LAST
        // `count` after skipping `skip` from the end (most-recent window). The
        // history Vec is already in block-connect (oldest-first) order; we emit
        // line items in that order, then apply the from-the-end pagination.
        for entry in wallet_guard.history() {
            let txid_hex =
                hex::encode(entry.txid.0.iter().rev().copied().collect::<Vec<_>>());
            let confirmations = wallet_guard.history_confirmations(entry) as i32;
            let generated = if entry.is_coinbase { Some(true) } else { None };
            let blockhash = if entry.block_hash == rustoshi_primitives::Hash256::ZERO {
                None
            } else {
                Some(hex::encode(
                    entry.block_hash.0.iter().rev().copied().collect::<Vec<_>>(),
                ))
            };
            let blocktime = if entry.block_time == 0 { None } else { Some(entry.block_time) };

            for d in &entry.details {
                // For a coinbase receive, refine generate -> immature when the
                // coinbase has not yet reached maturity at the current tip.
                let category = if entry.is_coinbase
                    && (d.category == "generate" || d.category == "receive")
                {
                    if wallet_guard.history_coinbase_is_mature(entry) {
                        "generate".to_string()
                    } else {
                        "immature".to_string()
                    }
                } else {
                    d.category.clone()
                };

                transactions.push(WalletTransaction {
                    address: d.address.clone(),
                    category,
                    amount: Self::sats_to_btc_signed(d.amount_sats),
                    label: None,
                    vout: Some(d.vout),
                    fee: d.fee_sats.map(Self::sats_to_btc_signed),
                    confirmations,
                    generated,
                    abandoned: Some(false),
                    blockhash: blockhash.clone(),
                    blockheight: Some(entry.block_height),
                    blockindex: None,
                    blocktime,
                    txid: txid_hex.clone(),
                    walletconflicts: vec![],
                    bip125_replaceable: "no".to_string(),
                    time: entry.block_time,
                    timereceived: entry.block_time,
                });
            }
        }

        // Most-recent window: skip `skip` from the END, then take `count`
        // (still oldest-first within the window), matching Core's
        // `nFrom`/`nCount` slicing over the oldest-first list.
        let total = transactions.len();
        let end = total.saturating_sub(skip);
        let start = end.saturating_sub(count);
        let transactions: Vec<WalletTransaction> =
            transactions[start..end].to_vec();

        tracing::debug!(
            "listtransactions for wallet {}: {} results",
            wallet_name,
            transactions.len()
        );
        Ok(transactions)
    }

    async fn get_transaction(
        &self,
        txid: String,
        _include_watchonly: Option<bool>,
        _verbose: Option<bool>,
    ) -> RpcResult<GetTransactionResult> {
        let state = self.state.read().await;

        let (_wallet_name, wallet) = self.resolve_wallet(&state)?;

        let wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let txid_internal = Self::parse_txid_hex(&txid)?;
        let entry = wallet_guard.history_entry(&txid_internal).ok_or_else(|| {
            // Core: "Invalid or non-wallet transaction id"
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "Invalid or non-wallet transaction id",
            )
        })?;

        // Net amount to the wallet = (credit - debit) - fee, mirroring Core's
        // `nNet - nFee` where nNet = nCredit - nDebit and the fee is only
        // counted when the wallet funded the tx.
        let net: i64 = entry.credit_sats as i64 - entry.debit_sats as i64;
        let fee_sats_signed: Option<i64> = entry.fee_sats.map(|f| -(f as i64));
        // Core: amount = nNet - nFee; nFee here is the positive fee, so
        // subtracting it from net (with fee>0 for a send) yields net - fee.
        let amount_sats = net - entry.fee_sats.map(|f| f as i64).unwrap_or(0);

        let confirmations = wallet_guard.history_confirmations(entry) as i32;
        let generated = if entry.is_coinbase { Some(true) } else { None };
        let blockhash = if entry.block_hash == rustoshi_primitives::Hash256::ZERO {
            None
        } else {
            Some(hex::encode(
                entry.block_hash.0.iter().rev().copied().collect::<Vec<_>>(),
            ))
        };
        let blocktime = if entry.block_time == 0 { None } else { Some(entry.block_time) };

        let details: Vec<TransactionDetail> = entry
            .details
            .iter()
            .map(|d| {
                let category = if entry.is_coinbase
                    && (d.category == "generate" || d.category == "receive")
                {
                    if wallet_guard.history_coinbase_is_mature(entry) {
                        "generate".to_string()
                    } else {
                        "immature".to_string()
                    }
                } else {
                    d.category.clone()
                };
                TransactionDetail {
                    address: d.address.clone(),
                    category,
                    amount: Self::sats_to_btc_signed(d.amount_sats),
                    vout: d.vout,
                    fee: d.fee_sats.map(Self::sats_to_btc_signed),
                }
            })
            .collect();

        let txid_hex =
            hex::encode(entry.txid.0.iter().rev().copied().collect::<Vec<_>>());

        Ok(GetTransactionResult {
            amount: Self::sats_to_btc_signed(amount_sats),
            fee: fee_sats_signed.map(Self::sats_to_btc_signed),
            confirmations,
            generated,
            blockhash,
            blockheight: Some(entry.block_height),
            blocktime,
            txid: txid_hex,
            walletconflicts: vec![],
            bip125_replaceable: "no".to_string(),
            time: entry.block_time,
            timereceived: entry.block_time,
            details,
            hex: hex::encode(&entry.raw_tx),
        })
    }

    async fn get_wallet_info(&self) -> RpcResult<WalletInfo> {
        let state = self.state.read().await;

        let (wallet_name, wallet) = self.resolve_wallet(&state)?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let balance = Self::sats_to_btc(wallet_guard.confirmed_balance());
        let unconfirmed_balance = Self::sats_to_btc(wallet_guard.unconfirmed_balance());
        let immature_balance = Self::sats_to_btc(wallet_guard.immature_balance());
        let tx_count = wallet_guard.list_unspent().len(); // Approximation
        // Core: private_keys_enabled = !IsWalletFlagSet(
        // WALLET_FLAG_DISABLE_PRIVATE_KEYS) (wallet/rpc/wallet.cpp:50,98).
        let private_keys_enabled = wallet_guard.private_keys_enabled();

        Ok(WalletInfo {
            walletname: wallet_name,
            walletversion: 169900,
            format: "sqlite".to_string(),
            balance,
            unconfirmed_balance,
            immature_balance,
            txcount: tx_count,
            keypoololdest: 0,
            keypoolsize: if private_keys_enabled { 1000 } else { 0 },
            keypoolsize_hd_internal: if private_keys_enabled {
                Some(1000)
            } else {
                Some(0)
            },
            paytxfee: 0.0,
            hdseedid: None,
            private_keys_enabled,
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

        let (name, wallet) = self.resolve_wallet(&state)?;

        // P0-SECURITY gate (W118 BUG-1): signing requires an unlocked wallet.
        Self::require_unlocked(&state, &name)?;

        let wallet_guard = wallet.lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // Watch-only wallets cannot sign (Core: private keys disabled -> -4).
        if !wallet_guard.private_keys_enabled() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "Error: Private keys are disabled for this wallet",
            ));
        }

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

    async fn sign_raw_transaction_with_key(
        &self,
        hexstring: String,
        privkeys: Vec<String>,
        prevtxs: Option<Vec<PrevTx>>,
        sighashtype: Option<String>,
    ) -> RpcResult<SignRawTransactionResult> {
        use rustoshi_primitives::{Decodable, Encodable, Hash256, OutPoint, Transaction};
        use rustoshi_wallet::{KeySigner, WalletUtxo};

        // No wallet needed — Core's signrawtransactionwithkey builds a
        // temporary FillableSigningProvider from the explicit keys. We DO
        // borrow the active network from the wallet manager so WIF version
        // bytes are validated against the right network (Core DecodeSecret).
        let network = {
            let state = self.state.read().await;
            state.wallet_manager.network()
        };

        // Sighash type — the per-script signers currently emit SIGHASH_ALL
        // (0x01) / SIGHASH_DEFAULT for taproot. Refuse anything else honestly
        // rather than silently signing ALL (same contract as
        // signrawtransactionwithwallet).
        let sighash_type_str = sighashtype.as_deref().unwrap_or("ALL");
        if !matches!(sighash_type_str, "ALL" | "DEFAULT") {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                format!(
                    "sighashtype {:?} not yet supported (only ALL/DEFAULT)",
                    sighash_type_str
                ),
            ));
        }

        // Decode the raw transaction.
        let tx_bytes = hex::decode(&hexstring).map_err(|e| {
            Self::rpc_error(wallet_error::RPC_DESERIALIZATION_ERROR, format!("Invalid hex: {}", e))
        })?;
        let mut tx = Transaction::deserialize(&tx_bytes).map_err(|e| {
            Self::rpc_error(
                wallet_error::RPC_DESERIALIZATION_ERROR,
                format!("TX decode failed: {}", e),
            )
        })?;

        // Build the temporary keystore from the explicit WIF keys (Core's
        // FillableSigningProvider). `KeySigner` validates each WIF against the
        // network and registers the standard single-key scriptPubKeys each key
        // controls; an invalid WIF is a hard -5 error.
        let key_signer = KeySigner::from_wifs(&privkeys, network).map_err(|e| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                format!("Invalid private key: {}", e),
            )
        })?;

        // Merge prevout info from the prevtxs array, keyed by outpoint. Each
        // entry carries the scriptPubKey (script type) + amount (BIP-143/341
        // sighash). redeemScript / witnessScript are accepted but only the
        // single-key script shapes are signable here.
        let mut prevout_info: std::collections::HashMap<OutPoint, (Vec<u8>, u64)> =
            std::collections::HashMap::new();
        if let Some(list) = &prevtxs {
            for p in list {
                let txid_bytes = hex::decode(&p.txid).map_err(|_| {
                    Self::rpc_error(
                        wallet_error::RPC_DESERIALIZATION_ERROR,
                        format!("prevtx txid is not valid hex: {}", p.txid),
                    )
                })?;
                if txid_bytes.len() != 32 {
                    return Err(Self::rpc_error(
                        wallet_error::RPC_DESERIALIZATION_ERROR,
                        format!("prevtx txid must be 32 bytes: {}", p.txid),
                    ));
                }
                // RPC txids are big-endian display order; internal is reversed.
                let mut internal = txid_bytes;
                internal.reverse();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&internal);
                let spk = hex::decode(&p.script_pubkey).map_err(|_| {
                    Self::rpc_error(
                        wallet_error::RPC_DESERIALIZATION_ERROR,
                        format!("prevtx scriptPubKey is not valid hex (vout {})", p.vout),
                    )
                })?;
                // BTC amount -> satoshis (Core AmountFromValue). 0 if omitted.
                let value = match p.amount {
                    Some(a) => (a * 1e8).round() as u64,
                    None => 0,
                };
                prevout_info.insert(
                    OutPoint { txid: Hash256(arr), vout: p.vout },
                    (spk, value),
                );
            }
        }

        // Assemble per-input prevout UTXOs (in spend order) for the BIP-341
        // sighash, which needs EVERY input's prevout. Missing entries become a
        // zeroed placeholder; an input with no prevout info is reported as an
        // error rather than signed.
        let placeholder = WalletUtxo {
            outpoint: OutPoint { txid: Hash256([0u8; 32]), vout: 0 },
            value: 0,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 0,
            is_change: false,
            is_coinbase: false,
            height: None,
        };
        let mut all_prevouts: Vec<WalletUtxo> = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            match prevout_info.get(&input.previous_output) {
                Some((spk, value)) => all_prevouts.push(WalletUtxo {
                    outpoint: input.previous_output.clone(),
                    value: *value,
                    script_pubkey: spk.clone(),
                    derivation_path: vec![],
                    confirmations: 0,
                    is_change: false,
                    is_coinbase: false,
                    height: None,
                }),
                None => all_prevouts.push(placeholder.clone()),
            }
        }

        // Snapshot per-input metadata for error rows before &mut tx is handed
        // to the signer (Core TransactionError shape: txid/vout/scriptSig/
        // sequence/error, plus witness).
        let input_meta: Vec<(String, u32, u32, bool)> = tx
            .inputs
            .iter()
            .map(|inp| {
                let txid_hex = hex::encode(
                    inp.previous_output.txid.0.iter().rev().copied().collect::<Vec<_>>(),
                );
                let has_prevout = prevout_info.contains_key(&inp.previous_output);
                (txid_hex, inp.previous_output.vout, inp.sequence, has_prevout)
            })
            .collect();

        let mut errors: Vec<SigningError> = Vec::new();

        for i in 0..tx.inputs.len() {
            let (txid_hex, vout, sequence, has_prevout) = input_meta[i].clone();
            let prevout = all_prevouts[i].clone();

            if !has_prevout {
                errors.push(SigningError {
                    txid: txid_hex,
                    vout,
                    script_sig: hex::encode(&tx.inputs[i].script_sig),
                    sequence,
                    error: "Input not found or already spent".to_string(),
                });
                continue;
            }

            // No provided key controls this prevout's scriptPubKey -> leave the
            // input unsigned and report it (Core: input stays incomplete).
            if !key_signer.can_sign(&prevout.script_pubkey) {
                errors.push(SigningError {
                    txid: txid_hex,
                    vout,
                    script_sig: hex::encode(&tx.inputs[i].script_sig),
                    sequence,
                    error: "Unable to sign input, missing private key for scriptPubKey"
                        .to_string(),
                });
                continue;
            }

            if let Err(e) = key_signer.sign_input(&mut tx, i, &prevout, &all_prevouts) {
                errors.push(SigningError {
                    txid: txid_hex,
                    vout,
                    script_sig: hex::encode(&tx.inputs[i].script_sig),
                    sequence,
                    error: format!("Signing failed: {}", e),
                });
            }
        }

        // complete is true ONLY when every input was signed without error
        // (Core: SignTransaction sets complete = all inputs have a complete
        // SignatureData). Never fabricate completeness.
        let complete = errors.is_empty();

        let signed_hex = hex::encode(&tx.serialize());

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
        let state = self.state.read().await;
        let (wallet_name, wallet) = self.resolve_wallet(&state)?;

        // Core validates the timestamp per request via GetImportTimestamp
        // (backup.cpp:127-139) and a missing/mistyped timestamp is a
        // TOP-LEVEL throw (-3), unlike every other per-element failure.
        let mut timestamps: Vec<Option<u64>> = Vec::with_capacity(requests.len());
        for request in &requests {
            timestamps.push(Self::parse_import_timestamp(&request.timestamp)?);
        }

        let mut results: Vec<crate::types::ImportDescriptorResult> = Vec::new();
        // Persisted rows for successful imports: (canonical, label, ts, range_end).
        let mut persisted: Vec<(String, String, u64, u32)> = Vec::new();
        // Lowest NUMERIC timestamp across requests (clamped to min 1, Core
        // backup.cpp:376,390). u64::MAX = "every request said now" → no scan.
        let mut lowest_timestamp: u64 = u64::MAX;
        let mut any_success = false;

        {
            let mut wallet_guard = wallet.lock().map_err(|_| {
                Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet")
            })?;

            for (request, ts) in requests.iter().zip(timestamps.iter()) {
                match Self::process_descriptor_import(&mut wallet_guard, request) {
                    Ok((canonical, label, range_end, warnings)) => {
                        results.push(crate::types::ImportDescriptorResult {
                            success: true,
                            warnings: if warnings.is_empty() { None } else { Some(warnings) },
                            error: None,
                        });
                        any_success = true;
                        // Clamp numeric timestamps to minimum 1 (Core's
                        // minimum_timestamp, backup.cpp:376); 0/1 both mean
                        // "scan from genesis".
                        if let Some(t) = ts {
                            lowest_timestamp = lowest_timestamp.min((*t).max(1));
                        }
                        persisted.push((canonical, label, ts.unwrap_or(0), range_end));
                    }
                    Err((code, message)) => {
                        // Per-element embedded error (Core catches the throw
                        // and pushes {"success":false,"error":{...}} —
                        // backup.cpp:293-297).
                        results.push(crate::types::ImportDescriptorResult {
                            success: false,
                            warnings: None,
                            error: Some(crate::types::ImportDescriptorError { code, message }),
                        });
                    }
                }
            }
        }

        // Capture the handles the rescan needs, then RELEASE the wallet-state
        // guard before touching the node state: the block-connect path takes
        // node-write THEN wallet-state, so holding wallet-state while waiting
        // on a node lock would invert the order (same discipline as
        // send_to_address).
        let db_arc = state.wallet_manager.get_wallet_db(&wallet_name);
        let node = state.node.clone();
        drop(state);

        // Persist the imported descriptors so the watch set survives
        // loadwallet (re-registered by WalletManager::load_wallet).
        if let Some(db) = &db_arc {
            if let Ok(db_guard) = db.lock() {
                for (canonical, label, ts, range_end) in &persisted {
                    if let Err(e) = db_guard.save_descriptor(canonical, label, *ts, *range_end) {
                        tracing::warn!("importdescriptors: failed to persist '{canonical}': {e}");
                    }
                }
            }
        }

        // Synchronous rescan from the lowest timestamp (Core RescanFromTime,
        // backup.cpp:408-414 + wallet.cpp:1827-1848): runs whenever at least
        // one element succeeded, scanning from the first block whose time is
        // >= lowest_timestamp - TIMESTAMP_WINDOW (7200s, chain.h:37) — which
        // is genesis for timestamp <= 1. Blocking the RPC until the scan
        // finishes matches Core's behaviour (importdescriptors returns only
        // after its rescan). On a large chain with timestamp 0 this walks
        // every block — same cost Core pays.
        if any_success && lowest_timestamp != u64::MAX {
            let Some(node) = node else {
                tracing::warn!(
                    "importdescriptors: wallet not wired to a node; imported descriptors \
                     are registered but NOT rescanned (pre-existing funds will not be \
                     credited until a restart reconcile)"
                );
                return Ok(results);
            };
            let (tip_height, chain_db) = {
                let st = node.read().await;
                (st.best_height, st.db.clone())
            };
            if tip_height > 0 || lowest_timestamp <= 1 {
                // First block to scan: time >= lowest - TIMESTAMP_WINDOW.
                let threshold = lowest_timestamp.saturating_sub(7200);
                let wallet_arc = wallet.clone();
                let scan = tokio::task::spawn_blocking(move || -> Result<u32, String> {
                    let store = BlockStore::new(&chain_db);
                    let mut started = threshold == 0;
                    let mut last_scanned = 0u32;
                    for h in 0..=tip_height {
                        let hash = match store.get_hash_by_height(h) {
                            Ok(Some(hash)) => hash,
                            Ok(None) => break,
                            Err(e) => return Err(e.to_string()),
                        };
                        let block = match store.get_block(&hash) {
                            Ok(Some(b)) => b,
                            Ok(None) => break,
                            Err(e) => return Err(e.to_string()),
                        };
                        let block_time = block.header.timestamp as u64;
                        if !started && block_time >= threshold {
                            // Core CChain::FindEarliestAtLeast: scan starts at
                            // the FIRST block at/after the window and never
                            // stops again on later (non-monotonic) dips.
                            started = true;
                        }
                        if started {
                            if let Ok(mut w) = wallet_arc.lock() {
                                w.scan_block_at(&block.transactions, h, hash, block_time);
                            }
                            last_scanned = h;
                        }
                    }
                    Ok(last_scanned)
                })
                .await;
                match scan {
                    Ok(Ok(last_scanned)) => {
                        // Persist the advanced watermark + refresh durable
                        // confirmations against the tip.
                        if let Some(db) = &db_arc {
                            if let Ok(db_guard) = db.lock() {
                                // Never regress a previously-higher watermark
                                // (a gap-truncated rescan must not force a
                                // future full re-walk of already-synced range).
                                let prior = db_guard
                                    .get_last_synced_height()
                                    .ok()
                                    .flatten()
                                    .unwrap_or(0);
                                let _ = db_guard.set_last_synced_height(last_scanned.max(prior));
                                let _ = db_guard.recompute_confirmations(tip_height);
                            }
                        }
                        // Make sure the in-memory maturity view reaches tip
                        // even if the walk stopped early.
                        if let Ok(mut w) = wallet.lock() {
                            if w.chain_height() < tip_height {
                                w.set_chain_height(tip_height);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("importdescriptors rescan failed: {e}");
                    }
                    Err(e) => {
                        tracing::warn!("importdescriptors rescan task panicked: {e}");
                    }
                }
            }
        }

        Ok(results)
    }

    async fn get_address_info(&self, address: String) -> RpcResult<serde_json::Value> {
        use rustoshi_crypto::address::Address;
        use serde_json::json;

        let state = self.state.read().await;
        let (_wallet_name, wallet) = self.resolve_wallet(&state)?;
        let network = state.wallet_manager.network();

        // Core: invalid address -> -5 with DecodeDestination's reason or
        // "Invalid address" (addresses.cpp:434-439).
        let addr = Address::from_string(&address, Some(network)).map_err(|_| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "Invalid address",
            )
        })?;
        let spk = addr.to_script_pubkey();

        let wallet_guard = wallet.lock().map_err(|_| {
            Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet")
        })?;

        let watched = wallet_guard.watched_script(&spk).cloned();
        // ismine covers HD addresses (incl. lookahead), imported keys, and
        // watched descriptor scripts — TRUE for watch-only descriptor
        // matches (descriptor wallets have no ismine/iswatchonly split;
        // probe-confirmed shape A3 of the parity study).
        let ismine = wallet_guard.is_mine_script(&spk);
        let hd_path: Option<Vec<u32>> = wallet_guard.get_derivation_path(&address).cloned();
        // Watched scripts carry their descriptor's solvability (false for
        // addr()/raw()); HD-owned addresses are solvable.
        let solvable = match &watched {
            Some(w) => w.solvable,
            None => ismine,
        };

        // Field emission order mirrors Core addresses.cpp:441-510
        // (serde_json preserve_order keeps insertion order on the wire).
        let mut obj = serde_json::Map::new();
        obj.insert("address".into(), json!(address));
        obj.insert("scriptPubKey".into(), json!(hex::encode(&spk)));
        obj.insert("ismine".into(), json!(ismine));
        obj.insert("solvable".into(), json!(solvable));
        // desc — ONLY when solvable (addresses.cpp:454-463). Best-effort:
        // emitted for single-key descriptors whose pubkey is recorded.
        if solvable {
            if let Some(pk) = watched.as_ref().and_then(|w| w.pubkey.as_ref()) {
                let body = match &addr {
                    Address::P2WPKH { .. } => Some(format!("wpkh({})", hex::encode(pk))),
                    Address::P2PKH { .. } => Some(format!("pkh({})", hex::encode(pk))),
                    _ => None,
                };
                if let Some(desc) =
                    body.and_then(|b| rustoshi_wallet::descriptor::add_checksum(&b))
                {
                    obj.insert("desc".into(), json!(desc));
                }
            }
        }
        if let Some(w) = &watched {
            // The wallet descriptor this address belongs to
            // (addresses.cpp:465-476).
            obj.insert("parent_desc".into(), json!(w.descriptor));
        }
        // DEPRECATED, hardcoded false (addresses.cpp:383,478).
        obj.insert("iswatchonly".into(), json!(false));
        let isscript = matches!(addr, Address::P2SH { .. } | Address::P2WSH { .. });
        obj.insert("isscript".into(), json!(isscript));
        let witness: Option<(u8, Vec<u8>)> = match &addr {
            Address::P2WPKH { hash, .. } => Some((0, hash.0.to_vec())),
            Address::P2WSH { hash, .. } => Some((0, hash.0.to_vec())),
            Address::P2TR { output_key, .. } => Some((1, output_key.to_vec())),
            _ => None,
        };
        obj.insert("iswitness".into(), json!(witness.is_some()));
        if let Some((ver, prog)) = &witness {
            obj.insert("witness_version".into(), json!(ver));
            obj.insert("witness_program".into(), json!(hex::encode(prog)));
        }
        if let Some(pk) = watched.as_ref().and_then(|w| w.pubkey.as_ref()) {
            obj.insert("pubkey".into(), json!(hex::encode(pk)));
        }
        let ischange = hd_path
            .as_ref()
            .map(|p| p.get(3).copied() == Some(1))
            .unwrap_or(false);
        obj.insert("ischange".into(), json!(ischange));
        // labels: mine -> [label-or-empty], not-mine -> []
        // (addresses.cpp:503-508).
        let labels: Vec<String> = if ismine {
            vec![watched
                .as_ref()
                .map(|w| w.label.clone())
                .unwrap_or_default()]
        } else {
            Vec::new()
        };
        obj.insert("labels".into(), json!(labels));

        Ok(serde_json::Value::Object(obj))
    }

    async fn set_hd_seed(
        &self,
        _newkeypool: Option<bool>,
        seed: Option<String>,
    ) -> RpcResult<serde_json::Value> {
        // Require an explicit seed: this RPC is rustoshi's deterministic
        // restore path, so an absent seed is a usage error rather than
        // "generate a fresh random one" (which `createwallet` already does).
        let seed_hex = seed.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "sethdseed requires a 64-byte (128 hex char) master seed for deterministic restore",
            )
        })?;
        let seed_bytes = hex::decode(seed_hex.trim()).map_err(|_| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                "seed must be valid hex",
            )
        })?;
        if seed_bytes.len() != 64 {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                format!("seed must be 64 bytes (128 hex chars), got {}", seed_bytes.len()),
            ));
        }

        let mut state = self.state.write().await;

        // Resolve the target wallet name (URL-pinned, or the single default).
        let (name, _wallet) = self.resolve_wallet(&state)?;

        state
            .wallet_manager
            .set_hd_seed(&name, &seed_bytes)
            .map_err(|e| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e.to_string()))?;

        // Report the HD seed fingerprint so callers can confirm which seed is
        // active. The fingerprint is the first 4 bytes of HASH160(master
        // pubkey); we reuse the freshly-restored wallet to peek address 0,
        // but the simplest stable identifier we can return without exposing
        // key material is the first 4 bytes of the seed's SHA256 — purely an
        // opaque "which seed" tag, not consensus-relevant.
        use sha2::{Digest, Sha256};
        let tag = Sha256::digest(&seed_bytes);
        Ok(serde_json::json!(hex::encode(&tag[..4])))
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
        let (_, wallet) = self.resolve_wallet(&state)?;

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
        let (_, wallet) = self.resolve_wallet(&state)?;

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
        let (_, wallet) = self.resolve_wallet(&state)?;
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

    // -----------------------------------------------------------------------
    // walletprocesspsbt
    //
    // Reference: `bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt`
    // (v31.99). Decodes the base64 PSBT, runs CWallet::FillPSBT in the
    // Updater (fill UTXO/scripts/bip32 derivs) + Signer (sign=true default)
    // + Finalizer (finalize=true default) roles, then returns
    //   { psbt, complete }  (+ hex when complete).
    //
    // ⭐ ENGINE REUSE: the actual sighash + ECDSA/Schnorr signing is done by
    // `Wallet::sign_input` — the SAME path `signrawtransactionwithwallet`
    // (sign_raw_transaction_with_wallet, this file) drives, which itself
    // dispatches to the BIP-143 (`segwit_v0_sighash`) / BIP-341
    // (`sign_p2tr_input`) / legacy sighash signers in
    // `crates/wallet/src/wallet.rs`. We do NOT reimplement sighash or
    // signing here. sign_input produces FINAL scriptSig/witness; we graft
    // those into the PSBT's final_script_sig / final_script_witness, which
    // is exactly the Finalizer outcome (Core's finalize=true default).
    // -----------------------------------------------------------------------
    async fn wallet_process_psbt(
        &self,
        psbt: String,
        sign: Option<bool>,
        sighashtype: Option<String>,
        bip32derivs: Option<bool>,
        finalize: Option<bool>,
    ) -> RpcResult<WalletProcessPsbtResult> {
        use rustoshi_primitives::{Encodable, TxOut};
        use rustoshi_wallet::{Psbt, WalletUtxo};

        let sign = sign.unwrap_or(true);
        let bip32derivs = bip32derivs.unwrap_or(true);
        // Note: `finalize` defaults true (Core). Our signer produces final
        // scripts directly, so when finalize=false we keep the produced
        // signature OUT of the final_script_* fields and instead record it as
        // a partial_sig, leaving the PSBT un-finalized (complete=false).
        let finalize = finalize.unwrap_or(true);

        // Sighash type — the wallet signer currently honours SIGHASH_ALL only
        // (same constraint as signrawtransactionwithwallet); refuse other
        // types honestly rather than silently signing ALL.
        let sighash_type_str = sighashtype.as_deref().unwrap_or("ALL");
        if !matches!(sighash_type_str, "ALL" | "DEFAULT" | "ALL|ANYONECANPAY") {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                format!(
                    "sighashtype {:?} not yet supported (only ALL/DEFAULT)",
                    sighash_type_str
                ),
            ));
        }

        // Decode the base64 PSBT (Core: DecodeBase64PSBT -> RPC_DESERIALIZATION_ERROR -22).
        let mut psbt = Psbt::from_base64(&psbt).map_err(|e| {
            Self::rpc_error(
                wallet_error::RPC_DESERIALIZATION_ERROR,
                format!("TX decode failed {}", e),
            )
        })?;

        let state = self.state.read().await;
        let (name, wallet) = self.resolve_wallet(&state)?;

        // Core: `if (sign) EnsureWalletIsUnlocked(...)`.
        if sign {
            Self::require_unlocked(&state, &name)?;
        }

        let wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let num_inputs = psbt.unsigned_tx.inputs.len();

        // For each input, look up whether the wallet owns the spent UTXO.
        // (None = foreign input, the wallet cannot fill/sign it.)
        let prev_utxos: Vec<Option<WalletUtxo>> = psbt
            .unsigned_tx
            .inputs
            .iter()
            .map(|input| wallet_guard.get_utxo(&input.previous_output).cloned())
            .collect();

        // BIP-341 sighash needs every input's prevout. Build the parallel
        // Vec<WalletUtxo> the signer expects; missing entries are placeholders
        // we never read for a missing input (Taproot inputs are gated below).
        let any_missing = prev_utxos.iter().any(|u| u.is_none());
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

        // ============================================================
        // Updater role — fill witness_utxo / scripts / bip32 derivs.
        // ============================================================
        for i in 0..num_inputs {
            let Some(utxo) = &prev_utxos[i] else { continue };
            let spk = utxo.script_pubkey.clone();

            // Provide the spent output as a witness_utxo for segwit inputs
            // (P2WPKH/P2WSH/P2TR/P2SH-wrapped-segwit). For pure-legacy P2PKH
            // Core would attach a non_witness_utxo (full prev tx), which the
            // wallet does not retain — but the legacy signer reads scriptPubKey
            // + value directly from the wallet UTXO, so signing still works.
            let is_segwit = (spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14) // P2WPKH
                || (spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20) // P2WSH
                || (spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20) // P2TR
                || (spk.len() == 23 && spk[0] == 0xa9 && spk[2] == 0x14); // P2SH (may wrap segwit)
            if is_segwit && psbt.inputs[i].witness_utxo.is_none() {
                let _ = psbt.set_witness_utxo(
                    i,
                    TxOut {
                        value: utxo.value,
                        script_pubkey: spk.clone(),
                    },
                );
            }

            // BIP-32 derivation record (genuine pubkey + master-fingerprint
            // origin, derived via the same HD engine the signer uses).
            if bip32derivs {
                if let Ok((pubkey, origin)) =
                    wallet_guard.pubkey_and_origin(&utxo.derivation_path)
                {
                    let _ = psbt.add_input_derivation(i, pubkey, origin);
                }
            }
        }

        // ============================================================
        // Signer role — sign every wallet-owned input.
        // ============================================================
        // `complete` starts true (Core: `bool complete = true;`) and is
        // cleared whenever an input cannot be fully signed + finalized.
        let mut complete = num_inputs > 0;

        if sign {
            for i in 0..num_inputs {
                // Already finalized by a prior round: counts as done.
                if psbt.inputs[i].is_finalized() {
                    continue;
                }

                let Some(utxo) = &prev_utxos[i] else {
                    // Foreign input — wallet has no key, cannot complete.
                    complete = false;
                    continue;
                };

                // Taproot guard: BIP-341 sighash for THIS input needs every
                // other input's prevout. If any is missing we cannot produce a
                // correct sighash, so don't sign (and the PSBT stays incomplete).
                let spk = &utxo.script_pubkey;
                let is_tr = spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20;
                if is_tr && any_missing {
                    complete = false;
                    continue;
                }

                // Sign into a scratch tx via the SAME engine
                // signrawtransactionwithwallet uses (sign_input).
                let mut scratch = psbt.unsigned_tx.clone();
                match wallet_guard.sign_input(&mut scratch, i, &all_prev_utxos) {
                    Ok(()) => {
                        let signed_in = &scratch.inputs[i];
                        if finalize {
                            // Finalizer role: graft the produced FINAL
                            // scriptSig/witness onto the PSBT input.
                            if !signed_in.script_sig.is_empty() {
                                psbt.inputs[i].final_script_sig =
                                    Some(signed_in.script_sig.clone());
                            }
                            if !signed_in.witness.is_empty() {
                                psbt.inputs[i].final_script_witness =
                                    Some(signed_in.witness.clone());
                            }
                            if !psbt.inputs[i].is_finalized() {
                                complete = false;
                            }
                        } else {
                            // sign=true, finalize=false: record a partial sig
                            // and leave the input un-finalized (Core returns a
                            // signed-but-not-finalized PSBT, complete=false).
                            // Extract (pubkey, sig) from the produced witness /
                            // scriptSig single-sig shapes (P2WPKH / P2PKH /
                            // P2SH-P2WPKH).
                            let extracted = extract_single_partial_sig(signed_in);
                            if let Some((pk, sig)) = extracted {
                                psbt.inputs[i].partial_sigs.insert(pk, sig);
                            }
                            complete = false;
                        }
                    }
                    Err(_) => {
                        complete = false;
                    }
                }
            }
        } else {
            // sign=false: Updater/Finalizer only. complete only if every input
            // is already finalized in the input PSBT.
            for i in 0..num_inputs {
                if finalize {
                    let _ = psbt.finalize_input(i);
                }
                if !psbt.inputs[i].is_finalized() {
                    complete = false;
                }
            }
        }

        // ============================================================
        // Build result: { psbt, complete } (+ hex when complete).
        // ============================================================
        let mut hex = None;
        if complete {
            // Core: FinalizeAndExtractPSBT -> serialize the network tx.
            if let Ok(final_tx) = psbt.extract_tx() {
                hex = Some(hex::encode(final_tx.serialize()));
            } else {
                // Should not happen if complete is true; degrade honestly.
                complete = false;
            }
        }

        Ok(WalletProcessPsbtResult {
            psbt: psbt.to_base64(),
            complete,
            hex,
        })
    }

    // -----------------------------------------------------------------------
    // fundrawtransaction
    //
    // Reference: `bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction`
    // (line 706) + `FundTransaction` (line 470).
    //
    // Core's flow:
    //   1. DecodeHexTx(hexstring) -> CMutableTransaction
    //   2. Treat tx.vout as the recipients, clear tx.vout, set
    //      coin_control.m_allow_other_inputs = true
    //   3. FundTransaction() -> the SAME CreateTransaction coin-selection
    //      engine that backs walletcreatefundedpsbt; adds inputs + at most one
    //      change output, keeping existing inputs/outputs
    //   4. result = { hex: EncodeHexTx(txr.tx), fee, changepos }
    //
    // We mirror this by REUSING `Wallet::create_transaction` — the exact
    // selector the no-inputs path of `wallet_create_funded_psbt` above calls.
    // We feed it the decoded tx's existing outputs as recipients, take the
    // inputs it selected + the change output it created, and graft them onto
    // the decoded tx's existing inputs/outputs (existing outputs are preserved
    // byte-identical, matching Core's "No existing outputs will be modified").
    // The funded tx is then serialised back to hex (vs. the PSBT wrapping the
    // sibling does). Coin selection / change / fee are NOT reimplemented.
    // -----------------------------------------------------------------------
    async fn fund_raw_transaction(
        &self,
        hexstring: String,
        options: Option<FundRawTransactionOptions>,
        _iswitness: Option<bool>,
    ) -> RpcResult<FundRawTransactionResult> {
        use rustoshi_primitives::{Encodable, TxOut};
        use rustoshi_crypto::address::{Address, Network};

        let opts = options.unwrap_or_default();

        // --- Fee rate resolution (Core: feeRate is BTC/kvB, fee_rate is
        // sat/vB; cannot specify both). Default mirrors create_transaction's
        // sibling path (2 sat/vB). ---
        if opts.fee_rate.is_some() && opts.fee_rate_btc_kvb.is_some() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "Cannot specify both fee_rate (sat/vB) and feeRate (BTC/kvB)",
            ));
        }
        let fee_rate_sat_vb = if let Some(r) = opts.fee_rate {
            r
        } else if let Some(btc_kvb) = opts.fee_rate_btc_kvb {
            // BTC/kvB -> sat/vB: btc_kvb * 1e8 sat per kvB / 1000 vB per kvB.
            (btc_kvb * 100_000_000.0) / 1000.0
        } else {
            2.0
        };
        if fee_rate_sat_vb <= 0.0 {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "fee rate must be positive",
            ));
        }

        // --- Decode the raw transaction hex (Core: DecodeHexTx). Uses the
        // try-witness-then-no-witness heuristic so a zero-input tx (the exact
        // "fund me" shape) decodes correctly despite the SegWit-marker
        // ambiguity. Honours the `iswitness` hint. ---
        let tx_bytes = hex::decode(hexstring.trim()).map_err(|e| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                format!("TX decode failed: invalid hex: {}", e),
            )
        })?;
        let decoded = Self::decode_raw_tx_heuristic(&tx_bytes, _iswitness).map_err(|e| {
            Self::rpc_error(wallet_error::RPC_WALLET_ERROR, e)
        })?;

        // subtractFeeFromOutputs / changeAddress are not yet wired through the
        // shared selector (it owns change-address generation and fee
        // placement). Refuse honestly rather than silently ignore, matching
        // the walletcreatefundedpsbt sibling's stance.
        if opts.subtract_fee_from_outputs.is_some() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "options.subtractFeeFromOutputs is not yet supported",
            ));
        }

        let state = self.state.read().await;
        let (_, wallet) = self.resolve_wallet(&state)?;
        let net = state.wallet_manager.network();
        let net_param = match net {
            Network::Mainnet => Network::Mainnet,
            Network::Testnet => Network::Testnet,
            Network::Regtest => Network::Regtest,
        };

        // --- Map the decoded tx's existing outputs into the recipient form
        // the selector expects: (address_string, value_sats). The selector
        // rebuilds these into outputs internally; we then discard its rebuilt
        // recipient outputs and keep the ORIGINAL decoded outputs byte-for-byte
        // (so non-standard scripts and exact values survive untouched). The
        // recipient round-trip exists only to drive the selector's target.
        let mut recipients: Vec<(String, u64)> = Vec::with_capacity(decoded.outputs.len());
        for (i, out) in decoded.outputs.iter().enumerate() {
            let addr = Address::from_script_pubkey(&out.script_pubkey, net_param).ok_or_else(|| {
                Self::rpc_error(
                    wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                    format!(
                        "output {} has a non-standard script that cannot be funded (fundrawtransaction requires standard outputs to estimate fees)",
                        i
                    ),
                )
            })?;
            recipients.push((addr.to_string(), out.value));
        }
        if recipients.is_empty() {
            // Core funds a tx that has no outputs by funding fee-only; rustoshi's
            // selector needs a positive target. Honestly refuse the empty case.
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "raw transaction has no outputs to fund",
            ));
        }

        // --- Reuse the shared coin-selection engine. This is the SAME
        // `Wallet::create_transaction` that walletcreatefundedpsbt's
        // no-inputs path calls (crates/rpc/src/wallet.rs ~line 2768). ---
        let mut wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        let selected = wallet_guard
            .create_transaction(recipients.clone(), fee_rate_sat_vb)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("insufficient") || msg.contains("Insufficient") {
                    Self::rpc_error(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, msg)
                } else if msg.contains("address") || msg.contains("Address") {
                    Self::rpc_error(wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY, msg)
                } else {
                    Self::rpc_error(wallet_error::RPC_WALLET_ERROR, msg)
                }
            })?;

        // The selector returns inputs[selected] and
        // outputs = [recipients..., change?] (change appended last, only when
        // economic — see Wallet::create_transaction). Recover the change
        // output (if any) by position: anything past the recipient count.
        let change_output: Option<TxOut> = if selected.outputs.len() > recipients.len() {
            // Exactly one change output, appended last.
            selected.outputs.last().cloned()
        } else {
            None
        };

        // --- Graft selected inputs + change onto the ORIGINAL decoded tx.
        // Existing inputs/outputs preserved exactly (Core: existing inputs
        // kept, "No existing outputs will be modified"). The selector's inputs
        // are stripped of script_sig/witness (fundrawtransaction returns an
        // UNSIGNED funded tx — Core: "The inputs added will not be signed").
        let rbf = opts.replaceable.unwrap_or(true);
        let default_sequence: u32 = if rbf {
            0xFFFFFFFD // MAX_BIP125_RBF_SEQUENCE
        } else if decoded.lock_time != 0 {
            0xFFFFFFFE // MAX_SEQUENCE_NONFINAL
        } else {
            0xFFFFFFFF // SEQUENCE_FINAL
        };

        let mut funded = decoded.clone();
        for sin in &selected.inputs {
            funded.inputs.push(rustoshi_primitives::TxIn {
                previous_output: sin.previous_output.clone(),
                script_sig: vec![],
                sequence: default_sequence,
                witness: vec![],
            });
        }

        // Insert the change output. Default position = appended last; honour
        // changePosition if in-bounds (Core: change_position, default random —
        // we default to deterministic append). changeAddress override would
        // require the selector to accept a destination; refuse it honestly so
        // the returned changepos is never a lie.
        let mut changepos: i32 = -1;
        if let Some(mut change) = change_output {
            // If a changeAddress was requested, re-point the selector-created
            // change output's script at it (value unchanged — the selector
            // already sized it). This is a faithful override: the amount is
            // still the genuine computed change.
            if let Some(change_addr_str) = &opts.change_address {
                let change_addr = Address::from_string(change_addr_str, Some(net_param)).map_err(|e| {
                    Self::rpc_error(
                        wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY,
                        format!("Change address must be a valid bitcoin address: {}", e),
                    )
                })?;
                change.script_pubkey = change_addr.to_script_pubkey();
            }
            let insert_at = match opts.change_position {
                Some(want) => {
                    let want = want as usize;
                    if want > funded.outputs.len() {
                        return Err(Self::rpc_error(
                            wallet_error::RPC_WALLET_ERROR,
                            "changePosition out of bounds",
                        ));
                    }
                    want
                }
                None => funded.outputs.len(),
            };
            funded.outputs.insert(insert_at, change);
            changepos = insert_at as i32;
        }

        // --- Genuine fee = sum(all input values) - sum(all output values).
        // Sum every input's value from the wallet UTXO set (the funded tx is
        // built only from wallet-selected inputs plus whatever the raw tx
        // already carried; missing values are skipped, mirroring Core's
        // psbt-funding behaviour for foreign inputs). ---
        let in_value: u64 = funded
            .inputs
            .iter()
            .filter_map(|i| wallet_guard.get_utxo(&i.previous_output).map(|u| u.value))
            .sum();
        let out_value: u64 = funded.outputs.iter().map(|o| o.value).sum();
        let fee_sats = in_value.saturating_sub(out_value);

        drop(wallet_guard);

        let hex = hex::encode(funded.serialize());

        Ok(FundRawTransactionResult {
            hex,
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
        let name = self.effective_wallet().or_else(|| {
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
        let name = self.effective_wallet().or_else(|| {
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
        let name = self.effective_wallet().or_else(|| {
            state.wallet_manager.get_default_wallet().map(|(n, _)| n)
        });
        let name = name.ok_or_else(|| {
            Self::rpc_error(
                wallet_error::RPC_WALLET_NOT_SPECIFIED,
                "No wallet specified",
            )
        })?;

        // Core encrypt.cpp:256: encrypting a wallet without private keys is
        // RPC_WALLET_ENCRYPTION_FAILED (-16).
        if let Some(w) = state.wallet_manager.get_wallet(&name) {
            if let Ok(guard) = w.lock() {
                if !guard.private_keys_enabled() {
                    return Err(Self::rpc_error(
                        wallet_error::RPC_WALLET_ENCRYPTION_FAILED,
                        "Error: wallet does not contain private keys, nothing to encrypt.",
                    ));
                }
            }
        }

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
        let name = self.effective_wallet().or_else(|| {
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
        let (name, wallet) = self.resolve_wallet(&state)?;

        Self::require_unlocked(&state, &name)?;

        let mut wallet_guard = wallet
            .lock()
            .map_err(|_| Self::rpc_error(wallet_error::RPC_WALLET_ERROR, "Failed to lock wallet"))?;

        // Core spend.cpp:1036 (bumpfee signs; psbtbumpfee remains available).
        if !wallet_guard.private_keys_enabled() {
            return Err(Self::rpc_error(
                wallet_error::RPC_WALLET_ERROR,
                "bumpfee is not available with wallets that have private keys disabled. Use psbtbumpfee instead.",
            ));
        }

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
        let (name, wallet) = self.resolve_wallet(&state)?;

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

        let (name, wallet) = self.resolve_wallet(&state)?;
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
        let (name, wallet) = self.resolve_wallet(&state)?;
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

    /// createwallet on a wallet whose DB exists on disk (but is not loaded)
    /// returns the GENUINE Core code `RPC_WALLET_ALREADY_EXISTS = -36`
    /// (protocol.h:83), NOT the generic `RPC_WALLET_ERROR = -4`. Core maps
    /// DatabaseStatus::FAILED_ALREADY_EXISTS to this code (wallet/rpc/util.cpp:142).
    /// Proves the call-site wiring, not just the constant. We unload first so the
    /// manager's "already loaded" branch is bypassed and the on-disk
    /// "already exists" branch fires (Core's FAILED_ALREADY_EXISTS).
    #[tokio::test]
    async fn test_create_wallet_already_exists_code() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        // Create, then unload so the on-disk wallet dir survives but the name is
        // no longer in memory (so the "already loaded" path is NOT taken).
        rpc.create_wallet("dupe".to_string(), None, None, None, None, None, None)
            .await
            .expect("first createwallet must succeed");
        rpc.unload_wallet(Some("dupe".to_string()), None)
            .await
            .expect("unload must succeed");

        // Re-create with the same name: the on-disk dir exists -> Core's
        // FAILED_ALREADY_EXISTS -> RPC_WALLET_ALREADY_EXISTS (-36).
        let err = rpc
            .create_wallet("dupe".to_string(), None, None, None, None, None, None)
            .await
            .expect_err("re-create of existing on-disk wallet must error");
        assert_eq!(
            err.code(),
            wallet_error::RPC_WALLET_ALREADY_EXISTS,
            "re-create of existing wallet must emit RPC_WALLET_ALREADY_EXISTS"
        );
        assert_eq!(err.code(), -36, "and that code is the genuine Core value -36");
        assert_ne!(
            err.code(),
            wallet_error::RPC_WALLET_ERROR,
            "must NOT collapse to the generic RPC_WALLET_ERROR (-4)"
        );
    }

    /// createwallet on an ALREADY-LOADED wallet maps to Core's
    /// FAILED_ALREADY_LOADED -> RPC_WALLET_ALREADY_LOADED (-35), distinct from
    /// both the generic -4 and the on-disk-exists -36. Guards the call-site
    /// branch order (loaded check before exists check, matching the manager).
    #[tokio::test]
    async fn test_create_wallet_already_loaded_code() {
        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());

        rpc.create_wallet("loaded".to_string(), None, None, None, None, None, None)
            .await
            .expect("first createwallet must succeed");

        // Same name while still loaded -> RPC_WALLET_ALREADY_LOADED (-35).
        let err = rpc
            .create_wallet("loaded".to_string(), None, None, None, None, None, None)
            .await
            .expect_err("re-create of loaded wallet must error");
        assert_eq!(
            err.code(),
            wallet_error::RPC_WALLET_ALREADY_LOADED,
            "re-create of loaded wallet must emit RPC_WALLET_ALREADY_LOADED (-35)"
        );
        assert_eq!(err.code(), -35, "genuine Core value");
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

    // -----------------------------------------------------------------------
    // fundrawtransaction — happy path: a raw tx with one output and NO inputs
    // gets inputs + a change output added from the wallet UTXO set via the
    // shared coin-selection engine. Asserts the funded tx is internally
    // consistent (sum(in) == sum(out) + fee, change = in - out - fee) and
    // that the returned hex round-trips to that tx.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn fundrawtransaction_adds_inputs_and_change() {
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_primitives::{Decodable, Encodable, Hash256, OutPoint, Transaction, TxOut};
        use rustoshi_wallet::WalletUtxo;

        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet("w".to_string(), None, None, None, None, None, None)
            .await
            .unwrap();

        // Inject a confirmed UTXO the wallet owns (0.01 BTC) so the selector
        // has something to pick — same fixture pattern as the
        // walletcreatefundedpsbt happy-path test.
        let utxo_value: u64 = 1_000_000; // 0.01 BTC
        {
            let st = state.read().await;
            let wallet_arc = st.wallet_manager.get_wallet("w").expect("wallet should exist");
            let mut wallet = wallet_arc.lock().unwrap();
            let addr = wallet.get_new_address().unwrap();
            let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
            let path = wallet.get_derivation_path(&addr).unwrap().clone();
            wallet.add_utxo(WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256([0x42u8; 32]),
                    vout: 0,
                },
                value: utxo_value,
                script_pubkey: addr_obj.to_script_pubkey(),
                derivation_path: path,
                confirmations: 6,
                is_change: false,
                is_coinbase: false,
                height: Some(100),
            });
        }

        // Build a raw tx with ONE output (0.005 BTC to a dummy bech32 addr)
        // and NO inputs — the canonical "fund me" shape (Core RPCExamples).
        let recipient = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let recipient_value: u64 = 500_000; // 0.005 BTC; leaves change > dust
        let recipient_spk = Address::from_string(recipient, Some(Network::Testnet))
            .unwrap()
            .to_script_pubkey();
        let raw_tx = Transaction {
            version: 2,
            inputs: vec![],
            outputs: vec![TxOut {
                value: recipient_value,
                script_pubkey: recipient_spk.clone(),
            }],
            lock_time: 0,
        };
        let raw_hex = hex::encode(raw_tx.serialize());

        let res = rpc
            .fund_raw_transaction(raw_hex, None, None)
            .await
            .expect("fundrawtransaction must succeed");

        // Fee must be positive — we are paying for the tx.
        assert!(res.fee > 0.0, "fee must be > 0; got {}", res.fee);
        // A change output must have been added (recipient < UTXO), so
        // changepos >= 0.
        assert!(
            res.changepos >= 0,
            "expected a change output; changepos={}",
            res.changepos
        );

        // The returned hex must decode to the funded tx.
        let funded_bytes = hex::decode(&res.hex).expect("returned hex must decode");
        let funded = Transaction::deserialize(&funded_bytes).expect("funded tx must deserialize");

        // Inputs were added (vin non-empty).
        assert!(
            !funded.inputs.is_empty(),
            "funded tx must have at least one input added"
        );
        // The original recipient output is preserved byte-identical.
        assert!(
            funded
                .outputs
                .iter()
                .any(|o| o.value == recipient_value && o.script_pubkey == recipient_spk),
            "original recipient output must be preserved unchanged"
        );
        // There must be more outputs than the single original recipient (the
        // added change), and changepos must index a real output.
        assert!(
            funded.outputs.len() > 1,
            "expected recipient + change; got {} outputs",
            funded.outputs.len()
        );
        assert!(
            (res.changepos as usize) < funded.outputs.len(),
            "changepos {} out of range for {} outputs",
            res.changepos,
            funded.outputs.len()
        );

        // Sum the input values from the wallet UTXO set; this funded tx's only
        // input is the injected wallet UTXO.
        let in_value: u64 = {
            let st = state.read().await;
            let wallet_arc = st.wallet_manager.get_wallet("w").unwrap();
            let wallet = wallet_arc.lock().unwrap();
            funded
                .inputs
                .iter()
                .filter_map(|i| wallet.get_utxo(&i.previous_output).map(|u| u.value))
                .sum()
        };
        let out_value: u64 = funded.outputs.iter().map(|o| o.value).sum();
        let fee_sats = (res.fee * 100_000_000.0).round() as u64;

        // sum(selected inputs) == sum(outputs) + fee.
        assert_eq!(
            in_value,
            out_value + fee_sats,
            "in {} must equal out {} + fee {}",
            in_value,
            out_value,
            fee_sats
        );

        // change = inputs - outputs(excluding change) - fee. The non-change
        // outputs total is just the recipient; change is at changepos.
        let change_value = funded.outputs[res.changepos as usize].value;
        let non_change_out: u64 = out_value - change_value;
        assert_eq!(
            change_value,
            in_value - non_change_out - fee_sats,
            "change {} must equal in {} - non_change_out {} - fee {}",
            change_value,
            in_value,
            non_change_out,
            fee_sats
        );
        // The input value covers outputs + fee (Core invariant).
        assert!(
            in_value >= out_value + fee_sats,
            "input value {} must cover outputs+fee {}",
            in_value,
            out_value + fee_sats
        );
    }

    // fundrawtransaction — insufficient funds surfaces the wallet
    // insufficient-funds error (Core: RPC_WALLET_INSUFFICIENT_FUNDS).
    #[tokio::test]
    async fn fundrawtransaction_insufficient_funds_errors() {
        use rustoshi_crypto::address::{Address, Network};
        use rustoshi_primitives::{Encodable, Transaction, TxOut};

        let state = setup_wallet_state();
        let rpc = WalletRpcImpl::new(state.clone());
        rpc.create_wallet("w".to_string(), None, None, None, None, None, None)
            .await
            .unwrap();

        // No UTXOs injected: the wallet is empty. Funding a 0.005 BTC output
        // must fail with insufficient funds rather than fabricate inputs.
        let recipient_spk = Address::from_string(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Some(Network::Testnet),
        )
        .unwrap()
        .to_script_pubkey();
        let raw_tx = Transaction {
            version: 2,
            inputs: vec![],
            outputs: vec![TxOut {
                value: 500_000,
                script_pubkey: recipient_spk,
            }],
            lock_time: 0,
        };
        let raw_hex = hex::encode(raw_tx.serialize());

        let res = rpc.fund_raw_transaction(raw_hex, None, None).await;
        assert!(res.is_err(), "funding an empty wallet must error");
    }
}
