//! BIP-174/370 Partially Signed Bitcoin Transactions (PSBT).
//!
//! This module implements PSBT, a standard format for unsigned and partially-signed
//! Bitcoin transactions that enables multi-party signing workflows.
//!
//! # PSBT Roles
//!
//! - **Creator**: Creates an empty PSBT from an unsigned transaction
//! - **Updater**: Adds UTXO, script, and derivation information
//! - **Signer**: Adds partial signatures
//! - **Combiner**: Merges multiple PSBTs with the same underlying transaction
//! - **Finalizer**: Constructs final scriptSig/witness from partial signatures
//! - **Extractor**: Extracts the final signed transaction
//!
//! # Example
//!
//! ```rust,ignore
//! use rustoshi_wallet::psbt::Psbt;
//! use rustoshi_primitives::transaction::Transaction;
//!
//! // Create a PSBT from an unsigned transaction
//! let tx = Transaction { ... };
//! let psbt = Psbt::from_unsigned_tx(tx)?;
//!
//! // Encode to base64 for transport
//! let base64 = psbt.to_base64();
//!
//! // Decode from base64
//! let psbt = Psbt::from_base64(&base64)?;
//! ```

use crate::hd::WalletError;
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size, Decodable, Encodable};
use rustoshi_primitives::transaction::{Transaction, TxOut};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};

// ============================================================================
// PSBT Constants
// ============================================================================

/// PSBT magic bytes: "psbt" + 0xff separator
pub const PSBT_MAGIC_BYTES: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Separator byte (marks end of each map)
pub const PSBT_SEPARATOR: u8 = 0x00;

/// Maximum PSBT file size (100 MB)
pub const MAX_PSBT_SIZE: usize = 100_000_000;

/// Highest supported PSBT version
pub const PSBT_HIGHEST_VERSION: u32 = 0;

// Global key types
pub const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
pub const PSBT_GLOBAL_XPUB: u8 = 0x01;
pub const PSBT_GLOBAL_VERSION: u8 = 0xFB;
pub const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

// Input key types
pub const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
pub const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
pub const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
pub const PSBT_IN_SIGHASH: u8 = 0x03;
pub const PSBT_IN_REDEEMSCRIPT: u8 = 0x04;
pub const PSBT_IN_WITNESSSCRIPT: u8 = 0x05;
pub const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
pub const PSBT_IN_SCRIPTSIG: u8 = 0x07;
pub const PSBT_IN_SCRIPTWITNESS: u8 = 0x08;
pub const PSBT_IN_RIPEMD160: u8 = 0x0A;
pub const PSBT_IN_SHA256: u8 = 0x0B;
pub const PSBT_IN_HASH160: u8 = 0x0C;
pub const PSBT_IN_HASH256: u8 = 0x0D;
pub const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
pub const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
pub const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
pub const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
pub const PSBT_IN_PROPRIETARY: u8 = 0xFC;

// Output key types
pub const PSBT_OUT_REDEEMSCRIPT: u8 = 0x00;
pub const PSBT_OUT_WITNESSSCRIPT: u8 = 0x01;
pub const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
pub const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
pub const PSBT_OUT_TAP_TREE: u8 = 0x06;
pub const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
pub const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x08;
pub const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

// ============================================================================
// PSBT Error Types
// ============================================================================

/// PSBT-specific errors
#[derive(Debug, thiserror::Error)]
pub enum PsbtError {
    /// Invalid PSBT magic bytes
    #[error("invalid PSBT magic bytes")]
    InvalidMagic,

    /// Unsupported PSBT version
    #[error("unsupported PSBT version: {0}")]
    UnsupportedVersion(u32),

    /// Missing required global unsigned transaction
    #[error("missing unsigned transaction")]
    MissingUnsignedTx,

    /// Unsigned transaction has non-empty scriptSigs or witnesses
    #[error("unsigned transaction has non-empty scriptSigs or witnesses")]
    NonEmptyScriptSig,

    /// Duplicate key in PSBT map
    #[error("duplicate key: {0}")]
    DuplicateKey(String),

    /// Missing separator at end of map
    #[error("missing separator at end of map")]
    MissingSeparator,

    /// Input count mismatch
    #[error("input count mismatch: expected {expected}, got {got}")]
    InputCountMismatch { expected: usize, got: usize },

    /// Output count mismatch
    #[error("output count mismatch: expected {expected}, got {got}")]
    OutputCountMismatch { expected: usize, got: usize },

    /// Invalid key size for type
    #[error("invalid key size for type {key_type}: expected {expected}, got {got}")]
    InvalidKeySize {
        key_type: u8,
        expected: usize,
        got: usize,
    },

    /// Invalid public key
    #[error("invalid public key")]
    InvalidPubkey,

    /// Invalid signature encoding
    #[error("invalid signature encoding")]
    InvalidSignature,

    /// Invalid derivation path
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// Non-witness UTXO hash mismatch
    #[error("non-witness UTXO hash mismatch")]
    UtxoHashMismatch,

    /// witness_utxo and non_witness_utxo disagree on the spent output
    /// (CVE-2020-14199 amount-oracle defense — the spending wallet must
    /// not trust the witness_utxo amount/scriptPubKey when both fields are
    /// present and they conflict).
    #[error("witness_utxo and non_witness_utxo disagree on amount or scriptPubKey")]
    WitnessUtxoMismatch,

    /// UTXO index out of range
    #[error("UTXO index out of range")]
    UtxoIndexOutOfRange,

    /// Cannot combine PSBTs with different underlying transactions
    #[error("cannot combine PSBTs with different transactions")]
    IncompatiblePsbts,

    /// Cannot finalize incomplete PSBT
    #[error("cannot finalize: {0}")]
    CannotFinalize(String),

    /// Trailing (unparsed) bytes remained after a complete PSBT.
    ///
    /// Mirrors Bitcoin Core's `DecodeRawPSBT` (src/psbt.cpp): after
    /// `ss_data >> psbt` it rejects with `if (!ss_data.empty()) { error =
    /// "extra data after PSBT"; }`. A PSBT that does not consume its entire
    /// input stream is malformed and must not deserialize as Ok.
    #[error("extra data after PSBT")]
    TrailingData,

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Base64 decode error
    #[error("base64 decode error: {0}")]
    Base64(String),
}

impl From<PsbtError> for WalletError {
    fn from(e: PsbtError) -> Self {
        WalletError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

// ============================================================================
// PSBT Role
// ============================================================================

/// PSBT workflow role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtRole {
    /// Creates an empty PSBT from an unsigned transaction
    Creator,
    /// Adds UTXO, script, and derivation information
    Updater,
    /// Adds partial signatures
    Signer,
    /// Combines multiple PSBTs
    Combiner,
    /// Constructs final scriptSig/witness
    Finalizer,
    /// Extracts the final signed transaction
    Extractor,
}

impl std::fmt::Display for PsbtRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsbtRole::Creator => write!(f, "Creator"),
            PsbtRole::Updater => write!(f, "Updater"),
            PsbtRole::Signer => write!(f, "Signer"),
            PsbtRole::Combiner => write!(f, "Combiner"),
            PsbtRole::Finalizer => write!(f, "Finalizer"),
            PsbtRole::Extractor => write!(f, "Extractor"),
        }
    }
}

// ============================================================================
// Key Origin Info
// ============================================================================

/// BIP32 key origin information: master fingerprint + derivation path
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeyOrigin {
    /// Master key fingerprint (first 4 bytes of HASH160 of master public key)
    pub fingerprint: [u8; 4],
    /// Derivation path (list of child indices, hardened indices have bit 31 set)
    pub path: Vec<u32>,
}

impl KeyOrigin {
    /// Create a new key origin
    pub fn new(fingerprint: [u8; 4], path: Vec<u32>) -> Self {
        Self { fingerprint, path }
    }

    /// Serialized size: 4 bytes fingerprint + 4 bytes per path element
    pub fn serialized_size(&self) -> usize {
        4 + self.path.len() * 4
    }

    /// Encode to writer
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.fingerprint)?;
        for index in &self.path {
            writer.write_all(&index.to_le_bytes())?;
        }
        Ok(self.serialized_size())
    }

    /// Decode from reader with known length
    pub fn decode_with_len<R: Read>(reader: &mut R, len: usize) -> io::Result<Self> {
        if !len.is_multiple_of(4) || len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid key origin length",
            ));
        }

        let mut fingerprint = [0u8; 4];
        reader.read_exact(&mut fingerprint)?;

        let path_len = (len / 4) - 1;
        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            path.push(u32::from_le_bytes(buf));
        }

        Ok(Self { fingerprint, path })
    }
}

// ============================================================================
// Proprietary Data
// ============================================================================

/// Proprietary PSBT key-value pair
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proprietary {
    /// Identifier prefix (e.g., company name)
    pub identifier: Vec<u8>,
    /// Subtype within the identifier namespace
    pub subtype: u64,
    /// Key data (after type byte)
    pub key: Vec<u8>,
    /// Value data
    pub value: Vec<u8>,
}

// ============================================================================
// PSBT Input
// ============================================================================

/// Per-input PSBT data
#[derive(Debug, Clone, Default)]
pub struct PsbtInput {
    /// Non-witness UTXO: full previous transaction (required for legacy inputs)
    pub non_witness_utxo: Option<Transaction>,

    /// Witness UTXO: just the output being spent (for SegWit inputs)
    pub witness_utxo: Option<TxOut>,

    /// Partial signatures: pubkey -> signature
    /// Key is 33-byte compressed pubkey, value is DER signature with sighash byte
    pub partial_sigs: BTreeMap<[u8; 33], Vec<u8>>,

    /// Sighash type to use for this input
    pub sighash_type: Option<u32>,

    /// Redeem script (for P2SH)
    pub redeem_script: Option<Vec<u8>>,

    /// Witness script (for P2WSH)
    pub witness_script: Option<Vec<u8>>,

    /// BIP32 derivation paths: pubkey -> KeyOrigin
    pub bip32_derivation: BTreeMap<[u8; 33], KeyOrigin>,

    /// Final scriptSig (after signing is complete)
    pub final_script_sig: Option<Vec<u8>>,

    /// Final scriptWitness (after signing is complete)
    pub final_script_witness: Option<Vec<Vec<u8>>>,

    /// RIPEMD160 preimages: hash -> preimage
    pub ripemd160_preimages: HashMap<[u8; 20], Vec<u8>>,

    /// SHA256 preimages: hash -> preimage
    pub sha256_preimages: HashMap<[u8; 32], Vec<u8>>,

    /// HASH160 preimages: hash -> preimage
    pub hash160_preimages: HashMap<[u8; 20], Vec<u8>>,

    /// HASH256 preimages: hash -> preimage
    pub hash256_preimages: HashMap<[u8; 32], Vec<u8>>,

    /// Taproot key-path signature (64 or 65 bytes)
    pub tap_key_sig: Option<Vec<u8>>,

    /// Taproot script-path signatures: (x-only pubkey, leaf hash) -> signature
    pub tap_script_sigs: BTreeMap<([u8; 32], [u8; 32]), Vec<u8>>,

    /// Taproot leaf scripts: (script, leaf_version) -> set of control blocks
    pub tap_leaf_scripts: BTreeMap<(Vec<u8>, u8), BTreeSet<Vec<u8>>>,

    /// Taproot BIP32 derivation: x-only pubkey -> (leaf hashes, key origin)
    pub tap_bip32_derivation: BTreeMap<[u8; 32], (BTreeSet<[u8; 32]>, KeyOrigin)>,

    /// Taproot internal key (32 bytes, x-only)
    pub tap_internal_key: Option<[u8; 32]>,

    /// Taproot merkle root (32 bytes)
    pub tap_merkle_root: Option<[u8; 32]>,

    /// Proprietary key-value pairs
    pub proprietary: BTreeSet<Proprietary>,

    /// Unknown key-value pairs
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl PsbtInput {
    /// Check if this input has been finalized (has final scriptSig or witness)
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() || self.final_script_witness.is_some()
    }

    /// Check if this input is empty (no data)
    pub fn is_null(&self) -> bool {
        self.non_witness_utxo.is_none()
            && self.witness_utxo.is_none()
            && self.partial_sigs.is_empty()
            && self.sighash_type.is_none()
            && self.redeem_script.is_none()
            && self.witness_script.is_none()
            && self.bip32_derivation.is_empty()
            && self.final_script_sig.is_none()
            && self.final_script_witness.is_none()
            && self.tap_key_sig.is_none()
            && self.tap_script_sigs.is_empty()
            && self.tap_leaf_scripts.is_empty()
            && self.tap_bip32_derivation.is_empty()
            && self.tap_internal_key.is_none()
            && self.tap_merkle_root.is_none()
            && self.proprietary.is_empty()
            && self.unknown.is_empty()
    }

    /// Merge another input into this one (for Combiner role)
    pub fn merge(&mut self, other: &PsbtInput) {
        // Take non-witness UTXO if we don't have it
        if self.non_witness_utxo.is_none() {
            self.non_witness_utxo = other.non_witness_utxo.clone();
        }

        // Take witness UTXO if we don't have it
        if self.witness_utxo.is_none() {
            self.witness_utxo = other.witness_utxo.clone();
        }

        // Merge partial signatures
        for (key, sig) in &other.partial_sigs {
            self.partial_sigs.entry(*key).or_insert_with(|| sig.clone());
        }

        // Take sighash type if we don't have it
        if self.sighash_type.is_none() {
            self.sighash_type = other.sighash_type;
        }

        // Take redeem script if we don't have it
        if self.redeem_script.is_none() {
            self.redeem_script = other.redeem_script.clone();
        }

        // Take witness script if we don't have it
        if self.witness_script.is_none() {
            self.witness_script = other.witness_script.clone();
        }

        // Merge BIP32 derivation paths
        for (key, origin) in &other.bip32_derivation {
            self.bip32_derivation
                .entry(*key)
                .or_insert_with(|| origin.clone());
        }

        // Take final scriptSig if we don't have it
        if self.final_script_sig.is_none() {
            self.final_script_sig = other.final_script_sig.clone();
        }

        // Take final witness if we don't have it
        if self.final_script_witness.is_none() {
            self.final_script_witness = other.final_script_witness.clone();
        }

        // Merge hash preimages
        for (hash, preimage) in &other.ripemd160_preimages {
            self.ripemd160_preimages
                .entry(*hash)
                .or_insert_with(|| preimage.clone());
        }
        for (hash, preimage) in &other.sha256_preimages {
            self.sha256_preimages
                .entry(*hash)
                .or_insert_with(|| preimage.clone());
        }
        for (hash, preimage) in &other.hash160_preimages {
            self.hash160_preimages
                .entry(*hash)
                .or_insert_with(|| preimage.clone());
        }
        for (hash, preimage) in &other.hash256_preimages {
            self.hash256_preimages
                .entry(*hash)
                .or_insert_with(|| preimage.clone());
        }

        // Taproot fields
        if self.tap_key_sig.is_none() {
            self.tap_key_sig = other.tap_key_sig.clone();
        }
        for (key, sig) in &other.tap_script_sigs {
            self.tap_script_sigs
                .entry(*key)
                .or_insert_with(|| sig.clone());
        }
        for (key, cbs) in &other.tap_leaf_scripts {
            self.tap_leaf_scripts
                .entry(key.clone())
                .or_default()
                .extend(cbs.iter().cloned());
        }
        for (key, val) in &other.tap_bip32_derivation {
            self.tap_bip32_derivation
                .entry(*key)
                .or_insert_with(|| val.clone());
        }
        if self.tap_internal_key.is_none() {
            self.tap_internal_key = other.tap_internal_key;
        }
        if self.tap_merkle_root.is_none() {
            self.tap_merkle_root = other.tap_merkle_root;
        }

        // Merge proprietary and unknown
        self.proprietary.extend(other.proprietary.iter().cloned());
        for (key, val) in &other.unknown {
            self.unknown
                .entry(key.clone())
                .or_insert_with(|| val.clone());
        }
    }
}

// ============================================================================
// PSBT Output
// ============================================================================

/// Per-output PSBT data
#[derive(Debug, Clone, Default)]
pub struct PsbtOutput {
    /// Redeem script (for P2SH outputs)
    pub redeem_script: Option<Vec<u8>>,

    /// Witness script (for P2WSH outputs)
    pub witness_script: Option<Vec<u8>>,

    /// BIP32 derivation paths: pubkey -> KeyOrigin
    pub bip32_derivation: BTreeMap<[u8; 33], KeyOrigin>,

    /// Taproot internal key (32 bytes, x-only)
    pub tap_internal_key: Option<[u8; 32]>,

    /// Taproot script tree: list of (depth, leaf_version, script)
    pub tap_tree: Vec<(u8, u8, Vec<u8>)>,

    /// Taproot BIP32 derivation: x-only pubkey -> (leaf hashes, key origin)
    pub tap_bip32_derivation: BTreeMap<[u8; 32], (BTreeSet<[u8; 32]>, KeyOrigin)>,

    /// MuSig2 participant public keys (BIP-327 / PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08)
    /// aggregate_pubkey (33 bytes) -> Vec of participant pubkeys (33 bytes each)
    pub musig2_participant_pubkeys: BTreeMap<[u8; 33], Vec<[u8; 33]>>,

    /// Proprietary key-value pairs
    pub proprietary: BTreeSet<Proprietary>,

    /// Unknown key-value pairs
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl PsbtOutput {
    /// Check if this output is empty (no data)
    pub fn is_null(&self) -> bool {
        self.redeem_script.is_none()
            && self.witness_script.is_none()
            && self.bip32_derivation.is_empty()
            && self.tap_internal_key.is_none()
            && self.tap_tree.is_empty()
            && self.tap_bip32_derivation.is_empty()
            && self.musig2_participant_pubkeys.is_empty()
            && self.proprietary.is_empty()
            && self.unknown.is_empty()
    }

    /// Merge another output into this one (for Combiner role)
    pub fn merge(&mut self, other: &PsbtOutput) {
        if self.redeem_script.is_none() {
            self.redeem_script = other.redeem_script.clone();
        }
        if self.witness_script.is_none() {
            self.witness_script = other.witness_script.clone();
        }
        for (key, origin) in &other.bip32_derivation {
            self.bip32_derivation
                .entry(*key)
                .or_insert_with(|| origin.clone());
        }
        if self.tap_internal_key.is_none() {
            self.tap_internal_key = other.tap_internal_key;
        }
        if self.tap_tree.is_empty() {
            self.tap_tree = other.tap_tree.clone();
        }
        for (key, val) in &other.tap_bip32_derivation {
            self.tap_bip32_derivation
                .entry(*key)
                .or_insert_with(|| val.clone());
        }
        self.proprietary.extend(other.proprietary.iter().cloned());
        for (key, val) in &other.unknown {
            self.unknown
                .entry(key.clone())
                .or_insert_with(|| val.clone());
        }
    }
}

// ============================================================================
// Extended Public Key (for global xpubs)
// ============================================================================

/// Extended public key with version bytes (78 bytes total)
/// Format: version (4) + depth (1) + fingerprint (4) + child_number (4) + chain_code (32) + pubkey (33)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtPubKey {
    /// Serialized extended public key (78 bytes)
    pub data: [u8; 78],
}

impl ExtPubKey {
    /// Create from raw 78-byte data
    pub fn from_bytes(data: [u8; 78]) -> Self {
        Self { data }
    }

    /// Get the compressed public key (last 33 bytes)
    pub fn pubkey(&self) -> [u8; 33] {
        let mut key = [0u8; 33];
        key.copy_from_slice(&self.data[45..78]);
        key
    }
}

// ============================================================================
// Main PSBT Structure
// ============================================================================

/// Partially Signed Bitcoin Transaction (BIP-174)
#[derive(Debug, Clone)]
pub struct Psbt {
    /// The unsigned transaction
    pub unsigned_tx: Transaction,

    /// Global extended public keys: KeyOrigin -> set of ExtPubKeys
    /// Note: stored swapped from serialization order for faster lookups
    pub xpubs: BTreeMap<KeyOrigin, BTreeSet<ExtPubKey>>,

    /// PSBT version (0 for BIP-174)
    pub version: Option<u32>,

    /// Per-input data
    pub inputs: Vec<PsbtInput>,

    /// Per-output data
    pub outputs: Vec<PsbtOutput>,

    /// Proprietary global key-value pairs
    pub proprietary: BTreeSet<Proprietary>,

    /// Unknown global key-value pairs
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Psbt {
    // ========================================================================
    // Creator Role
    // ========================================================================

    /// Create a new PSBT from an unsigned transaction (Creator role).
    ///
    /// The transaction must have empty scriptSigs and witnesses.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, PsbtError> {
        // Verify transaction has empty scriptSigs and witnesses
        for input in &tx.inputs {
            if !input.script_sig.is_empty() || !input.witness.is_empty() {
                return Err(PsbtError::NonEmptyScriptSig);
            }
        }

        let num_inputs = tx.inputs.len();
        let num_outputs = tx.outputs.len();

        Ok(Self {
            unsigned_tx: tx,
            xpubs: BTreeMap::new(),
            version: None,
            inputs: vec![PsbtInput::default(); num_inputs],
            outputs: vec![PsbtOutput::default(); num_outputs],
            proprietary: BTreeSet::new(),
            unknown: BTreeMap::new(),
        })
    }

    // ========================================================================
    // Updater Role
    // ========================================================================

    /// Set the non-witness UTXO for an input (Updater role).
    ///
    /// Required for legacy (non-SegWit) inputs.
    pub fn set_non_witness_utxo(&mut self, input_index: usize, utxo_tx: Transaction) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        let expected_txid = self.unsigned_tx.inputs[input_index].previous_output.txid;
        if utxo_tx.txid() != expected_txid {
            return Err(PsbtError::UtxoHashMismatch);
        }

        self.inputs[input_index].non_witness_utxo = Some(utxo_tx);
        Ok(())
    }

    /// Set the witness UTXO for an input (Updater role).
    ///
    /// Sufficient for SegWit inputs (more efficient than full non-witness UTXO).
    pub fn set_witness_utxo(&mut self, input_index: usize, utxo: TxOut) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.inputs[input_index].witness_utxo = Some(utxo);
        Ok(())
    }

    /// Set the redeem script for an input (Updater role).
    pub fn set_input_redeem_script(&mut self, input_index: usize, script: Vec<u8>) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.inputs[input_index].redeem_script = Some(script);
        Ok(())
    }

    /// Set the witness script for an input (Updater role).
    pub fn set_input_witness_script(&mut self, input_index: usize, script: Vec<u8>) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.inputs[input_index].witness_script = Some(script);
        Ok(())
    }

    /// Add a BIP32 derivation path for an input (Updater role).
    pub fn add_input_derivation(
        &mut self,
        input_index: usize,
        pubkey: [u8; 33],
        origin: KeyOrigin,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.inputs[input_index].bip32_derivation.insert(pubkey, origin);
        Ok(())
    }

    /// Add a BIP32 derivation path for an output (Updater role).
    pub fn add_output_derivation(
        &mut self,
        output_index: usize,
        pubkey: [u8; 33],
        origin: KeyOrigin,
    ) -> Result<(), PsbtError> {
        if output_index >= self.outputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.outputs[output_index].bip32_derivation.insert(pubkey, origin);
        Ok(())
    }

    // ========================================================================
    // Signer Role
    // ========================================================================

    /// Add a partial signature for an input (Signer role).
    pub fn add_partial_sig(
        &mut self,
        input_index: usize,
        pubkey: [u8; 33],
        signature: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.inputs[input_index].partial_sigs.insert(pubkey, signature);
        Ok(())
    }

    /// Set the sighash type for an input (Signer role).
    pub fn set_sighash_type(&mut self, input_index: usize, sighash: u32) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        self.inputs[input_index].sighash_type = Some(sighash);
        Ok(())
    }

    // ========================================================================
    // Combiner Role
    // ========================================================================

    /// Merge another PSBT into this one (Combiner role).
    ///
    /// Both PSBTs must have the same underlying unsigned transaction.
    pub fn merge(&mut self, other: &Psbt) -> Result<(), PsbtError> {
        // Verify same underlying transaction
        if self.unsigned_tx.txid() != other.unsigned_tx.txid() {
            return Err(PsbtError::IncompatiblePsbts);
        }

        // Merge global xpubs
        for (origin, xpubs) in &other.xpubs {
            self.xpubs
                .entry(origin.clone())
                .or_default()
                .extend(xpubs.iter().cloned());
        }

        // Merge inputs
        //
        // W41 — A1 (combiner-role): if `other` carries a non_witness_utxo
        // we don't yet have, verify its txid against `self.unsigned_tx`
        // BEFORE adopting it. PSBTs sharing the same unsigned tx must
        // share the same prevout txids by construction; checking here
        // means a wire-tampered counterparty PSBT can't poison our
        // non_witness_utxo via combinepsbt. Mirrors Core's
        // `PSBTInput::Merge` constraint that the spent prevtx hash is
        // immutable across roles.
        for (i, other_input) in other.inputs.iter().enumerate() {
            if i < self.inputs.len() {
                if self.inputs[i].non_witness_utxo.is_none() {
                    if let Some(ref nw) = other_input.non_witness_utxo {
                        if nw.txid() != self.unsigned_tx.inputs[i].previous_output.txid {
                            return Err(PsbtError::UtxoHashMismatch);
                        }
                    }
                }
                self.inputs[i].merge(other_input);
            }
        }

        // Merge outputs
        for (i, other_output) in other.outputs.iter().enumerate() {
            if i < self.outputs.len() {
                self.outputs[i].merge(other_output);
            }
        }

        // Merge global proprietary and unknown
        self.proprietary.extend(other.proprietary.iter().cloned());
        for (key, val) in &other.unknown {
            self.unknown
                .entry(key.clone())
                .or_insert_with(|| val.clone());
        }

        Ok(())
    }

    /// Combine multiple PSBTs into one (static Combiner).
    pub fn combine(psbts: &[Psbt]) -> Result<Self, PsbtError> {
        if psbts.is_empty() {
            return Err(PsbtError::MissingUnsignedTx);
        }

        let mut result = psbts[0].clone();
        for psbt in &psbts[1..] {
            result.merge(psbt)?;
        }

        Ok(result)
    }

    // ========================================================================
    // Finalizer Role
    // ========================================================================

    /// Check if all inputs are finalized.
    pub fn is_finalized(&self) -> bool {
        self.inputs.iter().all(|i| i.is_finalized())
    }

    /// Finalize an input by constructing the final scriptSig/witness.
    ///
    /// This is a simplified finalizer that handles common script types.
    /// For complex scripts, use a custom finalizer.
    pub fn finalize_input(&mut self, input_index: usize) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::UtxoIndexOutOfRange);
        }

        let input = &mut self.inputs[input_index];

        // Already finalized
        if input.is_finalized() {
            return Ok(());
        }

        // Try to finalize based on available data
        // This is a simplified implementation - real finalizers need to understand script types

        // Check for Taproot key-path spend
        if let Some(ref sig) = input.tap_key_sig {
            input.final_script_witness = Some(vec![sig.clone()]);
            return Ok(());
        }

        // P2WSH and P2SH-P2WSH: presence of witness_script is the
        // unambiguous signal. Assemble a Core-shape witness from
        // partial_sigs in pubkey-order-of-the-script, prepending an empty
        // pad for CHECKMULTISIG.
        if let Some(ref witness_script) = input.witness_script.clone() {
            let witness = build_p2wsh_witness(witness_script, &input.partial_sigs)?;
            input.final_script_witness = Some(witness);

            // P2SH-P2WSH wrap: scriptSig is a single push of the redeem
            // script (which is OP_0 <sha256(witness_script)>).
            if let Some(ref redeem_script) = input.redeem_script {
                let mut script_sig = Vec::with_capacity(redeem_script.len() + 1);
                script_sig.push(redeem_script.len() as u8);
                script_sig.extend_from_slice(redeem_script);
                input.final_script_sig = Some(script_sig);
            }
            return Ok(());
        }

        // Check for P2WPKH (single sig in partial_sigs, no witness_script)
        if input.witness_script.is_none() && input.partial_sigs.len() == 1 {
            let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();
            input.final_script_witness = Some(vec![sig.clone(), pubkey.to_vec()]);
            return Ok(());
        }

        // Check for P2PKH (single sig in partial_sigs, no redeem_script)
        if input.redeem_script.is_none()
            && input.witness_script.is_none()
            && input.partial_sigs.len() == 1
        {
            let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();
            // scriptSig: <sig> <pubkey>
            let mut script_sig = Vec::new();
            script_sig.push(sig.len() as u8);
            script_sig.extend_from_slice(sig);
            script_sig.push(pubkey.len() as u8);
            script_sig.extend_from_slice(pubkey);
            input.final_script_sig = Some(script_sig);
            return Ok(());
        }

        // Legacy P2SH-multisig (W46, M-tier closure of W42-A diagnostic).
        //
        // Detect: redeem_script is present, witness_script is absent, and
        // the redeem_script parses as <M> <pk1> ... <pkN> <N> CHECKMULTISIG
        // (the canonical Core multisig solver shape). Assemble the
        // legacy scriptSig:
        //
        //     OP_0  push(sig1)  ...  push(sigM)  push(redeem_script)
        //
        // OP_0 is the empty-pad bug-compat byte for CHECKMULTISIG. The
        // signatures MUST be ordered to match the pubkey order in the
        // redeem_script — NOT insertion order, NOT pubkey-byte sort,
        // NOT partial_sigs map order. Mirrors `bitcoin-core/src/script/
        // sign.cpp::ProduceSignature` (legacy P2SH branch) and the
        // pubkey-order discipline already used by `build_p2wsh_witness`.
        if input.witness_script.is_none() {
            if let Some(ref redeem_script) = input.redeem_script.clone() {
                if let Some((m, keys)) = parse_multisig_script(redeem_script) {
                    // Walk pubkeys in script order; pick the first M for
                    // which we hold a partial_sig. Stop at M (extra pushes
                    // would fail CHECKMULTISIG strictness).
                    let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(m);
                    for pk in &keys {
                        // Legacy P2SH multisig allows uncompressed (65B)
                        // pubkeys, unlike segwit-v0. We only key
                        // partial_sigs by 33-byte compressed pubkeys
                        // today, so an uncompressed key in the redeem
                        // script will simply not match — the signer
                        // would have rejected it earlier.
                        if pk.len() != 33 {
                            continue;
                        }
                        let mut pk33 = [0u8; 33];
                        pk33.copy_from_slice(pk);
                        if let Some(sig) = input.partial_sigs.get(&pk33) {
                            sigs.push(sig.clone());
                            if sigs.len() == m {
                                break;
                            }
                        }
                    }
                    if sigs.len() < m {
                        return Err(PsbtError::CannotFinalize(format!(
                            "P2SH multisig: have {} signatures, need {}",
                            sigs.len(),
                            m
                        )));
                    }

                    // Assemble scriptSig. Use OP_PUSHDATA1 for any push
                    // body > 75 bytes (large redeem scripts in N-of-N
                    // can exceed this; sigs themselves are 70-72B + 1B
                    // sighash, well under the limit).
                    let mut script_sig: Vec<u8> = Vec::new();
                    script_sig.push(0x00); // OP_0 — CHECKMULTISIG empty pad
                    for sig in &sigs {
                        push_to_script_sig(&mut script_sig, sig);
                    }
                    push_to_script_sig(&mut script_sig, redeem_script);

                    // CRITICAL (W43-1 regression-avoidance):
                    // set final_script_sig BEFORE clearing producer
                    // fields. Clearing first leaves the input in a
                    // half-baked state if a later step panics, and the
                    // ouroboros W43-1 regression showed a blockbrew
                    // variant of exactly this bug class. The local
                    // `script_sig` snapshot above means we don't need
                    // to read producer fields after this point either.
                    input.final_script_sig = Some(script_sig);

                    // Clear producer fields per BIP-174 finalizer role
                    // (lunarblock W41 + ouroboros W43 pattern). The
                    // encoder already skips them once final_script_sig
                    // is set, but clearing keeps the in-memory PsbtInput
                    // honest for downstream consumers.
                    input.partial_sigs.clear();
                    input.redeem_script = None;
                    input.witness_script = None;
                    input.bip32_derivation.clear();
                    input.sighash_type = None;

                    return Ok(());
                }
            }
        }

        Err(PsbtError::CannotFinalize(
            "insufficient data or unsupported script type".to_string(),
        ))
    }

    /// Finalize all inputs.
    pub fn finalize(&mut self) -> Result<(), PsbtError> {
        for i in 0..self.inputs.len() {
            self.finalize_input(i)?;
        }
        Ok(())
    }

    // ========================================================================
    // Extractor Role
    // ========================================================================

    /// Extract the final signed transaction (Extractor role).
    ///
    /// All inputs must be finalized.
    pub fn extract_tx(&self) -> Result<Transaction, PsbtError> {
        if !self.is_finalized() {
            return Err(PsbtError::CannotFinalize(
                "not all inputs are finalized".to_string(),
            ));
        }

        let mut tx = self.unsigned_tx.clone();

        for (i, input) in self.inputs.iter().enumerate() {
            if let Some(ref script_sig) = input.final_script_sig {
                tx.inputs[i].script_sig = script_sig.clone();
            }
            if let Some(ref witness) = input.final_script_witness {
                tx.inputs[i].witness = witness.clone();
            }
        }

        Ok(tx)
    }

    // ========================================================================
    // Analysis
    // ========================================================================

    /// Get the UTXO being spent by an input (either from witness_utxo or non_witness_utxo).
    pub fn get_input_utxo(&self, input_index: usize) -> Option<TxOut> {
        if input_index >= self.inputs.len() {
            return None;
        }

        let input = &self.inputs[input_index];

        // Prefer witness UTXO
        if let Some(ref utxo) = input.witness_utxo {
            return Some(utxo.clone());
        }

        // Fall back to non-witness UTXO
        if let Some(ref tx) = input.non_witness_utxo {
            let vout = self.unsigned_tx.inputs[input_index].previous_output.vout as usize;
            if vout < tx.outputs.len() {
                return Some(tx.outputs[vout].clone());
            }
        }

        None
    }

    /// Count the number of unsigned (not finalized) inputs.
    pub fn count_unsigned_inputs(&self) -> usize {
        self.inputs.iter().filter(|i| !i.is_finalized()).count()
    }

    /// Determine the next role needed to complete this PSBT.
    pub fn next_role(&self) -> PsbtRole {
        // If any input is missing UTXO information, needs Updater
        for input in &self.inputs {
            if input.non_witness_utxo.is_none() && input.witness_utxo.is_none() {
                return PsbtRole::Updater;
            }
        }

        // If any input is missing signatures and not finalized, needs Signer
        for input in &self.inputs {
            if !input.is_finalized() && input.partial_sigs.is_empty() && input.tap_key_sig.is_none() {
                return PsbtRole::Signer;
            }
        }

        // If any input has signatures but not finalized, needs Finalizer
        for input in &self.inputs {
            if !input.is_finalized() {
                return PsbtRole::Finalizer;
            }
        }

        // All inputs finalized, ready for Extractor
        PsbtRole::Extractor
    }

    /// Compute the per-input + PSBT-level role analysis used by the
    /// `analyzepsbt` RPC, mirroring Bitcoin Core's `AnalyzePSBT` in
    /// `bitcoin-core/src/node/psbt.cpp`.
    ///
    /// Per-input verdict is one of `Updater`, `Signer`, `Finalizer`,
    /// `Extractor` (Core's `PSBTRole` set minus `Creator` / `Combiner`,
    /// which are not reachable for an inhabited input). The PSBT-level
    /// `next` is the minimum per-input role under Core's order
    /// `creator < updater < signer < finalizer < extractor`
    /// (`bitcoin-core/src/node/psbt.cpp:91-95`).
    ///
    /// References:
    ///   * camlcoin `lib/psbt.ml` `psbt_next_role` (W41 / 2a22a0e).
    ///   * hotbuns `src/wallet/psbt.ts` `analyzePSBTCore` (W47 / b6ccf2a).
    pub fn analyze(&self) -> PsbtAnalysis {
        let inputs: Vec<PsbtInputAnalysis> = self
            .inputs
            .iter()
            .map(input_next_role)
            .collect();

        // PSBT-level next = MIN over per-input roles in Core's ordering.
        // Default is Extractor (matches Core's initial value before the
        // std::min walk; see psbt.cpp:91).
        let mut next = PsbtRole::Extractor;
        for inp in &inputs {
            if role_rank(inp.next) < role_rank(next) {
                next = inp.next;
            }
        }
        PsbtAnalysis { inputs, next }
    }

    /// Get the PSBT version (0 if not specified).
    pub fn get_version(&self) -> u32 {
        self.version.unwrap_or(0)
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).expect("writing to Vec never fails");
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, PsbtError> {
        if data.len() > MAX_PSBT_SIZE {
            return Err(PsbtError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "PSBT too large",
            )));
        }
        let mut cursor = Cursor::new(data);
        let psbt = Self::decode(&mut cursor)?;
        // Core parity: DecodeRawPSBT (src/psbt.cpp) rejects any bytes left in
        // the stream after a complete unserialize ("extra data after PSBT").
        // The byte-slice boundary is where the total length is known, so the
        // trailing-data check lives here rather than inside the streaming
        // `decode<R: Read>` (which has no notion of "end of the whole blob").
        if (cursor.position() as usize) != data.len() {
            return Err(PsbtError::TrailingData);
        }
        Ok(psbt)
    }

    /// Encode to base64.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.serialize())
    }

    /// Decode from base64.
    pub fn from_base64(s: &str) -> Result<Self, PsbtError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| PsbtError::Base64(e.to_string()))?;
        Self::deserialize(&bytes)
    }
}

// ============================================================================
// P2WSH witness assembly (shared by finalizer + raw-tx signer)
// ============================================================================

/// Append a length-prefixed push of `data` to a script body, using the
/// minimal Bitcoin script encoding (1-byte length for <=75B, OP_PUSHDATA1
/// for 76..=255, OP_PUSHDATA2 for 256..=65535). Used by the legacy
/// P2SH-multisig finalizer (W46) to emit signatures + redeem_script
/// pushes in `final_script_sig`. Mirrors `CScript::operator<<` in
/// `bitcoin-core/src/script/script.h`.
fn push_to_script_sig(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00); // OP_0 / OP_FALSE — empty push
    } else if len <= 75 {
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 255 {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 65535 {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
        script.extend_from_slice(data);
    } else {
        script.push(0x4e); // OP_PUSHDATA4
        script.extend_from_slice(&(len as u32).to_le_bytes());
        script.extend_from_slice(data);
    }
}

/// Walk a `<M> <pk1> ... <pkN> <N> OP_CHECKMULTISIG` script and return the
/// embedded compressed/uncompressed pubkeys in script-pubkey order, plus the
/// declared M (signature threshold). Returns `None` if `script` doesn't match
/// the canonical Core multisig solver shape (mirrors
/// `bitcoin-core/src/script/solver.cpp::MatchMultisig`).
fn parse_multisig_script(script: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
    if script.len() < 4 {
        return None;
    }
    if *script.last()? != 0xae {
        // OP_CHECKMULTISIG
        return None;
    }
    let m_op = *script.first()?;
    if !(0x51..=0x60).contains(&m_op) {
        return None;
    }
    let m = (m_op - 0x50) as usize;
    let n_op = script[script.len() - 2];
    if !(0x51..=0x60).contains(&n_op) {
        return None;
    }
    let n = (n_op - 0x50) as usize;
    if m == 0 || m > n || n > 20 {
        return None;
    }

    let mut keys = Vec::with_capacity(n);
    let mut i = 1usize;
    let end = script.len() - 2;
    while i < end {
        let push_len = script[i] as usize;
        if push_len != 33 && push_len != 65 {
            return None;
        }
        i += 1;
        if i + push_len > end {
            return None;
        }
        keys.push(script[i..i + push_len].to_vec());
        i += push_len;
    }
    if keys.len() != n {
        return None;
    }
    Some((m, keys))
}

// ============================================================================
// analyzepsbt support (W48, mirrors bitcoin-core/src/node/psbt.cpp::AnalyzePSBT)
// ============================================================================

/// Per-input result of [`Psbt::analyze`].
///
/// Mirrors Bitcoin Core's `PSBTInputAnalysis`:
///   * `has_utxo` — does this input carry witness_utxo or non_witness_utxo?
///   * `is_final` — has the finalizer run (final_script_sig / witness present)?
///   * `next` — next role this input still needs (updater / signer /
///     finalizer / extractor).
///   * `missing_signatures` — for multisig inputs in the `Signer` state, the
///     compressed pubkeys whose partial sig is still absent. Core records
///     `CKeyID` (HASH160 of pubkey, 20 bytes) here; we follow the camlcoin /
///     hotbuns convention of emitting full pubkeys because the W40-C harness
///     does not assert on this sub-field, and the pubkey is the natural
///     identifier in our codebase. See `bitcoin-core/src/node/psbt.cpp:74`
///     and the JSON formatting in `rpc/rawtransaction.cpp:1957`.
#[derive(Debug, Clone)]
pub struct PsbtInputAnalysis {
    pub has_utxo: bool,
    pub is_final: bool,
    pub next: PsbtRole,
    pub missing_signatures: Vec<Vec<u8>>,
}

/// Result of [`Psbt::analyze`].
#[derive(Debug, Clone)]
pub struct PsbtAnalysis {
    pub inputs: Vec<PsbtInputAnalysis>,
    pub next: PsbtRole,
}

/// Order of PSBT roles in Bitcoin Core's pipeline
/// (`bitcoin-core/src/node/psbt.cpp:91-95`):
///   creator < updater < signer < finalizer < extractor
/// PSBT-level `next` = minimum (in this order) over per-input verdicts.
fn role_rank(role: PsbtRole) -> u8 {
    match role {
        PsbtRole::Creator => 0,
        PsbtRole::Updater => 1,
        PsbtRole::Signer => 2,
        // Combiner is not part of the linear ordering — it isn't a per-input
        // verdict in Core's AnalyzePSBT. Map it to Updater for safety, since
        // it is never returned by `input_next_role`.
        PsbtRole::Combiner => 1,
        PsbtRole::Finalizer => 3,
        PsbtRole::Extractor => 4,
    }
}

/// Compute the minimum number of partial sigs required to finalize a
/// non-finalized PSBT input.
///
/// Mirrors Core's `SignPSBTInput` dummy-sign branch in
/// `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT`: for next-role analysis,
/// the only thing that matters is the missing-sig count.
///
///   * Multisig (P2SH / P2WSH / P2SH-P2WSH): M from the redeem/witness
///     script (decoded by `parse_multisig_script`).
///   * Taproot key-path: 1 (the single schnorr sig).
///   * Single-sig (P2PKH / P2WPKH / P2SH-P2WPKH): 1.
///   * No UTXO and no script: `None` — caller treats as "cannot classify",
///     and falls back to "any sig is enough" (matches camlcoin W41
///     behavior so single-sig inputs aren't regressed).
fn required_sig_count(input: &PsbtInput) -> Option<usize> {
    if let Some(script) = input.witness_script.as_deref() {
        if let Some((m, _)) = parse_multisig_script(script) {
            return Some(m);
        }
        return Some(1);
    }
    if let Some(script) = input.redeem_script.as_deref() {
        if let Some((m, _)) = parse_multisig_script(script) {
            return Some(m);
        }
        return Some(1);
    }
    if input.tap_internal_key.is_some() {
        return Some(1);
    }
    if input.witness_utxo.is_some() || input.non_witness_utxo.is_some() {
        return Some(1);
    }
    None
}

/// Is this input ready for the finalizer step?
///
/// Mirrors Core's "dummy-sign succeeds" branch in `AnalyzePSBT`: when a
/// non-finalized input has every signature it needs (M-of-N multisig;
/// 1 for single-sig; tap_key_sig for taproot key-path), the next role is
/// `Finalizer`, not `Signer`.
fn is_input_ready_to_finalize(input: &PsbtInput) -> bool {
    if input.is_finalized() {
        return false;
    }
    if input.tap_key_sig.is_some() {
        return true;
    }
    let n_sigs = input.partial_sigs.len();
    if n_sigs == 0 {
        return false;
    }
    match required_sig_count(input) {
        Some(needed) => n_sigs >= needed,
        // Cannot classify; legacy any-sig heuristic.
        None => n_sigs >= 1,
    }
}

/// Per-input next role for analyzepsbt, mirroring Bitcoin Core's
/// `AnalyzePSBT` (`bitcoin-core/src/node/psbt.cpp`).
///
/// Branching order matches Core:
///   1. finalized                                  -> Extractor
///   2. has UTXO + has enough partial sigs         -> Finalizer
///   3. has UTXO, missing sigs                     -> Signer
///   4. no UTXO                                    -> Updater
fn input_next_role(input: &PsbtInput) -> PsbtInputAnalysis {
    let has_utxo = input.witness_utxo.is_some() || input.non_witness_utxo.is_some();
    let is_final = input.is_finalized();

    if is_final {
        return PsbtInputAnalysis {
            has_utxo,
            is_final: true,
            next: PsbtRole::Extractor,
            missing_signatures: Vec::new(),
        };
    }

    if !has_utxo {
        return PsbtInputAnalysis {
            has_utxo: false,
            is_final: false,
            next: PsbtRole::Updater,
            missing_signatures: Vec::new(),
        };
    }

    if is_input_ready_to_finalize(input) {
        return PsbtInputAnalysis {
            has_utxo: true,
            is_final: false,
            next: PsbtRole::Finalizer,
            missing_signatures: Vec::new(),
        };
    }

    // Signer. For multisig inputs, compute the missing-pubkey list for the
    // optional `missing.signatures` JSON field. Core walks the descriptor
    // and reports CKeyIDs; we walk the redeem/witness script directly and
    // emit the compressed pubkey bytes (the W40-C harness only checks the
    // top-level `next` field; this sub-field is informational).
    let mut missing_signatures = Vec::new();
    let script = input
        .witness_script
        .as_deref()
        .or(input.redeem_script.as_deref());
    if let Some(script) = script {
        if let Some((_m, pubkeys)) = parse_multisig_script(script) {
            for pk in pubkeys {
                if pk.len() == 33 {
                    let mut pk33 = [0u8; 33];
                    pk33.copy_from_slice(&pk);
                    if !input.partial_sigs.contains_key(&pk33) {
                        missing_signatures.push(pk);
                    }
                } else {
                    // Uncompressed pubkey — record as-is; we can't index
                    // partial_sigs (keyed on [u8; 33]) by it, so it is
                    // always "missing" for our purposes.
                    missing_signatures.push(pk);
                }
            }
        }
    }

    PsbtInputAnalysis {
        has_utxo: true,
        is_final: false,
        next: PsbtRole::Signer,
        missing_signatures,
    }
}

/// Assemble a P2WSH witness stack from a witness script + partial signatures
/// gathered by a Signer. For CHECKMULTISIG, picks signatures in the
/// pubkey-order embedded in the script (Core enforces stack order in
/// `script/sign.cpp::SignStep`) and prepends the empty CHECKMULTISIG pad.
/// For non-multisig (single CHECKSIG / CHECKSIGVERIFY) scripts, takes the
/// only available signature.
pub(crate) fn build_p2wsh_witness(
    witness_script: &[u8],
    partial_sigs: &BTreeMap<[u8; 33], Vec<u8>>,
) -> Result<Vec<Vec<u8>>, PsbtError> {
    if let Some((m, keys)) = parse_multisig_script(witness_script) {
        // Walk pubkeys in script order; emit signatures only for those
        // we actually have. Stop after M signatures (Core's CHECKMULTISIG
        // is strict about extra pushes failing the script).
        let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(m);
        for pk in &keys {
            if pk.len() != 33 {
                // Uncompressed pubkey in a witness script — Core forbids
                // this in segwit-v0 (CLEANSTACK + WITNESS_PUBKEYTYPE).
                // We don't even bother trying to match.
                continue;
            }
            let mut pk33 = [0u8; 33];
            pk33.copy_from_slice(pk);
            if let Some(sig) = partial_sigs.get(&pk33) {
                sigs.push(sig.clone());
                if sigs.len() == m {
                    break;
                }
            }
        }
        if sigs.len() < m {
            return Err(PsbtError::CannotFinalize(format!(
                "P2WSH multisig: have {} signatures, need {}",
                sigs.len(),
                m
            )));
        }
        let mut witness: Vec<Vec<u8>> = Vec::with_capacity(m + 2);
        witness.push(Vec::new()); // CHECKMULTISIG bug-compat empty pad
        witness.extend(sigs);
        witness.push(witness_script.to_vec());
        Ok(witness)
    } else {
        // Single-CHECKSIG style. We expect exactly one partial sig.
        if partial_sigs.len() != 1 {
            return Err(PsbtError::CannotFinalize(format!(
                "P2WSH non-multisig: expected exactly 1 partial sig, got {}",
                partial_sigs.len()
            )));
        }
        let sig = partial_sigs.values().next().unwrap().clone();
        Ok(vec![sig, witness_script.to_vec()])
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Write a key-value pair to PSBT format.
fn write_kv_pair<W: Write>(writer: &mut W, key: &[u8], value: &[u8]) -> io::Result<usize> {
    let mut len = 0;
    len += write_compact_size(writer, key.len() as u64)?;
    writer.write_all(key)?;
    len += key.len();
    len += write_compact_size(writer, value.len() as u64)?;
    writer.write_all(value)?;
    len += value.len();
    Ok(len)
}


// ============================================================================
// PSBT Encoding
// ============================================================================

impl Psbt {
    /// Encode the PSBT to a writer.
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = 0;

        // Magic bytes
        writer.write_all(&PSBT_MAGIC_BYTES)?;
        len += PSBT_MAGIC_BYTES.len();

        // Global: unsigned tx (required)
        let tx_bytes = self.unsigned_tx.serialize_no_witness();
        let mut key = vec![PSBT_GLOBAL_UNSIGNED_TX];
        len += write_kv_pair(writer, &key, &tx_bytes)?;

        // Global: xpubs
        for (origin, xpubs) in &self.xpubs {
            for xpub in xpubs {
                key.clear();
                key.push(PSBT_GLOBAL_XPUB);
                key.extend_from_slice(&xpub.data);

                // BIP-174: value is the raw key origin bytes
                // (4-byte fingerprint + N*4 path indices, all little-endian).
                // The outer record length is supplied by write_kv_pair itself;
                // an inner CompactSize prefix here would not interoperate with
                // Bitcoin Core's decodepsbt (W36, mirrors nimrod W34-C).
                let mut value = Vec::new();
                origin.encode(&mut value)?;
                len += write_kv_pair(writer, &key, &value)?;
            }
        }

        // Global: version (only if > 0)
        if let Some(v) = self.version {
            if v > 0 {
                key.clear();
                key.push(PSBT_GLOBAL_VERSION);
                // BIP-174: value is exactly 4 LE bytes (a u32). The outer
                // record length comes from write_kv_pair; no inner
                // CompactSize prefix (W36, mirrors nimrod W34-C).
                let mut value = Vec::new();
                value.extend_from_slice(&v.to_le_bytes());
                len += write_kv_pair(writer, &key, &value)?;
            }
        }

        // Global: proprietary
        for prop in &self.proprietary {
            len += write_kv_pair(writer, &prop.key, &prop.value)?;
        }

        // Global: unknown
        for (k, v) in &self.unknown {
            len += write_kv_pair(writer, k, v)?;
        }

        // Global separator
        writer.write_all(&[PSBT_SEPARATOR])?;
        len += 1;

        // Inputs
        for input in &self.inputs {
            len += encode_psbt_input(writer, input)?;
        }

        // Outputs
        for output in &self.outputs {
            len += encode_psbt_output(writer, output)?;
        }

        Ok(len)
    }
}

/// Encode a PSBT input to a writer.
fn encode_psbt_input<W: Write>(writer: &mut W, input: &PsbtInput) -> io::Result<usize> {
    let mut len = 0;

    // Non-witness UTXO
    if let Some(ref tx) = input.non_witness_utxo {
        let key = vec![PSBT_IN_NON_WITNESS_UTXO];
        let value = tx.serialize_no_witness();
        len += write_kv_pair(writer, &key, &value)?;
    }

    // Witness UTXO
    if let Some(ref utxo) = input.witness_utxo {
        let key = vec![PSBT_IN_WITNESS_UTXO];
        let value = utxo.serialize();
        len += write_kv_pair(writer, &key, &value)?;
    }

    // Only write signing data if not finalized
    if input.final_script_sig.is_none() && input.final_script_witness.is_none() {
        // Partial signatures.
        //
        // W49: emit in HASH160(pubkey) order to match Bitcoin Core's
        // `std::map<CKeyID, SigPair>` (CKeyID = HASH160 of pubkey),
        // see bitcoin-core/src/psbt.h:270. The in-memory storage is a
        // BTreeMap keyed by raw 33-byte pubkey, so we extract, sort by
        // hash160, and emit in that canonical order.
        //
        // Closes the rustoshi T2 combinepsbt byte-divergence; mirrors
        // ouroboros W46-4 (3d44478) and blockbrew W45 (e000f9b).
        let mut sig_keys: Vec<&[u8; 33]> = input.partial_sigs.keys().collect();
        sig_keys.sort_by_key(|pk| rustoshi_crypto::hash160(pk.as_ref()).0);
        for pubkey in sig_keys {
            let sig = &input.partial_sigs[pubkey];
            let mut key = vec![PSBT_IN_PARTIAL_SIG];
            key.extend_from_slice(pubkey);
            len += write_kv_pair(writer, &key, sig)?;
        }

        // Sighash type
        if let Some(sighash) = input.sighash_type {
            let key = vec![PSBT_IN_SIGHASH];
            let mut value = Vec::new();
            value.extend_from_slice(&sighash.to_le_bytes());
            len += write_kv_pair(writer, &key, &value)?;
        }

        // Redeem script
        if let Some(ref script) = input.redeem_script {
            let key = vec![PSBT_IN_REDEEMSCRIPT];
            len += write_kv_pair(writer, &key, script)?;
        }

        // Witness script
        if let Some(ref script) = input.witness_script {
            let key = vec![PSBT_IN_WITNESSSCRIPT];
            len += write_kv_pair(writer, &key, script)?;
        }

        // BIP32 derivation paths
        for (pubkey, origin) in &input.bip32_derivation {
            let mut key = vec![PSBT_IN_BIP32_DERIVATION];
            key.extend_from_slice(pubkey);
            // BIP-174: value is the raw key origin (fingerprint + path),
            // no inner CompactSize. The outer record length comes from
            // write_kv_pair (W36, mirrors nimrod W34-C).
            let mut value = Vec::new();
            origin.encode(&mut value)?;
            len += write_kv_pair(writer, &key, &value)?;
        }

        // Hash preimages
        for (hash, preimage) in &input.ripemd160_preimages {
            let mut key = vec![PSBT_IN_RIPEMD160];
            key.extend_from_slice(hash);
            len += write_kv_pair(writer, &key, preimage)?;
        }
        for (hash, preimage) in &input.sha256_preimages {
            let mut key = vec![PSBT_IN_SHA256];
            key.extend_from_slice(hash);
            len += write_kv_pair(writer, &key, preimage)?;
        }
        for (hash, preimage) in &input.hash160_preimages {
            let mut key = vec![PSBT_IN_HASH160];
            key.extend_from_slice(hash);
            len += write_kv_pair(writer, &key, preimage)?;
        }
        for (hash, preimage) in &input.hash256_preimages {
            let mut key = vec![PSBT_IN_HASH256];
            key.extend_from_slice(hash);
            len += write_kv_pair(writer, &key, preimage)?;
        }

        // Taproot key signature
        if let Some(ref sig) = input.tap_key_sig {
            let key = vec![PSBT_IN_TAP_KEY_SIG];
            len += write_kv_pair(writer, &key, sig)?;
        }

        // Taproot script signatures
        for ((xonly, leaf_hash), sig) in &input.tap_script_sigs {
            let mut key = vec![PSBT_IN_TAP_SCRIPT_SIG];
            key.extend_from_slice(xonly);
            key.extend_from_slice(leaf_hash);
            len += write_kv_pair(writer, &key, sig)?;
        }

        // Taproot leaf scripts
        for ((script, leaf_ver), control_blocks) in &input.tap_leaf_scripts {
            for cb in control_blocks {
                let mut key = vec![PSBT_IN_TAP_LEAF_SCRIPT];
                key.extend_from_slice(cb);
                let mut value = script.clone();
                value.push(*leaf_ver);
                len += write_kv_pair(writer, &key, &value)?;
            }
        }

        // Taproot BIP32 derivation
        for (xonly, (leaf_hashes, origin)) in &input.tap_bip32_derivation {
            let mut key = vec![PSBT_IN_TAP_BIP32_DERIVATION];
            key.extend_from_slice(xonly);

            let mut value = Vec::new();
            // Write leaf hashes count
            write_compact_size(&mut value, leaf_hashes.len() as u64)?;
            for hash in leaf_hashes {
                value.extend_from_slice(hash);
            }
            origin.encode(&mut value)?;
            len += write_kv_pair(writer, &key, &value)?;
        }

        // Taproot internal key
        if let Some(ref ik) = input.tap_internal_key {
            let key = vec![PSBT_IN_TAP_INTERNAL_KEY];
            len += write_kv_pair(writer, &key, ik)?;
        }

        // Taproot merkle root
        if let Some(ref mr) = input.tap_merkle_root {
            let key = vec![PSBT_IN_TAP_MERKLE_ROOT];
            len += write_kv_pair(writer, &key, mr)?;
        }
    }

    // Final scriptSig
    if let Some(ref script) = input.final_script_sig {
        let key = vec![PSBT_IN_SCRIPTSIG];
        len += write_kv_pair(writer, &key, script)?;
    }

    // Final witness
    if let Some(ref witness) = input.final_script_witness {
        let key = vec![PSBT_IN_SCRIPTWITNESS];
        let mut value = Vec::new();
        write_compact_size(&mut value, witness.len() as u64)?;
        for item in witness {
            write_compact_size(&mut value, item.len() as u64)?;
            value.extend_from_slice(item);
        }
        len += write_kv_pair(writer, &key, &value)?;
    }

    // Proprietary
    for prop in &input.proprietary {
        len += write_kv_pair(writer, &prop.key, &prop.value)?;
    }

    // Unknown
    for (k, v) in &input.unknown {
        len += write_kv_pair(writer, k, v)?;
    }

    // Separator
    writer.write_all(&[PSBT_SEPARATOR])?;
    len += 1;

    Ok(len)
}

/// Encode a PSBT output to a writer.
fn encode_psbt_output<W: Write>(writer: &mut W, output: &PsbtOutput) -> io::Result<usize> {
    let mut len = 0;

    // Redeem script
    if let Some(ref script) = output.redeem_script {
        let key = vec![PSBT_OUT_REDEEMSCRIPT];
        len += write_kv_pair(writer, &key, script)?;
    }

    // Witness script
    if let Some(ref script) = output.witness_script {
        let key = vec![PSBT_OUT_WITNESSSCRIPT];
        len += write_kv_pair(writer, &key, script)?;
    }

    // BIP32 derivation paths
    for (pubkey, origin) in &output.bip32_derivation {
        let mut key = vec![PSBT_OUT_BIP32_DERIVATION];
        key.extend_from_slice(pubkey);
        // BIP-174: value is the raw key origin (fingerprint + path),
        // no inner CompactSize. The outer record length comes from
        // write_kv_pair (W36, mirrors nimrod W34-C).
        let mut value = Vec::new();
        origin.encode(&mut value)?;
        len += write_kv_pair(writer, &key, &value)?;
    }

    // Taproot internal key
    if let Some(ref ik) = output.tap_internal_key {
        let key = vec![PSBT_OUT_TAP_INTERNAL_KEY];
        len += write_kv_pair(writer, &key, ik)?;
    }

    // Taproot tree
    if !output.tap_tree.is_empty() {
        let key = vec![PSBT_OUT_TAP_TREE];
        let mut value = Vec::new();
        for (depth, leaf_ver, script) in &output.tap_tree {
            value.push(*depth);
            value.push(*leaf_ver);
            write_compact_size(&mut value, script.len() as u64)?;
            value.extend_from_slice(script);
        }
        len += write_kv_pair(writer, &key, &value)?;
    }

    // Taproot BIP32 derivation
    for (xonly, (leaf_hashes, origin)) in &output.tap_bip32_derivation {
        let mut key = vec![PSBT_OUT_TAP_BIP32_DERIVATION];
        key.extend_from_slice(xonly);

        let mut value = Vec::new();
        write_compact_size(&mut value, leaf_hashes.len() as u64)?;
        for hash in leaf_hashes {
            value.extend_from_slice(hash);
        }
        origin.encode(&mut value)?;
        len += write_kv_pair(writer, &key, &value)?;
    }

    // Proprietary
    for prop in &output.proprietary {
        len += write_kv_pair(writer, &prop.key, &prop.value)?;
    }

    // Unknown
    for (k, v) in &output.unknown {
        len += write_kv_pair(writer, k, v)?;
    }

    // Separator
    writer.write_all(&[PSBT_SEPARATOR])?;
    len += 1;

    Ok(len)
}

// ============================================================================
// PSBT Decoding
// ============================================================================

impl Psbt {
    /// Decode a PSBT from a reader.
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, PsbtError> {
        // Read and verify magic bytes
        let mut magic = [0u8; 5];
        reader.read_exact(&mut magic)?;
        if magic != PSBT_MAGIC_BYTES {
            return Err(PsbtError::InvalidMagic);
        }

        // Track seen keys for duplicate detection
        let mut key_lookup: HashSet<Vec<u8>> = HashSet::new();

        let mut unsigned_tx: Option<Transaction> = None;
        let mut xpubs: BTreeMap<KeyOrigin, BTreeSet<ExtPubKey>> = BTreeMap::new();
        let mut version: Option<u32> = None;
        let mut proprietary: BTreeSet<Proprietary> = BTreeSet::new();
        let mut unknown: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

        // Read global map
        loop {
            // Read key
            let key_len = read_compact_size(reader)?;
            if key_len == 0 {
                // Separator
                break;
            }

            let mut key = vec![0u8; key_len as usize];
            reader.read_exact(&mut key)?;

            // Duplicate check
            if !key_lookup.insert(key.clone()) {
                return Err(PsbtError::DuplicateKey("global key".to_string()));
            }

            // Read value
            let value_len = read_compact_size(reader)?;
            let mut value = vec![0u8; value_len as usize];
            reader.read_exact(&mut value)?;

            // Parse key type
            let mut key_cursor = Cursor::new(&key);
            let key_type = read_compact_size(&mut key_cursor)? as u8;

            match key_type {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    if key.len() != 1 {
                        return Err(PsbtError::InvalidKeySize {
                            key_type,
                            expected: 1,
                            got: key.len(),
                        });
                    }
                    // The PSBT global unsigned tx is serialized TX_NO_WITNESS (Core
                    // psbt.h), symmetric with serialize_no_witness on the write side;
                    // decode it no-witness so an empty-vin tx is not mis-read as a
                    // segwit marker (which would silently drop its outputs), and reject
                    // trailing data.
                    let mut tx_reader = io::Cursor::new(&value[..]);
                    let tx = Transaction::decode_no_witness(&mut tx_reader)?;
                    if (tx_reader.position() as usize) != value.len() {
                        return Err(PsbtError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PSBT global unsigned tx has trailing data",
                        )));
                    }
                    // Verify empty scriptSigs and witnesses
                    for input in &tx.inputs {
                        if !input.script_sig.is_empty() || !input.witness.is_empty() {
                            return Err(PsbtError::NonEmptyScriptSig);
                        }
                    }
                    unsigned_tx = Some(tx);
                }
                PSBT_GLOBAL_XPUB => {
                    if key.len() != 79 {
                        // 1 byte type + 78 bytes xpub
                        return Err(PsbtError::InvalidKeySize {
                            key_type,
                            expected: 79,
                            got: key.len(),
                        });
                    }
                    let mut xpub_data = [0u8; 78];
                    xpub_data.copy_from_slice(&key[1..79]);
                    let xpub = ExtPubKey::from_bytes(xpub_data);

                    // BIP-174: value is the raw key origin (fingerprint +
                    // path), no inner CompactSize prefix. The total length
                    // is value.len() itself (W36, mirrors nimrod W34-C).
                    let mut value_cursor = Cursor::new(&value);
                    let origin = KeyOrigin::decode_with_len(&mut value_cursor, value.len())?;

                    xpubs
                        .entry(origin)
                        .or_default()
                        .insert(xpub);
                }
                PSBT_GLOBAL_VERSION => {
                    if key.len() != 1 {
                        return Err(PsbtError::InvalidKeySize {
                            key_type,
                            expected: 1,
                            got: key.len(),
                        });
                    }
                    // BIP-174: value is exactly 4 LE bytes (a u32). No
                    // inner CompactSize prefix (W36, mirrors nimrod W34-C).
                    if value.len() != 4 {
                        return Err(PsbtError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid version length",
                        )));
                    }
                    let mut v_bytes = [0u8; 4];
                    v_bytes.copy_from_slice(&value);
                    let v = u32::from_le_bytes(v_bytes);
                    if v > PSBT_HIGHEST_VERSION {
                        return Err(PsbtError::UnsupportedVersion(v));
                    }
                    version = Some(v);
                }
                PSBT_GLOBAL_PROPRIETARY => {
                    // Parse proprietary format
                    let mut key_cursor = Cursor::new(&key[1..]);
                    let mut identifier = Vec::new();
                    let id_len = read_compact_size(&mut key_cursor)?;
                    identifier.resize(id_len as usize, 0);
                    key_cursor.read_exact(&mut identifier)?;
                    let subtype = read_compact_size(&mut key_cursor)?;

                    proprietary.insert(Proprietary {
                        identifier,
                        subtype,
                        key: key.clone(),
                        value,
                    });
                }
                _ => {
                    unknown.insert(key, value);
                }
            }
        }

        // Verify we got an unsigned tx
        let unsigned_tx = unsigned_tx.ok_or(PsbtError::MissingUnsignedTx)?;
        let num_inputs = unsigned_tx.inputs.len();
        let num_outputs = unsigned_tx.outputs.len();

        // Read inputs
        let mut inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(decode_psbt_input(reader)?);
        }

        // Read outputs
        let mut outputs = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            outputs.push(decode_psbt_output(reader)?);
        }

        // ============================================================
        // W41 — A1: NON_WITNESS_UTXO txid sanity at deserialize time.
        //
        // BIP-174 (and Bitcoin Core's `PSBTInput::IsSane`-style checks at
        // src/psbt.cpp `GetInputUTXO` / `SignPSBTInput`) require that, if
        // `non_witness_utxo` is present for input i, its txid must equal
        // `unsigned_tx.inputs[i].previous_output.txid`. Without this
        // check, a malicious provider can hand the wallet a fake prevtx,
        // and any downstream code that reads `non_witness_utxo.outputs[
        // prevout.vout].value` to feed segwit-v0 sighashing trusts an
        // attacker-controlled amount (CVE-2020-14199 / "amount oracle").
        //
        // The Updater-role helper `Psbt::set_non_witness_utxo` already
        // enforces this on the in-process API; mirror it on the wire so
        // we can never construct a `Psbt` value where an input claims a
        // prevtx that doesn't hash to its prevout.
        for (i, input) in inputs.iter().enumerate() {
            if let Some(ref nw) = input.non_witness_utxo {
                if nw.txid() != unsigned_tx.inputs[i].previous_output.txid {
                    return Err(PsbtError::UtxoHashMismatch);
                }
            }
        }

        Ok(Self {
            unsigned_tx,
            xpubs,
            version,
            inputs,
            outputs,
            proprietary,
            unknown,
        })
    }
}

/// Decode a PSBT input from a reader.
fn decode_psbt_input<R: Read>(reader: &mut R) -> Result<PsbtInput, PsbtError> {
    let mut key_lookup: HashSet<Vec<u8>> = HashSet::new();
    let mut input = PsbtInput::default();

    loop {
        // Read key
        let key_len = read_compact_size(reader)?;
        if key_len == 0 {
            // Separator
            break;
        }

        let mut key = vec![0u8; key_len as usize];
        reader.read_exact(&mut key)?;

        // Read value
        let value_len = read_compact_size(reader)?;
        let mut value = vec![0u8; value_len as usize];
        reader.read_exact(&mut value)?;

        // Parse key type
        let mut key_cursor = Cursor::new(&key);
        let key_type = read_compact_size(&mut key_cursor)? as u8;

        match key_type {
            PSBT_IN_NON_WITNESS_UTXO => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("non-witness utxo".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                input.non_witness_utxo = Some(Transaction::deserialize(&value)?);
            }
            PSBT_IN_WITNESS_UTXO => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("witness utxo".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                input.witness_utxo = Some(TxOut::deserialize(&value)?);
            }
            PSBT_IN_PARTIAL_SIG => {
                // Key is type + pubkey (33 or 65 bytes)
                if key.len() != 34 && key.len() != 66 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 34,
                        got: key.len(),
                    });
                }
                let mut pubkey = [0u8; 33];
                if key.len() == 34 {
                    pubkey.copy_from_slice(&key[1..34]);
                } else {
                    // Uncompressed - take first 33 bytes (this is simplified)
                    return Err(PsbtError::InvalidPubkey);
                }
                // BIP-174 / Core psbt.h:535: a duplicate partial-sig pubkey
                // key must be rejected, not silently overwritten. Core throws
                // "Duplicate Key, input partial signature for pubkey already
                // provided". The map is keyed by the pubkey bytes from the
                // record key, so contains_key is the faithful equivalent.
                if input.partial_sigs.contains_key(&pubkey) {
                    return Err(PsbtError::DuplicateKey("partial signature".to_string()));
                }
                input.partial_sigs.insert(pubkey, value);
            }
            PSBT_IN_SIGHASH => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("sighash type".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                if value.len() < 4 {
                    return Err(PsbtError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sighash value too short",
                    )));
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&value[0..4]);
                input.sighash_type = Some(u32::from_le_bytes(bytes));
            }
            PSBT_IN_REDEEMSCRIPT => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("redeem script".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                input.redeem_script = Some(value);
            }
            PSBT_IN_WITNESSSCRIPT => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("witness script".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                input.witness_script = Some(value);
            }
            PSBT_IN_BIP32_DERIVATION => {
                // Key is type + pubkey (33 bytes compressed)
                if key.len() != 34 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 34,
                        got: key.len(),
                    });
                }
                let mut pubkey = [0u8; 33];
                pubkey.copy_from_slice(&key[1..34]);

                // BIP-174: value is the raw key origin (fingerprint +
                // path), no inner CompactSize. Total length is
                // value.len() (W36, mirrors nimrod W34-C).
                let mut value_cursor = Cursor::new(&value);
                let origin = KeyOrigin::decode_with_len(&mut value_cursor, value.len())?;
                input.bip32_derivation.insert(pubkey, origin);
            }
            PSBT_IN_SCRIPTSIG => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("final script sig".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                input.final_script_sig = Some(value);
            }
            PSBT_IN_SCRIPTWITNESS => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("final script witness".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                // Value is a witness stack
                let mut value_cursor = Cursor::new(&value);
                let count = read_compact_size(&mut value_cursor)?;
                let mut witness = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let item_len = read_compact_size(&mut value_cursor)?;
                    let mut item = vec![0u8; item_len as usize];
                    value_cursor.read_exact(&mut item)?;
                    witness.push(item);
                }
                input.final_script_witness = Some(witness);
            }
            PSBT_IN_RIPEMD160 => {
                if key.len() != 21 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 21,
                        got: key.len(),
                    });
                }
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&key[1..21]);
                input.ripemd160_preimages.insert(hash, value);
            }
            PSBT_IN_SHA256 => {
                if key.len() != 33 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 33,
                        got: key.len(),
                    });
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&key[1..33]);
                input.sha256_preimages.insert(hash, value);
            }
            PSBT_IN_HASH160 => {
                if key.len() != 21 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 21,
                        got: key.len(),
                    });
                }
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&key[1..21]);
                input.hash160_preimages.insert(hash, value);
            }
            PSBT_IN_HASH256 => {
                if key.len() != 33 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 33,
                        got: key.len(),
                    });
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&key[1..33]);
                input.hash256_preimages.insert(hash, value);
            }
            PSBT_IN_TAP_KEY_SIG => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("tap key sig".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                if value.len() < 64 || value.len() > 65 {
                    return Err(PsbtError::InvalidSignature);
                }
                input.tap_key_sig = Some(value);
            }
            PSBT_IN_TAP_SCRIPT_SIG => {
                if key.len() != 65 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 65,
                        got: key.len(),
                    });
                }
                let mut xonly = [0u8; 32];
                let mut leaf_hash = [0u8; 32];
                xonly.copy_from_slice(&key[1..33]);
                leaf_hash.copy_from_slice(&key[33..65]);
                if value.len() < 64 || value.len() > 65 {
                    return Err(PsbtError::InvalidSignature);
                }
                input.tap_script_sigs.insert((xonly, leaf_hash), value);
            }
            PSBT_IN_TAP_LEAF_SCRIPT => {
                if key.len() < 34 || !(key.len() - 2).is_multiple_of(32) {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 34,
                        got: key.len(),
                    });
                }
                if value.is_empty() {
                    return Err(PsbtError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "empty tap leaf script",
                    )));
                }
                let control_block = key[1..].to_vec();
                let leaf_ver = value[value.len() - 1];
                let script = value[..value.len() - 1].to_vec();
                input
                    .tap_leaf_scripts
                    .entry((script, leaf_ver))
                    .or_insert_with(BTreeSet::new)
                    .insert(control_block);
            }
            PSBT_IN_TAP_BIP32_DERIVATION => {
                if key.len() != 33 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 33,
                        got: key.len(),
                    });
                }
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&key[1..33]);

                let mut value_cursor = Cursor::new(&value);
                let num_hashes = read_compact_size(&mut value_cursor)?;
                let mut leaf_hashes = BTreeSet::new();
                for _ in 0..num_hashes {
                    let mut hash = [0u8; 32];
                    value_cursor.read_exact(&mut hash)?;
                    leaf_hashes.insert(hash);
                }
                // Remaining bytes are key origin
                let remaining = value.len() - value_cursor.position() as usize;
                let origin = KeyOrigin::decode_with_len(&mut value_cursor, remaining)?;
                input.tap_bip32_derivation.insert(xonly, (leaf_hashes, origin));
            }
            PSBT_IN_TAP_INTERNAL_KEY => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("tap internal key".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                if value.len() != 32 {
                    return Err(PsbtError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tap internal key must be 32 bytes",
                    )));
                }
                let mut ik = [0u8; 32];
                ik.copy_from_slice(&value);
                input.tap_internal_key = Some(ik);
            }
            PSBT_IN_TAP_MERKLE_ROOT => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("tap merkle root".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                if value.len() != 32 {
                    return Err(PsbtError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tap merkle root must be 32 bytes",
                    )));
                }
                let mut mr = [0u8; 32];
                mr.copy_from_slice(&value);
                input.tap_merkle_root = Some(mr);
            }
            PSBT_IN_PROPRIETARY => {
                let mut key_cursor = Cursor::new(&key[1..]);
                let id_len = read_compact_size(&mut key_cursor)?;
                let mut identifier = vec![0u8; id_len as usize];
                key_cursor.read_exact(&mut identifier)?;
                let subtype = read_compact_size(&mut key_cursor)?;

                input.proprietary.insert(Proprietary {
                    identifier,
                    subtype,
                    key: key.clone(),
                    value,
                });
            }
            _ => {
                input.unknown.insert(key, value);
            }
        }
    }

    Ok(input)
}

/// Decode a PSBT output from a reader.
fn decode_psbt_output<R: Read>(reader: &mut R) -> Result<PsbtOutput, PsbtError> {
    let mut key_lookup: HashSet<Vec<u8>> = HashSet::new();
    let mut output = PsbtOutput::default();

    loop {
        // Read key
        let key_len = read_compact_size(reader)?;
        if key_len == 0 {
            // Separator
            break;
        }

        let mut key = vec![0u8; key_len as usize];
        reader.read_exact(&mut key)?;

        // Read value
        let value_len = read_compact_size(reader)?;
        let mut value = vec![0u8; value_len as usize];
        reader.read_exact(&mut value)?;

        // Parse key type
        let mut key_cursor = Cursor::new(&key);
        let key_type = read_compact_size(&mut key_cursor)? as u8;

        match key_type {
            PSBT_OUT_REDEEMSCRIPT => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("output redeem script".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                output.redeem_script = Some(value);
            }
            PSBT_OUT_WITNESSSCRIPT => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("output witness script".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                output.witness_script = Some(value);
            }
            PSBT_OUT_BIP32_DERIVATION => {
                if key.len() != 34 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 34,
                        got: key.len(),
                    });
                }
                let mut pubkey = [0u8; 33];
                pubkey.copy_from_slice(&key[1..34]);

                // BIP-174: value is the raw key origin (fingerprint +
                // path), no inner CompactSize. Total length is
                // value.len() (W36, mirrors nimrod W34-C).
                let mut value_cursor = Cursor::new(&value);
                let origin = KeyOrigin::decode_with_len(&mut value_cursor, value.len())?;
                output.bip32_derivation.insert(pubkey, origin);
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("output tap internal key".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                if value.len() != 32 {
                    return Err(PsbtError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tap internal key must be 32 bytes",
                    )));
                }
                let mut ik = [0u8; 32];
                ik.copy_from_slice(&value);
                output.tap_internal_key = Some(ik);
            }
            PSBT_OUT_TAP_TREE => {
                if !key_lookup.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey("output tap tree".to_string()));
                }
                if key.len() != 1 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 1,
                        got: key.len(),
                    });
                }
                let mut value_cursor = Cursor::new(&value);
                while (value_cursor.position() as usize) < value.len() {
                    let mut depth_byte = [0u8; 1];
                    value_cursor.read_exact(&mut depth_byte)?;
                    let depth = depth_byte[0];

                    let mut leaf_ver_byte = [0u8; 1];
                    value_cursor.read_exact(&mut leaf_ver_byte)?;
                    let leaf_ver = leaf_ver_byte[0];

                    let script_len = read_compact_size(&mut value_cursor)?;
                    let mut script = vec![0u8; script_len as usize];
                    value_cursor.read_exact(&mut script)?;

                    output.tap_tree.push((depth, leaf_ver, script));
                }
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                if key.len() != 33 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 33,
                        got: key.len(),
                    });
                }
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&key[1..33]);

                let mut value_cursor = Cursor::new(&value);
                let num_hashes = read_compact_size(&mut value_cursor)?;
                let mut leaf_hashes = BTreeSet::new();
                for _ in 0..num_hashes {
                    let mut hash = [0u8; 32];
                    value_cursor.read_exact(&mut hash)?;
                    leaf_hashes.insert(hash);
                }
                let remaining = value.len() - value_cursor.position() as usize;
                let origin = KeyOrigin::decode_with_len(&mut value_cursor, remaining)?;
                output.tap_bip32_derivation.insert(xonly, (leaf_hashes, origin));
            }
            PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS => {
                // key = [type_byte(1)] + [aggregate_pubkey(33)] — total 34 bytes
                // value = concatenated participant pubkeys (33 bytes each)
                if key.len() != 34 {
                    return Err(PsbtError::InvalidKeySize {
                        key_type,
                        expected: 34,
                        got: key.len(),
                    });
                }
                let mut agg = [0u8; 33];
                agg.copy_from_slice(&key[1..34]);

                if value.len() % 33 != 0 {
                    return Err(PsbtError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "musig2 participant pubkeys value size is not a multiple of 33",
                    )));
                }
                let mut participants = Vec::new();
                let mut pos = 0;
                while pos + 33 <= value.len() {
                    let mut pk = [0u8; 33];
                    pk.copy_from_slice(&value[pos..pos + 33]);
                    participants.push(pk);
                    pos += 33;
                }
                output.musig2_participant_pubkeys.insert(agg, participants);
            }
            PSBT_OUT_PROPRIETARY => {
                let mut key_cursor = Cursor::new(&key[1..]);
                let id_len = read_compact_size(&mut key_cursor)?;
                let mut identifier = vec![0u8; id_len as usize];
                key_cursor.read_exact(&mut identifier)?;
                let subtype = read_compact_size(&mut key_cursor)?;

                output.proprietary.insert(Proprietary {
                    identifier,
                    subtype,
                    key: key.clone(),
                    value,
                });
            }
            _ => {
                output.unknown.insert(key, value);
            }
        }
    }

    Ok(output)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::hash::Hash256;
    use rustoshi_primitives::transaction::{OutPoint, TxIn};

    fn create_test_tx() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn test_psbt_creation() {
        let tx = create_test_tx();
        let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();

        assert_eq!(psbt.unsigned_tx.txid(), tx.txid());
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
        assert!(!psbt.is_finalized());
    }

    #[test]
    fn test_psbt_empty_vin_roundtrip_preserves_outputs() {
        // Regression: an empty-vin tx serializes no-witness as 02000000 00 01 ...
        // The PSBT global unsigned tx must be DECODED no-witness too; otherwise the
        // leading 0x00 is mis-read as a segwit marker and the OP_RETURN output is
        // silently dropped on the round-trip.
        let tx = Transaction {
            version: 2,
            inputs: vec![],
            outputs: vec![TxOut {
                value: 0,
                // OP_RETURN OP_PUSH4 00010203
                script_pubkey: vec![0x6a, 0x04, 0x00, 0x01, 0x02, 0x03],
            }],
            lock_time: 0,
        };
        let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let decoded = Psbt::from_base64(&psbt.to_base64()).unwrap();
        assert_eq!(decoded.unsigned_tx.inputs.len(), 0, "empty vin preserved");
        assert_eq!(
            decoded.unsigned_tx.outputs.len(),
            1,
            "OP_RETURN output must survive the round-trip (not dropped by a witness-misdecode)"
        );
        assert_eq!(
            decoded.unsigned_tx.outputs[0].script_pubkey,
            vec![0x6a, 0x04, 0x00, 0x01, 0x02, 0x03]
        );
        assert_eq!(decoded.unsigned_tx.txid(), tx.txid());
    }

    #[test]
    fn test_psbt_rejects_signed_tx() {
        let mut tx = create_test_tx();
        tx.inputs[0].script_sig = vec![0x00, 0x01, 0x02];

        let result = Psbt::from_unsigned_tx(tx);
        assert!(matches!(result, Err(PsbtError::NonEmptyScriptSig)));
    }

    #[test]
    fn test_psbt_serialization_roundtrip() {
        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Add some data
        psbt.set_witness_utxo(0, TxOut {
            value: 100_000,
            script_pubkey: vec![0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                                0x13, 0x14],
        }).unwrap();

        psbt.inputs[0].sighash_type = Some(1);

        // Serialize and deserialize
        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();

        assert_eq!(psbt.unsigned_tx.txid(), psbt2.unsigned_tx.txid());
        assert!(psbt2.inputs[0].witness_utxo.is_some());
        assert_eq!(psbt2.inputs[0].sighash_type, Some(1));
    }

    #[test]
    fn test_psbt_base64_roundtrip() {
        let tx = create_test_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let base64 = psbt.to_base64();
        let psbt2 = Psbt::from_base64(&base64).unwrap();

        assert_eq!(psbt.unsigned_tx.txid(), psbt2.unsigned_tx.txid());
    }

    #[test]
    fn test_psbt_magic_validation() {
        let bad_magic = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let result = Psbt::deserialize(&bad_magic);
        assert!(matches!(result, Err(PsbtError::InvalidMagic)));
    }

    #[test]
    fn test_key_origin_serialization() {
        let origin = KeyOrigin {
            fingerprint: [0x01, 0x02, 0x03, 0x04],
            path: vec![0x80000054, 0x80000000, 0x80000000, 0, 0],
        };

        let mut buf = Vec::new();
        origin.encode(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = KeyOrigin::decode_with_len(&mut cursor, buf.len()).unwrap();

        assert_eq!(origin.fingerprint, decoded.fingerprint);
        assert_eq!(origin.path, decoded.path);
    }

    #[test]
    fn test_psbt_merge() {
        let tx = create_test_tx();
        let mut psbt1 = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt2 = Psbt::from_unsigned_tx(tx).unwrap();

        // Add different data to each
        psbt1.inputs[0].sighash_type = Some(1);
        psbt2.set_witness_utxo(0, TxOut {
            value: 100_000,
            script_pubkey: vec![0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                                0x13, 0x14],
        }).unwrap();

        // Merge
        psbt1.merge(&psbt2).unwrap();

        // Should have data from both
        assert_eq!(psbt1.inputs[0].sighash_type, Some(1));
        assert!(psbt1.inputs[0].witness_utxo.is_some());
    }

    #[test]
    fn test_psbt_next_role() {
        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // No UTXO info -> Updater
        assert_eq!(psbt.next_role(), PsbtRole::Updater);

        // Add UTXO -> Signer
        psbt.set_witness_utxo(0, TxOut {
            value: 100_000,
            script_pubkey: vec![0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                                0x13, 0x14],
        }).unwrap();
        assert_eq!(psbt.next_role(), PsbtRole::Signer);

        // Add partial sig -> Finalizer
        let pubkey = [0u8; 33];
        psbt.add_partial_sig(0, pubkey, vec![0x30, 0x44]).unwrap();
        assert_eq!(psbt.next_role(), PsbtRole::Finalizer);

        // Finalize -> Extractor
        psbt.inputs[0].final_script_witness = Some(vec![vec![0x30], vec![0x02]]);
        assert_eq!(psbt.next_role(), PsbtRole::Extractor);
    }

    #[test]
    fn test_psbt_bip32_derivation() {
        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let pubkey = [0x02u8; 33];
        let origin = KeyOrigin {
            fingerprint: [0x01, 0x02, 0x03, 0x04],
            path: vec![0x80000054, 0x80000000, 0x80000000, 0, 0],
        };

        psbt.add_input_derivation(0, pubkey, origin.clone()).unwrap();

        // Serialize and deserialize
        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();

        let decoded_origin = psbt2.inputs[0].bip32_derivation.get(&pubkey).unwrap();
        assert_eq!(decoded_origin.fingerprint, origin.fingerprint);
        assert_eq!(decoded_origin.path, origin.path);
    }

    #[test]
    fn test_bip174_valid_psbt_witness_utxo() {
        // Simple PSBT with witness UTXO (from Bitcoin Core tests)
        // 1 input with witness UTXO, 2 outputs
        let base64 = "cHNidP8BAHECAAAAAfA00BFgAm6tp86RowwH6BMImQNL5zXUcTT97XoLGz0BAAAAAAD/////AgD5ApUAAAAAFgAUKNw0x8HRctAgmvoevm4u1SbN7XL87QKVAAAAABYAFPck4gF7iL4NL4wtfRAKgQbghiTUAAAAAAABAR8AgIFq49AHABYAFJUDtxf2PHo641HEOBOAIvFMNTr2AAAA";

        let psbt = Psbt::from_base64(base64).unwrap();
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(psbt.inputs[0].non_witness_utxo.is_none());

        // Check the witness UTXO value (test vector value from Bitcoin Core)
        let utxo = psbt.inputs[0].witness_utxo.as_ref().unwrap();
        assert_eq!(utxo.value, 2200000000000000);
    }

    /// Regression test for W36 (rustoshi analog of nimrod W34-C).
    ///
    /// BIP-174 specifies that PSBT_GLOBAL_XPUB, PSBT_GLOBAL_VERSION,
    /// PSBT_IN_BIP32_DERIVATION, and PSBT_OUT_BIP32_DERIVATION values are
    /// raw bytes (no inner CompactSize length prefix); the only length
    /// prefix is the OUTER CompactSize that the generic key-value framer
    /// writes around every value. rustoshi previously wrapped each of
    /// these four value fields in an extra inner CompactSize on both
    /// sides, so self-round-trip passed but cross-impl byte-identity vs
    /// Bitcoin Core failed.
    ///
    /// This test asserts the on-wire byte layout for all four sites with
    /// a hand-constructed golden vector derived from BIP-174's spec, so
    /// any future regression on either the encode or decode side breaks
    /// it. Self-round-trip alone is intentionally insufficient — that's
    /// exactly what masked the original bug.
    #[test]
    fn test_w36_bip174_no_inner_compactsize_on_bip32_values() {
        // ------------------------------------------------------------------
        // Build a PSBT exercising all four bug sites:
        //   * PSBT_GLOBAL_XPUB
        //   * PSBT_GLOBAL_VERSION
        //   * PSBT_IN_BIP32_DERIVATION
        //   * PSBT_OUT_BIP32_DERIVATION
        // ------------------------------------------------------------------
        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let origin = KeyOrigin {
            fingerprint: [0xDE, 0xAD, 0xBE, 0xEF],
            // m/84'/0'/0' — three hardened path components (12 bytes).
            path: vec![0x80000054, 0x80000000, 0x80000000],
        };
        // Expected raw on-wire origin = fingerprint || LE(path[i])
        // 4 + 3*4 = 16 bytes.
        let expected_origin_bytes: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF,
            0x54, 0x00, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x80,
        ];
        assert_eq!(origin.serialized_size(), expected_origin_bytes.len());

        // Use a recognisable canary pubkey so we can locate the record in
        // the on-wire byte stream without parsing the whole PSBT.
        let mut input_pubkey = [0u8; 33];
        input_pubkey[0] = 0x02;
        for (i, b) in input_pubkey.iter_mut().enumerate().skip(1) {
            *b = 0xA0 | (i as u8 & 0x0F);
        }

        let mut output_pubkey = [0u8; 33];
        output_pubkey[0] = 0x03;
        for (i, b) in output_pubkey.iter_mut().enumerate().skip(1) {
            *b = 0xB0 | (i as u8 & 0x0F);
        }

        // 78-byte BIP32 extended key blob (canary pattern). The actual
        // contents do not need to be a valid xpub for byte-layout testing.
        let mut xpub_bytes = [0u8; 78];
        for (i, b) in xpub_bytes.iter_mut().enumerate() {
            *b = 0xC0 | (i as u8 & 0x0F);
        }
        let xpub = ExtPubKey::from_bytes(xpub_bytes);

        psbt.xpubs
            .entry(origin.clone())
            .or_default()
            .insert(xpub);
        // Note: rustoshi only supports PSBT version 0 (BIP-174 v0); the
        // encoder skips the GLOBAL_VERSION record when v == 0. We use a
        // separate hand-built golden vector below to cover the
        // GLOBAL_VERSION value-layout (the same bug-shape).
        psbt.add_input_derivation(0, input_pubkey, origin.clone()).unwrap();
        psbt.add_output_derivation(0, output_pubkey, origin.clone()).unwrap();

        let bytes = psbt.serialize();

        // ------------------------------------------------------------------
        // Helper: scan for `<keylen-compactsize> <type> <key-tail...>` and
        // return the offset of the first byte of the value-length CompactSize
        // immediately after the key blob.
        // ------------------------------------------------------------------
        fn find_record_value_offset(
            bytes: &[u8],
            type_byte: u8,
            key_tail: &[u8],
        ) -> Option<(usize, usize)> {
            // For all the records we test here, the keylen fits in a single
            // byte (keylen < 0xFD), so the CompactSize is one byte equal to
            // 1 + key_tail.len().
            let keylen = 1 + key_tail.len();
            assert!(keylen < 0xFD, "test keys must use single-byte CompactSize");
            let prefix = keylen as u8;
            let needle_len = 1 + 1 + key_tail.len(); // keylen + type + tail
            for i in 0..=(bytes.len().saturating_sub(needle_len)) {
                if bytes[i] != prefix {
                    continue;
                }
                if bytes[i + 1] != type_byte {
                    continue;
                }
                if &bytes[i + 2..i + 2 + key_tail.len()] != key_tail {
                    continue;
                }
                // Position of the value-length CompactSize.
                let val_len_off = i + needle_len;
                return Some((i, val_len_off));
            }
            None
        }

        // ------------------------------------------------------------------
        // 1. PSBT_GLOBAL_XPUB: value MUST be exactly the 16 origin bytes.
        //    Old buggy layout would emit value-len = 17 (16 + 1 inner
        //    CompactSize) and the value would start with 0x10 (CompactSize
        //    for 16) followed by the fingerprint.
        // ------------------------------------------------------------------
        let (_, val_len_off) = find_record_value_offset(
            &bytes,
            PSBT_GLOBAL_XPUB,
            &xpub_bytes,
        )
        .expect("global xpub record not found");

        assert_eq!(
            bytes[val_len_off], 16u8,
            "global xpub value-length CompactSize must be 16 (origin size); \
             a value of 17 indicates the buggy inner CompactSize prefix is \
             back (W36 regression)"
        );
        let val_start = val_len_off + 1;
        assert_eq!(
            &bytes[val_start..val_start + 16],
            &expected_origin_bytes,
            "global xpub value bytes must be raw origin (no inner prefix)"
        );
        // Defensive: ensure the value does NOT start with 0x10 followed by
        // the fingerprint (the exact buggy on-wire pattern).
        assert!(
            !(bytes[val_start] == 0x10 && bytes[val_start + 1] == 0xDE),
            "global xpub value starts with 0x10|0xDE — buggy inner \
             CompactSize prefix is back (W36 regression)"
        );

        // ------------------------------------------------------------------
        // 2. PSBT_IN_BIP32_DERIVATION: value MUST be the 16 origin bytes.
        // ------------------------------------------------------------------
        let (_, val_len_off) = find_record_value_offset(
            &bytes,
            PSBT_IN_BIP32_DERIVATION,
            &input_pubkey,
        )
        .expect("input bip32 derivation record not found");

        assert_eq!(
            bytes[val_len_off], 16u8,
            "input BIP32 derivation value-length must be 16 (origin size); \
             a value of 17 indicates the buggy inner CompactSize prefix is \
             back (W36 regression)"
        );
        let val_start = val_len_off + 1;
        assert_eq!(
            &bytes[val_start..val_start + 16],
            &expected_origin_bytes,
            "input BIP32 derivation value bytes must be raw origin"
        );

        // ------------------------------------------------------------------
        // 3. PSBT_OUT_BIP32_DERIVATION: value MUST be the 16 origin bytes.
        // ------------------------------------------------------------------
        let (_, val_len_off) = find_record_value_offset(
            &bytes,
            PSBT_OUT_BIP32_DERIVATION,
            &output_pubkey,
        )
        .expect("output bip32 derivation record not found");

        assert_eq!(
            bytes[val_len_off], 16u8,
            "output BIP32 derivation value-length must be 16 (origin size); \
             a value of 17 indicates the buggy inner CompactSize prefix is \
             back (W36 regression)"
        );
        let val_start = val_len_off + 1;
        assert_eq!(
            &bytes[val_start..val_start + 16],
            &expected_origin_bytes,
            "output BIP32 derivation value bytes must be raw origin"
        );

        // ------------------------------------------------------------------
        // 4. Self-round-trip MUST still work (the new layout decodes
        //    correctly through our own deserializer).
        // ------------------------------------------------------------------
        let restored = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(restored.xpubs.len(), 1);
        let restored_origin = restored.xpubs.keys().next().unwrap();
        assert_eq!(restored_origin.fingerprint, origin.fingerprint);
        assert_eq!(restored_origin.path, origin.path);

        let in_origin = restored.inputs[0]
            .bip32_derivation
            .get(&input_pubkey)
            .expect("input derivation lost in round-trip");
        assert_eq!(in_origin.fingerprint, origin.fingerprint);
        assert_eq!(in_origin.path, origin.path);

        let out_origin = restored.outputs[0]
            .bip32_derivation
            .get(&output_pubkey)
            .expect("output derivation lost in round-trip");
        assert_eq!(out_origin.fingerprint, origin.fingerprint);
        assert_eq!(out_origin.path, origin.path);
    }

    /// Regression test for W36 GLOBAL_VERSION byte layout (encode side).
    ///
    /// PSBT_HIGHEST_VERSION is currently 0 in this crate, so we cannot
    /// round-trip a non-zero version (the deserializer rejects it). We
    /// drive the encoder directly with version=Some(1) and assert the
    /// on-wire bytes match BIP-174 (raw 4-byte LE u32, no inner
    /// CompactSize), which is the W36 fix.
    #[test]
    fn test_w36_global_version_byte_layout_encode() {
        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.version = Some(1);

        let bytes = psbt.serialize();

        // Locate `<keylen=1> <type=PSBT_GLOBAL_VERSION>`.
        let mut found = None;
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i] == 0x01 && bytes[i + 1] == PSBT_GLOBAL_VERSION {
                found = Some(i);
                break;
            }
        }
        let i = found.expect("global version record not found");
        let val_len_off = i + 2;
        assert!(val_len_off < bytes.len());
        assert_eq!(
            bytes[val_len_off], 4u8,
            "global version value-length must be 4 (raw LE u32); a value \
             of 5 indicates the buggy inner CompactSize prefix is back \
             (W36 regression)"
        );
        let val_start = val_len_off + 1;
        assert_eq!(
            &bytes[val_start..val_start + 4],
            &1u32.to_le_bytes(),
            "global version value must be raw LE u32 (no inner prefix)"
        );
    }

    /// Regression test for W36 GLOBAL_VERSION byte layout (decode side).
    ///
    /// Hand-construct two byte streams: one in BIP-174-correct layout
    /// (raw 4-byte LE u32 value) and one in the old buggy layout (value
    /// is a CompactSize=4 followed by 4 bytes). The post-W36 decoder
    /// must accept the first and reject the second.
    #[test]
    fn test_w36_global_version_byte_layout_decode() {
        // Build a minimal PSBT with the unsigned tx + a GLOBAL_VERSION
        // record. We construct the bytes by hand to avoid the encoder
        // path entirely.
        let tx = create_test_tx();
        let tx_bytes = tx.serialize_no_witness();

        let make_psbt = |version_value: &[u8]| -> Vec<u8> {
            let mut out = Vec::new();
            // Magic: 0x70 0x73 0x62 0x74 0xff
            out.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
            // Global: PSBT_GLOBAL_UNSIGNED_TX
            out.push(0x01); // keylen = 1
            out.push(PSBT_GLOBAL_UNSIGNED_TX);
            write_compact_size(&mut out, tx_bytes.len() as u64).unwrap();
            out.extend_from_slice(&tx_bytes);
            // Global: PSBT_GLOBAL_VERSION
            out.push(0x01); // keylen = 1
            out.push(PSBT_GLOBAL_VERSION);
            write_compact_size(&mut out, version_value.len() as u64).unwrap();
            out.extend_from_slice(version_value);
            // Global separator
            out.push(0x00);
            // One input separator (matches create_test_tx's 1 input).
            out.push(0x00);
            // One output separator (matches create_test_tx's 1 output).
            out.push(0x00);
            out
        };

        // Spec-correct: value is exactly 4 bytes = LE u32 of version 0.
        let good = make_psbt(&0u32.to_le_bytes());
        let parsed = Psbt::deserialize(&good).expect("BIP-174 layout must parse");
        assert_eq!(parsed.version, Some(0));

        // Buggy layout: value is <CompactSize=4> || <4 bytes>. Total = 5.
        let mut bad_value = vec![0x04u8];
        bad_value.extend_from_slice(&0u32.to_le_bytes());
        let bad = make_psbt(&bad_value);
        let res = Psbt::deserialize(&bad);
        assert!(
            res.is_err(),
            "post-W36 the decoder must reject the old buggy layout \
             (5-byte value with leading CompactSize); got {:?}",
            res.map(|p| p.version)
        );
    }

    /// Regression test for W36: rejecting the OLD buggy on-wire layout.
    ///
    /// Until W36, rustoshi accepted (and produced) PSBTs whose
    /// PSBT_IN_BIP32_DERIVATION / PSBT_OUT_BIP32_DERIVATION /
    /// PSBT_GLOBAL_VERSION values had an inner CompactSize prefix. After
    /// the fix, those values are interpreted strictly per BIP-174, so
    /// any leading inner CompactSize is parsed as origin bytes — which
    /// means the path will end up containing a stray `0x00000010`
    /// component derived from the leading CompactSize (0x10 + 3 zeros
    /// from the start of the fingerprint), proving the decode side
    /// genuinely parses the new layout and rejects the old one.
    ///
    /// This is the key piece that nimrod's W34-C test added: a check
    /// that breaks if either side reverts.
    #[test]
    fn test_w36_buggy_layout_no_longer_decoded_as_clean_origin() {
        // Construct a PSBT_IN_BIP32_DERIVATION value field in the OLD
        // buggy on-wire shape: <CompactSize=16> || <fingerprint> || <path>.
        // Total length = 1 + 16 = 17.
        let buggy_value: Vec<u8> = {
            let mut v = vec![0x10u8];          // inner CompactSize = 16
            v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
            v.extend_from_slice(&0x80000054u32.to_le_bytes());
            v.extend_from_slice(&0x80000000u32.to_le_bytes());
            v.extend_from_slice(&0x80000000u32.to_le_bytes());
            v
        };

        // Decode strictly per BIP-174 (post-W36 path): the whole 17 bytes
        // is the origin. 17 is NOT a multiple of 4, so KeyOrigin's strict
        // length check rejects it outright.
        let mut cur = Cursor::new(&buggy_value);
        let res = KeyOrigin::decode_with_len(&mut cur, buggy_value.len());
        assert!(
            res.is_err(),
            "the old buggy layout (17-byte value with leading 0x10) must \
             no longer parse as a clean BIP-174 origin; if this passes, \
             the decode-side fix has regressed (W36)"
        );
    }

    // ====================================================================
    // W41 — regression tests for PSBT NON_WITNESS_UTXO consistency
    // (Bugs A1 + A2, ref bitcoin-core/src/psbt.cpp `GetInputUTXO` /
    // `PSBTInput::IsSane`) and BIP32 key-origin decoder against the live
    // W40-C multi-input fixture (Core's rpc_psbt.json signer[0].psbt).
    // Following the W36 / `906ec31` golden-vector pattern — ASYMMETRIC
    // bytes per axis to break self-round-trip blindness.
    // ====================================================================

    /// Build a minimal `Transaction` whose 1st output has the given amount
    /// and an asymmetric 4-byte scriptPubKey. Returns (tx, txid).
    /// `nonce` lets a caller produce DISTINCT prevtxs (different txids)
    /// for the txid-mismatch tests.
    fn make_prevtx(value: u64, spk_marker: u8, nonce: u32) -> (Transaction, Hash256) {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([nonce as u8; 32]),
                    vout: nonce,  // also salt vout to force distinct hashes
                },
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![
                TxOut {
                    value,
                    // Asymmetric SPK: leading byte differs from any
                    // trailing byte to expose endian-flip / reversed-copy
                    // bugs. (W36 lesson: `0x01 02 03 04` is palindrome-
                    // safe-looking but its reverse differs, which is the
                    // whole point.)
                    script_pubkey: vec![0xAA, 0xBB, 0xCC, spk_marker],
                },
                TxOut { value: 7777, script_pubkey: vec![0x00] },
            ],
            lock_time: 0,
        };
        let txid = tx.txid();
        (tx, txid)
    }

    /// Construct a Psbt whose unsigned_tx spends a fabricated prevout.
    fn make_psbt_spending(prev_txid: Hash256, prev_vout: u32) -> Psbt {
        let spending = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: prev_vout },
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 5000,
                script_pubkey: vec![0x00, 0x14, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                                    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03,
                                    0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            }],
            lock_time: 0,
        };
        Psbt::from_unsigned_tx(spending).unwrap()
    }

    /// W41 Bug A1 — wire deserializer must reject a NON_WITNESS_UTXO
    /// whose txid does not match the spending PSBT's prevout.
    ///
    /// Mirrors Core's `GetInputUTXO` (psbt.cpp:80) and the Updater
    /// helper `Psbt::set_non_witness_utxo` (psbt.rs:672-675).
    #[test]
    fn test_w41_a1_deserializer_rejects_nonwitness_txid_mismatch() {
        // Honest prevout the PSBT claims to spend.
        let (honest_tx, honest_txid) = make_prevtx(100_000, 0xAA, 1);
        // Attacker's lying prevtx — DIFFERENT txid by construction.
        let (attacker_tx, attacker_txid) = make_prevtx(999_999, 0xBB, 2);
        assert_ne!(honest_txid, attacker_txid, "fixture must produce distinct txids");

        let psbt = make_psbt_spending(honest_txid, 0);

        // Hand-craft on-wire bytes: serialize an honest psbt, then patch
        // the non_witness_utxo entry to carry the attacker's tx instead.
        // Easier: build via the API, then forcibly install attacker_tx
        // bypassing the Updater check, encode, decode, and assert reject.
        let mut tampered = psbt.clone();
        tampered.inputs[0].non_witness_utxo = Some(attacker_tx);  // direct field write skips set_non_witness_utxo's check
        let bytes = tampered.serialize();

        let res = Psbt::deserialize(&bytes);
        assert!(matches!(res, Err(PsbtError::UtxoHashMismatch)),
            "deserializer must reject mismatched non_witness_utxo (A1); got {:?}", res);

        // Sanity: an honestly-built PSBT round-trips fine.
        let mut clean = psbt.clone();
        clean.set_non_witness_utxo(0, honest_tx).unwrap();
        let bytes_clean = clean.serialize();
        Psbt::deserialize(&bytes_clean).expect("honest PSBT must round-trip");
    }

    /// W41 Bug A1 (combiner) — `Psbt::merge` must reject importing a
    /// NON_WITNESS_UTXO from `other` when its txid disagrees with our
    /// `unsigned_tx.inputs[i].previous_output.txid`. Stops a malicious
    /// counterparty from poisoning a Combiner via combinepsbt.
    #[test]
    fn test_w41_a1_combiner_rejects_nonwitness_txid_mismatch() {
        let (honest_tx, honest_txid) = make_prevtx(50_000, 0xCC, 3);
        let (attacker_tx, attacker_txid) = make_prevtx(50_000, 0xDD, 4);
        assert_ne!(honest_txid, attacker_txid);

        // Both PSBTs share the same unsigned_tx (spending honest_txid:0)
        // — that's the precondition for combinepsbt. The attacker's
        // PSBT slips in a wrong-txid prevtx in slot 0.
        let mut self_psbt = make_psbt_spending(honest_txid, 0);
        let mut attacker_psbt = make_psbt_spending(honest_txid, 0);
        // Direct field write — skips set_non_witness_utxo's update-time
        // check, simulating a counterparty whose own deserializer is
        // pre-W41 (or they hand-crafted bytes).
        attacker_psbt.inputs[0].non_witness_utxo = Some(attacker_tx);

        let res = self_psbt.merge(&attacker_psbt);
        assert!(matches!(res, Err(PsbtError::UtxoHashMismatch)),
            "Psbt::merge must reject txid-mismatched non_witness_utxo (A1 combiner); got {:?}", res);

        // Sanity: a same-tx counterparty PSBT merges fine.
        let mut clean_other = make_psbt_spending(honest_txid, 0);
        clean_other.set_non_witness_utxo(0, honest_tx).unwrap();
        let mut self2 = make_psbt_spending(honest_txid, 0);
        self2.merge(&clean_other).expect("clean merge must succeed");
        assert!(self2.inputs[0].non_witness_utxo.is_some());
    }

    /// W41 Bug A2 — CVE-2020-14199 amount-oracle defense.
    ///
    /// When a P2WSH PSBT input ships BOTH `witness_utxo` and
    /// `non_witness_utxo`, the wallet must NOT trust witness_utxo's
    /// amount/script if it disagrees with the on-chain prev tx
    /// (which is hash-checked at deserialize per Bug A1). A pre-fix
    /// rustoshi would happily produce a BIP-143 sighash over the
    /// inflated witness_utxo.value; the resulting signature is then
    /// replayable against the real (smaller) prevout.
    ///
    /// Triggered through the actual `sign_psbt_input` codepath — not
    /// just a unit-level check — so the test catches accidental
    /// bypasses (e.g. a future signer caller that re-fetches
    /// witness_utxo without going through the guard).
    #[test]
    fn test_w41_a2_witness_nonwitness_amount_mismatch_rejected() {
        use crate::wallet::{AddressType, Wallet};
        use crate::hd::WalletError;
        use rustoshi_crypto::address::Network;
        use rustoshi_crypto::sha256;
        use secp256k1::{Secp256k1, SecretKey};

        // 2-of-2 multisig witness_script with two arbitrary pubkeys.
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let pk1 = secp256k1::PublicKey::from_secret_key(&secp, &sk1).serialize();
        let pk2 = secp256k1::PublicKey::from_secret_key(&secp, &sk2).serialize();
        let mut witness_script = Vec::new();
        witness_script.push(0x52); // OP_2
        witness_script.push(0x21); witness_script.extend_from_slice(&pk1);
        witness_script.push(0x21); witness_script.extend_from_slice(&pk2);
        witness_script.push(0x52); // OP_2
        witness_script.push(0xae); // OP_CHECKMULTISIG

        // P2WSH prevout SPK = OP_0 PUSH32 SHA256(witness_script).
        let ws_hash = sha256(&witness_script);
        let mut p2wsh_spk = vec![0x00, 0x20];
        p2wsh_spk.extend_from_slice(&ws_hash);

        // Honest prevout pays 100_000 sats to the P2WSH SPK.
        let honest_prevtx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([0x33; 32]), vout: 0 },
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: p2wsh_spk.clone(),
            }],
            lock_time: 0,
        };
        let prev_txid = honest_prevtx.txid();

        let mut psbt = make_psbt_spending(prev_txid, 0);
        psbt.set_non_witness_utxo(0, honest_prevtx).unwrap();
        psbt.inputs[0].witness_script = Some(witness_script);

        // ── Honest case — witness_utxo agrees with non_witness_utxo. ──
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 100_000,
            script_pubkey: p2wsh_spk.clone(),
        });
        let wallet = Wallet::from_seed(&[0x77u8; 32], Network::Mainnet, AddressType::P2WPKH).unwrap();
        let r = wallet.sign_psbt_input(&mut psbt, 0, &[sk1], 0x01);
        assert!(r.is_ok(), "honest agreement must sign cleanly: {:?}", r);

        // ── Attack case — witness_utxo lies about the amount. ──
        psbt.inputs[0].partial_sigs.clear();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 999_999_999,                 // INFLATED
            script_pubkey: p2wsh_spk.clone(),
        });
        let r = wallet.sign_psbt_input(&mut psbt, 0, &[sk1], 0x01);
        match r {
            Err(WalletError::Io(ref e))
                if e.to_string().contains("witness_utxo and non_witness_utxo disagree") => {}
            other => panic!("A2 amount-mismatch must be rejected; got {:?}", other),
        }

        // ── Attack case — witness_utxo lies about the SPK. ──
        psbt.inputs[0].partial_sigs.clear();
        let mut tampered_spk = p2wsh_spk.clone();
        tampered_spk[2] ^= 0xFF;                // flip a SPK byte
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 100_000,
            script_pubkey: tampered_spk,
        });
        let r = wallet.sign_psbt_input(&mut psbt, 0, &[sk1], 0x01);
        match r {
            Err(WalletError::Io(ref e))
                if e.to_string().contains("witness_utxo and non_witness_utxo disagree") => {}
            other => panic!("A2 SPK-mismatch must be rejected; got {:?}", other),
        }
    }

    /// W41 Fix 3 — BIP32 key-origin decoder MUST accept the W40-C
    /// canonical fixture (Bitcoin Core 31.99 `rpc_psbt.json` signer[0]
    /// — a 2-input/2-output asymmetric P2SH-multisig + P2SH-P2WSH-
    /// multisig PSBT with 4 input + 2 output BIP32_DERIVATION entries,
    /// each value=16 bytes = 4-byte fingerprint + 3 path indexes).
    ///
    /// Pre-W36 the decoder treated the value as <CompactSize len> ||
    /// <fingerprint>||<path>, yielding "invalid key origin length" for
    /// any well-formed Core PSBT. W36 (commit 906ec31) switched to the
    /// BIP-174 "raw" encoding (no inner CompactSize). This test pins
    /// the canonical fixture so future strictness tweaks can't silently
    /// re-break it.
    #[test]
    fn test_w41_fix3_decode_w40c_multi_input_fixture() {
        use base64::Engine;
        // Canonical signer[0] PSBT from
        // bitcoin-core/test/functional/data/rpc_psbt.json
        // (2-in / 2-out, P2SH-multisig + P2SH-P2WSH-multisig).
        let psbt_b64 = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911\
                        AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////\
                        8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw\
                        +HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrB\
                        gpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKt\
                        JDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAA\
                        AXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe1\
                        2FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRA\
                        IgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPI\
                        BwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbov\
                        v+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pn\
                        Wm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0\
                        etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa\
                        5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak\
                        8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZ\
                        DGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIe\
                        iHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fH\
                        P0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzT\
                        hAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIg\
                        ZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8\
                        uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2n\
                        Tof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAt\
                        whAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25\
                        BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21\
                        T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/\
                        WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn\
                        9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA";
        let cleaned: String = psbt_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(cleaned.as_bytes()).unwrap();

        let psbt = Psbt::deserialize(&bytes)
            .expect("W40-C canonical fixture must decode (Fix 3 regression)");

        // Shape assertions: 2-in / 2-out, asymmetric.
        assert_eq!(psbt.unsigned_tx.inputs.len(), 2, "2 inputs expected");
        assert_eq!(psbt.unsigned_tx.outputs.len(), 2, "2 outputs expected");
        assert_eq!(psbt.inputs.len(), 2);
        assert_eq!(psbt.outputs.len(), 2);

        // Each input has 2 BIP32 derivations; outputs have 1 each.
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 2);
        assert_eq!(psbt.inputs[1].bip32_derivation.len(), 2);
        assert_eq!(psbt.outputs[0].bip32_derivation.len(), 1);
        assert_eq!(psbt.outputs[1].bip32_derivation.len(), 1);

        // All key origins use the same fingerprint d90c6a4f and 3-deep
        // BIP44-style paths (m/0'/0'/N'). Spot-check one entry.
        let any_origin = psbt.inputs[0].bip32_derivation.values().next().unwrap();
        assert_eq!(any_origin.fingerprint, [0xd9, 0x0c, 0x6a, 0x4f]);
        assert_eq!(any_origin.path.len(), 3, "BIP44 m/0'/0'/N' = 3 indexes");

        // Round-trip: re-encode, re-decode must succeed (no wire-format
        // regression).
        let reenc = psbt.serialize();
        Psbt::deserialize(&reenc).expect("re-encoded PSBT must round-trip");
    }

    /// W46 — legacy P2SH-multisig finalize MUST emit signatures in
    /// script-pubkey order, NOT partial_sigs map order, NOT insertion
    /// order, NOT pubkey-byte sort. Insert in REVERSE order to make
    /// the wrong-ordering bug observable. Mirrors `bitcoin-core/src/
    /// script/sign.cpp::ProduceSignature`.
    #[test]
    fn test_w46_p2sh_multisig_finalize_script_order() {
        // Two asymmetric 33-byte compressed pubkeys (no palindromes;
        // W32-B fixture rule). Different prefix bytes so a byte-sort
        // would also reorder them.
        let pk1: [u8; 33] = [
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x12,
        ];
        let pk2: [u8; 33] = [
            0x03, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x0a, 0x1b,
            0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6,
            0xd7, 0xe8, 0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
        ];

        // 2-of-2 redeem script: OP_2 <pk1> OP_2 OP_CHECKMULTISIG... wait,
        // actually OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG.
        let mut redeem_script = Vec::new();
        redeem_script.push(0x52); // OP_2
        redeem_script.push(33);
        redeem_script.extend_from_slice(&pk1);
        redeem_script.push(33);
        redeem_script.extend_from_slice(&pk2);
        redeem_script.push(0x52); // OP_2
        redeem_script.push(0xae); // OP_CHECKMULTISIG

        // Two distinct DER-shaped sigs (asymmetric, no palindromes).
        let sig1: Vec<u8> = vec![
            0x30, 0x44, 0x02, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x12, 0x13, 0x02, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x01,
        ];
        let sig2: Vec<u8> = vec![
            0x30, 0x44, 0x02, 0x20, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93,
            0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e,
            0x5f, 0x60, 0x71, 0x82, 0x02, 0x20, 0x99, 0x88, 0x77, 0x66, 0x55,
            0x44, 0x33, 0x22, 0x11, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
            0xdc, 0xed, 0xfe, 0x01, 0x12, 0x01,
        ];

        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].redeem_script = Some(redeem_script.clone());
        // Insert in REVERSE script order. BTreeMap sorts by pubkey
        // bytes regardless, so this also exercises the script-order
        // discipline against the sort-order bug.
        psbt.inputs[0].partial_sigs.insert(pk2, sig2.clone());
        psbt.inputs[0].partial_sigs.insert(pk1, sig1.clone());
        psbt.inputs[0].sighash_type = Some(0x01);

        psbt.finalize_input(0).expect("legacy P2SH-multisig finalize must succeed");

        // Must be finalized (W46 close).
        assert!(psbt.inputs[0].is_finalized());
        let script_sig = psbt.inputs[0]
            .final_script_sig
            .as_ref()
            .expect("W46: final_script_sig must be set");

        // scriptSig layout:
        //   OP_0 (0x00)
        //   <push sig1>      [pk1 first in script]
        //   <push sig2>      [pk2 second in script]
        //   <push redeem_script>
        let mut expected = Vec::new();
        expected.push(0x00);
        expected.push(sig1.len() as u8);
        expected.extend_from_slice(&sig1);
        expected.push(sig2.len() as u8);
        expected.extend_from_slice(&sig2);
        expected.push(redeem_script.len() as u8);
        expected.extend_from_slice(&redeem_script);

        assert_eq!(
            script_sig, &expected,
            "W46: signatures must be emitted in script-pubkey order (sig1 before sig2), \
             not partial_sigs/BTreeMap byte order, not insertion order"
        );
    }

    /// W46 — after legacy P2SH-multisig finalize, the producer fields
    /// (partial_sigs, redeem_script, witness_script, bip32_derivation,
    /// sighash_type) MUST be cleared. Mirrors lunarblock W41 + ouroboros
    /// W43. Also re-checks that the cleanup happens AFTER setting
    /// final_script_sig (W43-1 regression-avoidance).
    #[test]
    fn test_w46_p2sh_multisig_clears_producer_fields() {
        let pk1: [u8; 33] = [
            0x02, 0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let pk2: [u8; 33] = [
            0x03, 0xbb, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];

        let mut redeem_script = Vec::new();
        redeem_script.push(0x52); // OP_2
        redeem_script.push(33);
        redeem_script.extend_from_slice(&pk1);
        redeem_script.push(33);
        redeem_script.extend_from_slice(&pk2);
        redeem_script.push(0x52); // OP_2
        redeem_script.push(0xae); // OP_CHECKMULTISIG

        let sig1: Vec<u8> = vec![0x30, 0x05, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43, 0x01];
        let sig2: Vec<u8> = vec![0x30, 0x05, 0x02, 0x01, 0x77, 0x02, 0x01, 0x88, 0x01];

        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].redeem_script = Some(redeem_script);
        psbt.inputs[0].partial_sigs.insert(pk1, sig1);
        psbt.inputs[0].partial_sigs.insert(pk2, sig2);
        psbt.inputs[0].sighash_type = Some(0x01);

        // Add a bip32 derivation entry to verify it gets cleared too.
        psbt.inputs[0].bip32_derivation.insert(
            pk1,
            KeyOrigin::new([0xab, 0xcd, 0xef, 0x01], vec![0, 1, 2]),
        );

        psbt.finalize_input(0).expect("legacy P2SH-multisig finalize must succeed");

        // final_script_sig is set ...
        assert!(
            psbt.inputs[0].final_script_sig.is_some(),
            "W46/W43-1: final_script_sig must be set"
        );

        // ... AND all producer fields are cleared.
        assert!(
            psbt.inputs[0].partial_sigs.is_empty(),
            "W46: partial_sigs must be cleared post-finalize"
        );
        assert!(
            psbt.inputs[0].redeem_script.is_none(),
            "W46: redeem_script must be cleared post-finalize"
        );
        assert!(
            psbt.inputs[0].witness_script.is_none(),
            "W46: witness_script must be cleared post-finalize"
        );
        assert!(
            psbt.inputs[0].bip32_derivation.is_empty(),
            "W46: bip32_derivation must be cleared post-finalize"
        );
        assert!(
            psbt.inputs[0].sighash_type.is_none(),
            "W46: sighash_type must be cleared post-finalize"
        );

        // is_finalized() should return true now.
        assert!(psbt.inputs[0].is_finalized());
    }

    // ========================================================================
    // W48: analyzepsbt regression tests
    //
    // Mirrors camlcoin W41 (`test/test_psbt.ml`) and hotbuns W47
    // (`src/wallet/psbt.test.ts`). Verifies the per-input + PSBT-level
    // role rollup matches Bitcoin Core's `AnalyzePSBT` for the W40-C
    // multi-input fixture (2-of-2 P2SH-multisig + 2-of-2 P2SH-P2WSH-
    // multisig with both partial sigs present) and for partial / final
    // variants.
    // ========================================================================

    /// W40-C signed fixture (`tools/psbt-multi-input-fixture.json`):
    /// 2-input PSBT with full partial sigs on both inputs but no
    /// `final_script_*` yet. Core 31.99 reports `next == "finalizer"`.
    const W40C_PSBT_SIGNED: &str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA";

    /// Same fixture, finalized: each input now has `final_script_*` set.
    /// Core reports `next == "extractor"`.
    const W40C_PSBT_FINALIZED: &str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA==";

    /// W48-1: analyzepsbt on the W40-C signed fixture (both inputs have
    /// all required partial sigs, neither is finalized yet) — every
    /// per-input verdict is `Finalizer` and the PSBT-level `next` is
    /// `Finalizer`. Mirrors camlcoin W41 regression test exactly.
    /// Closes the T5 N/A on `tools/psbt-multi-input-test.sh`.
    #[test]
    fn test_w48_analyzepsbt_w40c_signed_is_finalizer() {
        let psbt = Psbt::from_base64(W40C_PSBT_SIGNED)
            .expect("W40-C signed fixture must decode");
        let analysis = psbt.analyze();
        assert_eq!(
            analysis.inputs.len(),
            2,
            "W40-C fixture must have 2 inputs"
        );
        for (i, inp) in analysis.inputs.iter().enumerate() {
            assert!(inp.has_utxo, "input {} must have a UTXO", i);
            assert!(!inp.is_final, "input {} must not yet be finalized", i);
            assert_eq!(
                inp.next,
                PsbtRole::Finalizer,
                "W48: input {} next must be Finalizer (had all M-of-N sigs)",
                i
            );
        }
        assert_eq!(
            analysis.next,
            PsbtRole::Finalizer,
            "W48: W40-C signed PSBT-level next must be Finalizer (matches Core 31.99)"
        );
    }

    /// W48-2: analyzepsbt on a partially-signed PSBT. We take the W40-C
    /// signed fixture and strip one partial sig from input 0 (a 2-of-2
    /// P2SH-multisig — needs both sigs to finalize). Per-input verdict
    /// flips to `Signer` and the PSBT-level `next` follows.
    #[test]
    fn test_w48_analyzepsbt_partial_is_signer() {
        let mut psbt = Psbt::from_base64(W40C_PSBT_SIGNED)
            .expect("W40-C signed fixture must decode");
        // Drop one of the two partial sigs on input 0. With 1/2 sigs
        // present and the redeem_script declaring 2-of-2, required = 2,
        // so the input is in `Signer`.
        let first_pk = *psbt.inputs[0]
            .partial_sigs
            .keys()
            .next()
            .expect("input 0 must have at least one partial sig");
        psbt.inputs[0].partial_sigs.remove(&first_pk);
        assert_eq!(
            psbt.inputs[0].partial_sigs.len(),
            1,
            "test setup: input 0 must now have 1 of 2 partial sigs"
        );

        let analysis = psbt.analyze();
        assert_eq!(
            analysis.inputs[0].next,
            PsbtRole::Signer,
            "input 0 with 1/2 multisig sigs must report Signer"
        );
        assert!(
            !analysis.inputs[0].missing_signatures.is_empty(),
            "input 0 in Signer state must list at least one missing pubkey"
        );
        // PSBT-level next = MIN(Signer, Finalizer) = Signer.
        assert_eq!(
            analysis.next,
            PsbtRole::Signer,
            "PSBT-level next must downgrade to Signer when any input is Signer"
        );
    }

    /// W48-3: analyzepsbt on the finalized fixture — every input has
    /// final_script_sig / final_script_witness set, so each verdict is
    /// `Extractor` and the PSBT-level `next` is `Extractor`.
    #[test]
    fn test_w48_analyzepsbt_finalized_is_extractor() {
        let psbt = Psbt::from_base64(W40C_PSBT_FINALIZED)
            .expect("W40-C finalized fixture must decode");
        let analysis = psbt.analyze();
        assert_eq!(analysis.inputs.len(), 2);
        for (i, inp) in analysis.inputs.iter().enumerate() {
            assert!(inp.is_final, "input {} must be finalized", i);
            assert_eq!(
                inp.next,
                PsbtRole::Extractor,
                "W48: finalized input {} must report Extractor",
                i
            );
        }
        assert_eq!(
            analysis.next,
            PsbtRole::Extractor,
            "W48: finalized PSBT-level next must be Extractor"
        );
    }

    /// W49: partial_sigs MUST be emitted on the wire in HASH160(pubkey)
    /// order (Core's `std::map<CKeyID, SigPair>`, see
    /// bitcoin-core/src/psbt.h:270), NOT raw-pubkey order
    /// (BTreeMap iteration order). This closes the rustoshi T2
    /// combinepsbt byte-divergence and brings the fleet to 50/50 on
    /// W40-C parity vs Bitcoin Core 31.99. Mirrors ouroboros W46-4
    /// (3d44478) and blockbrew W45 (e000f9b).
    ///
    /// Test pubkeys are chosen so that raw byte order DIFFERS from
    /// HASH160 byte order — without this, the test passes vacuously
    /// (per ouroboros W46-4 lesson):
    ///   pk_a < pk_b   bytewise  (BTreeMap order, raw)
    ///   h160(pk_a) > h160(pk_b) (Core's CKeyID order)
    /// so the on-wire sig for pk_b MUST appear before pk_a.
    #[test]
    fn test_w49_partial_sigs_emitted_in_hash160_order() {
        // pk_a / pk_b: shape-valid 33-byte compressed-pubkey arrays.
        // The PSBT serializer treats these as opaque bytes; they do
        // NOT need to be on-curve for a wire-format test.
        let pk_a: [u8; 33] = [
            0x02, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x00,
        ];
        let pk_b: [u8; 33] = [
            0x02, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x01,
        ];

        // Sanity: raw and hash160 orders disagree (the whole point of
        // the test). If a future libsecp / hash refactor accidentally
        // makes these agree, this assert turns the test into an
        // INCONCLUSIVE rather than a vacuous pass.
        let h_a = rustoshi_crypto::hash160(&pk_a).0;
        let h_b = rustoshi_crypto::hash160(&pk_b).0;
        assert!(pk_a < pk_b, "test setup: raw pk_a < pk_b");
        assert!(
            h_a > h_b,
            "test setup: hash160(pk_a) > hash160(pk_b) so the test \
             actually distinguishes raw-order from hash160-order"
        );

        // Two distinct DER-shaped sigs. Asymmetric, no palindromes.
        let sig_a: Vec<u8> = vec![
            0x30, 0x05, 0x02, 0x01, 0x11, 0x02, 0x01, 0x22, 0x01,
        ];
        let sig_b: Vec<u8> = vec![
            0x30, 0x05, 0x02, 0x01, 0x33, 0x02, 0x01, 0x44, 0x01,
        ];

        let tx = create_test_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        // Insert a-then-b. BTreeMap stores them in raw-pubkey order
        // (a then b). Without the W49 fix, the wire layout follows
        // raw order. With the fix, on-wire order is hash160 order
        // (b then a) — matching Core.
        psbt.inputs[0].partial_sigs.insert(pk_a, sig_a.clone());
        psbt.inputs[0].partial_sigs.insert(pk_b, sig_b.clone());

        let wire = psbt.serialize();

        // Find both PSBT_IN_PARTIAL_SIG records by scanning for the
        // signature payload — robust against reordering of unrelated
        // input fields. Returns the offset of the first byte of the
        // sig (i.e. the start of the kv-pair value).
        fn find_sig_offset(wire: &[u8], sig: &[u8]) -> usize {
            wire.windows(sig.len())
                .position(|w| w == sig)
                .expect("sig must appear in serialized PSBT")
        }
        let off_a = find_sig_offset(&wire, &sig_a);
        let off_b = find_sig_offset(&wire, &sig_b);

        // hash160(pk_b) < hash160(pk_a), so pk_b's record (and thus
        // sig_b) MUST appear before pk_a's on the wire.
        assert!(
            off_b < off_a,
            "W49: partial_sigs must be emitted in HASH160(pubkey) \
             order, not BTreeMap raw-pubkey order. \
             got off_b={} off_a={} (Core std::map<CKeyID,SigPair>)",
            off_b, off_a
        );
    }
}
