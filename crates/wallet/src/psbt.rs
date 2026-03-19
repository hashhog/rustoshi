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
use rustoshi_primitives::hash::Hash256;
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size, Decodable, Encodable};
use rustoshi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
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

    /// UTXO index out of range
    #[error("UTXO index out of range")]
    UtxoIndexOutOfRange,

    /// Cannot combine PSBTs with different underlying transactions
    #[error("cannot combine PSBTs with different transactions")]
    IncompatiblePsbts,

    /// Cannot finalize incomplete PSBT
    #[error("cannot finalize: {0}")]
    CannotFinalize(String),

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
        if len % 4 != 0 || len == 0 {
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
                .or_insert_with(BTreeSet::new)
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
                .or_insert_with(BTreeSet::new)
                .extend(xpubs.iter().cloned());
        }

        // Merge inputs
        for (i, other_input) in other.inputs.iter().enumerate() {
            if i < self.inputs.len() {
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
        Self::decode(&mut cursor)
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

                let mut value = Vec::new();
                write_compact_size(&mut value, origin.serialized_size() as u64)?;
                origin.encode(&mut value)?;
                len += write_kv_pair(writer, &key, &value)?;
            }
        }

        // Global: version (only if > 0)
        if let Some(v) = self.version {
            if v > 0 {
                key.clear();
                key.push(PSBT_GLOBAL_VERSION);
                let mut value = Vec::new();
                write_compact_size(&mut value, 4)?;
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
        // Partial signatures
        for (pubkey, sig) in &input.partial_sigs {
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
            let mut value = Vec::new();
            write_compact_size(&mut value, origin.serialized_size() as u64)?;
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
        let mut value = Vec::new();
        write_compact_size(&mut value, origin.serialized_size() as u64)?;
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
                    let tx = Transaction::deserialize(&value)?;
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

                    // Decode key origin from value
                    let mut value_cursor = Cursor::new(&value);
                    let origin_len = read_compact_size(&mut value_cursor)?;
                    let origin = KeyOrigin::decode_with_len(&mut value_cursor, origin_len as usize)?;

                    xpubs
                        .entry(origin)
                        .or_insert_with(BTreeSet::new)
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
                    if value.len() < 4 {
                        return Err(PsbtError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "version value too short",
                        )));
                    }
                    // Value is length-prefixed
                    let mut value_cursor = Cursor::new(&value);
                    let v_len = read_compact_size(&mut value_cursor)?;
                    if v_len != 4 {
                        return Err(PsbtError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid version length",
                        )));
                    }
                    let mut v_bytes = [0u8; 4];
                    value_cursor.read_exact(&mut v_bytes)?;
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

                // Value is length-prefixed key origin
                let mut value_cursor = Cursor::new(&value);
                let origin_len = read_compact_size(&mut value_cursor)?;
                let origin = KeyOrigin::decode_with_len(&mut value_cursor, origin_len as usize)?;
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
                if key.len() < 34 || (key.len() - 2) % 32 != 0 {
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

                let mut value_cursor = Cursor::new(&value);
                let origin_len = read_compact_size(&mut value_cursor)?;
                let origin = KeyOrigin::decode_with_len(&mut value_cursor, origin_len as usize)?;
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
}
