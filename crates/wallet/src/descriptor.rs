//! Output Descriptors (BIP-380/381/382/383/384/385/386).
//!
//! This module implements output descriptors, a language for describing sets
//! of output scripts. Descriptors enable wallet import/export, watch-only
//! wallets, and standardized address generation.
//!
//! # Descriptor Types
//!
//! - `pk(KEY)` - Pay to pubkey
//! - `pkh(KEY)` - Pay to pubkey hash (P2PKH)
//! - `wpkh(KEY)` - Pay to witness pubkey hash (P2WPKH)
//! - `sh(SCRIPT)` - Pay to script hash (P2SH)
//! - `wsh(SCRIPT)` - Pay to witness script hash (P2WSH)
//! - `tr(KEY)` - Taproot key-path spend
//! - `tr(KEY,TREE)` - Taproot with script tree
//! - `multi(K,KEY,...)` - K-of-N multisig
//! - `sortedmulti(K,KEY,...)` - K-of-N multisig with sorted keys
//! - `addr(ADDR)` - Raw address
//! - `raw(HEX)` - Raw scriptPubKey
//! - `combo(KEY)` - P2PK + P2PKH + P2WPKH + P2SH-P2WPKH (if compressed)
//!
//! # Key Expressions
//!
//! Key expressions can be:
//! - Hex-encoded public keys (33 or 65 bytes)
//! - WIF-encoded private keys
//! - Extended keys with derivation paths: `xpub.../0/1/*`
//! - Keys with origin info: `[fingerprint/path]xpub...`
//!
//! # Example
//!
//! ```rust,ignore
//! use rustoshi_wallet::descriptor::{Descriptor, parse_descriptor};
//!
//! // Parse a P2WPKH descriptor with range
//! let desc = parse_descriptor("wpkh([d34db33f/84'/0'/0']xpub.../0/*)")?;
//!
//! // Derive address at index 0
//! let script = desc.derive_script(0)?;
//! ```

use rustoshi_crypto::address::{Address, Network};
use rustoshi_crypto::hashes::{hash160, sha256, tagged_hash};
use rustoshi_primitives::Hash160;
use secp256k1::PublicKey;
use std::fmt;

use crate::hd::{parse_derivation_path, ExtendedPrivKey, ExtendedPubKey, WalletError, HARDENED_FLAG};

// =============================================================================
// Checksum implementation (BIP-380)
// =============================================================================

/// The input character set for descriptor checksums.
/// Designed so that the most common descriptor characters (hex, keypaths) are in the first group.
const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}\
                              IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
                              ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// The character set for the checksum itself (same as bech32).
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// PolyMod function for BCH checksum computation.
///
/// Interprets c as 8 groups of 5 bits which are coefficients of a degree-8 polynomial
/// over GF(32), multiplies by x, computes remainder modulo a generator, and adds val.
fn poly_mod(mut c: u64, val: u8) -> u64 {
    let c0 = (c >> 35) as u8;
    c = ((c & 0x7ffffffff) << 5) ^ (val as u64);
    if c0 & 1 != 0 {
        c ^= 0xf5dee51989;
    }
    if c0 & 2 != 0 {
        c ^= 0xa9fdca3312;
    }
    if c0 & 4 != 0 {
        c ^= 0x1bab10e32d;
    }
    if c0 & 8 != 0 {
        c ^= 0x3706b1677a;
    }
    if c0 & 16 != 0 {
        c ^= 0x644d626ffd;
    }
    c
}

/// Compute the descriptor checksum for a descriptor string.
///
/// Returns an 8-character checksum string, or None if the input contains
/// invalid characters.
pub fn descriptor_checksum(desc: &str) -> Option<String> {
    let mut c: u64 = 1;
    let mut cls = 0u8;
    let mut clscount = 0;

    for ch in desc.chars() {
        let pos = INPUT_CHARSET.find(ch)?;
        c = poly_mod(c, (pos & 31) as u8);
        cls = cls * 3 + (pos >> 5) as u8;
        clscount += 1;
        if clscount == 3 {
            c = poly_mod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }

    if clscount > 0 {
        c = poly_mod(c, cls);
    }

    for _ in 0..8 {
        c = poly_mod(c, 0);
    }
    c ^= 1;

    let mut result = String::with_capacity(8);
    for j in 0..8 {
        let idx = ((c >> (5 * (7 - j))) & 31) as usize;
        result.push(CHECKSUM_CHARSET[idx] as char);
    }
    Some(result)
}

/// Add a checksum to a descriptor string.
pub fn add_checksum(desc: &str) -> Option<String> {
    let checksum = descriptor_checksum(desc)?;
    Some(format!("{}#{}", desc, checksum))
}

/// Verify that a descriptor's checksum is valid.
pub fn verify_checksum(desc_with_checksum: &str) -> Result<&str, DescriptorError> {
    let parts: Vec<&str> = desc_with_checksum.rsplitn(2, '#').collect();
    if parts.len() != 2 {
        return Err(DescriptorError::MissingChecksum);
    }

    let checksum = parts[0];
    let desc = parts[1];

    if checksum.len() != 8 {
        return Err(DescriptorError::InvalidChecksum);
    }

    let computed = descriptor_checksum(desc).ok_or(DescriptorError::InvalidCharacter)?;
    if computed != checksum {
        return Err(DescriptorError::InvalidChecksum);
    }

    Ok(desc)
}

// =============================================================================
// Error types
// =============================================================================

/// Errors that can occur when parsing or using descriptors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DescriptorError {
    /// Invalid descriptor syntax.
    #[error("invalid descriptor syntax: {0}")]
    InvalidSyntax(String),

    /// Invalid character in descriptor.
    #[error("invalid character in descriptor")]
    InvalidCharacter,

    /// Invalid checksum.
    #[error("invalid checksum")]
    InvalidChecksum,

    /// Missing checksum.
    #[error("missing checksum")]
    MissingChecksum,

    /// Invalid key expression.
    #[error("invalid key expression: {0}")]
    InvalidKey(String),

    /// Invalid derivation path.
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    /// Invalid xpub/xprv.
    #[error("invalid extended key: {0}")]
    InvalidExtKey(String),

    /// Cannot derive hardened child from xpub.
    #[error("cannot derive hardened child from xpub")]
    HardenedFromXpub,

    /// Invalid multisig threshold.
    #[error("invalid multisig threshold: k={k}, n={n}")]
    InvalidThreshold { k: usize, n: usize },

    /// Invalid address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid hex.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Invalid script.
    #[error("invalid script: {0}")]
    InvalidScript(String),

    /// Unsupported descriptor type.
    #[error("unsupported descriptor type: {0}")]
    UnsupportedType(String),

    /// Key derivation error.
    #[error("key derivation error")]
    KeyDerivation,

    /// Range required but not provided.
    #[error("range required for ranged descriptor")]
    RangeRequired,

    /// Position out of range.
    #[error("position {0} out of range")]
    PositionOutOfRange(u32),
}

impl From<WalletError> for DescriptorError {
    fn from(e: WalletError) -> Self {
        match e {
            WalletError::InvalidPath(s) => DescriptorError::InvalidPath(s),
            WalletError::HardenedFromPublic => DescriptorError::HardenedFromXpub,
            _ => DescriptorError::KeyDerivation,
        }
    }
}

// =============================================================================
// Key origin info
// =============================================================================

/// Origin information for a key in a descriptor.
///
/// Format: `[fingerprint/path]` where fingerprint is 4 bytes (8 hex chars)
/// and path is a derivation path like `84'/0'/0'`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyOrigin {
    /// The fingerprint of the master key (first 4 bytes of HASH160).
    pub fingerprint: [u8; 4],
    /// The derivation path from the master key.
    pub path: Vec<u32>,
}

impl KeyOrigin {
    /// Create a new key origin.
    pub fn new(fingerprint: [u8; 4], path: Vec<u32>) -> Self {
        Self { fingerprint, path }
    }

    /// Format the origin as a string.
    pub fn to_string_with_apostrophe(&self, use_apostrophe: bool) -> String {
        let fp = hex::encode(self.fingerprint);
        let path = format_path(&self.path, use_apostrophe);
        format!("[{}{path}]", fp)
    }
}

impl fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_with_apostrophe(true))
    }
}

/// Format a derivation path as a string.
fn format_path(path: &[u32], use_apostrophe: bool) -> String {
    if path.is_empty() {
        return String::new();
    }
    let suffix = if use_apostrophe { "'" } else { "h" };
    let parts: Vec<String> = path
        .iter()
        .map(|&idx| {
            if idx >= HARDENED_FLAG {
                format!("/{}{}", idx & !HARDENED_FLAG, suffix)
            } else {
                format!("/{}", idx)
            }
        })
        .collect();
    parts.concat()
}

// =============================================================================
// Derivation type for ranged descriptors
// =============================================================================

/// Type of derivation for range expressions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveType {
    /// Not a range descriptor.
    NonRanged,
    /// Range with unhardened final derivation (`/*`).
    UnhardenedRanged,
    /// Range with hardened final derivation (`/*'` or `/*h`).
    HardenedRanged,
}

// =============================================================================
// Key providers
// =============================================================================

/// A provider of public keys for descriptor expansion.
#[derive(Clone, Debug)]
pub enum KeyProvider {
    /// A constant public key (hex or WIF).
    Const {
        /// The public key.
        pubkey: PublicKey,
        /// Whether this is an x-only key (for Taproot).
        xonly: bool,
    },
    /// An extended public key with derivation path.
    Xpub {
        /// The extended public key.
        xpub: ExtendedPubKey,
        /// The derivation path after the xpub.
        path: Vec<u32>,
        /// Whether this is a ranged descriptor.
        derive_type: DeriveType,
        /// Whether to use apostrophe or 'h' for hardened notation.
        apostrophe: bool,
    },
    /// An extended private key with derivation path.
    Xprv {
        /// The extended private key.
        xprv: ExtendedPrivKey,
        /// The derivation path after the xprv.
        path: Vec<u32>,
        /// Whether this is a ranged descriptor.
        derive_type: DeriveType,
        /// Whether to use apostrophe or 'h' for hardened notation.
        apostrophe: bool,
    },
    /// A key with origin information.
    WithOrigin {
        /// The origin info.
        origin: KeyOrigin,
        /// The inner key provider.
        inner: Box<KeyProvider>,
        /// Whether to use apostrophe for the origin path.
        apostrophe: bool,
    },
}

impl KeyProvider {
    /// Returns true if this is a ranged key expression.
    pub fn is_range(&self) -> bool {
        match self {
            KeyProvider::Const { .. } => false,
            KeyProvider::Xpub { derive_type, .. } | KeyProvider::Xprv { derive_type, .. } => {
                *derive_type != DeriveType::NonRanged
            }
            KeyProvider::WithOrigin { inner, .. } => inner.is_range(),
        }
    }

    /// Get the public key at the given position (for ranged descriptors).
    pub fn get_pubkey(&self, pos: u32) -> Result<PublicKey, DescriptorError> {
        match self {
            KeyProvider::Const { pubkey, .. } => Ok(*pubkey),
            KeyProvider::Xpub {
                xpub,
                path,
                derive_type,
                ..
            } => {
                // First derive along the path
                let mut derived = xpub.clone();
                for &child in path {
                    derived = derived.derive_child(child)?;
                }
                // Then derive the position if ranged
                match derive_type {
                    DeriveType::NonRanged => Ok(derived.public_key),
                    DeriveType::UnhardenedRanged => {
                        let final_key = derived.derive_child(pos)?;
                        Ok(final_key.public_key)
                    }
                    DeriveType::HardenedRanged => Err(DescriptorError::HardenedFromXpub),
                }
            }
            KeyProvider::Xprv {
                xprv,
                path,
                derive_type,
                ..
            } => {
                // First derive along the path
                let mut derived = xprv.clone();
                for &child in path {
                    derived = derived.derive_child(child)?;
                }
                // Then derive the position if ranged
                match derive_type {
                    DeriveType::NonRanged => Ok(derived.to_public().public_key),
                    DeriveType::UnhardenedRanged => {
                        let final_key = derived.derive_child(pos)?;
                        Ok(final_key.to_public().public_key)
                    }
                    DeriveType::HardenedRanged => {
                        let final_key = derived.derive_child(pos | HARDENED_FLAG)?;
                        Ok(final_key.to_public().public_key)
                    }
                }
            }
            KeyProvider::WithOrigin { inner, .. } => inner.get_pubkey(pos),
        }
    }

    /// Format as string for public representation.
    pub fn to_public_string(&self) -> String {
        match self {
            KeyProvider::Const { pubkey, xonly } => {
                let bytes = pubkey.serialize();
                if *xonly {
                    // x-only is 32 bytes, skip the prefix byte
                    hex::encode(&bytes[1..])
                } else {
                    hex::encode(bytes)
                }
            }
            KeyProvider::Xpub {
                xpub,
                path,
                derive_type,
                apostrophe,
            } => {
                let mut s = encode_xpub(xpub, Network::Mainnet);
                s.push_str(&format_path(path, *apostrophe));
                match derive_type {
                    DeriveType::NonRanged => {}
                    DeriveType::UnhardenedRanged => s.push_str("/*"),
                    DeriveType::HardenedRanged => {
                        if *apostrophe {
                            s.push_str("/*'");
                        } else {
                            s.push_str("/*h");
                        }
                    }
                }
                s
            }
            KeyProvider::Xprv { xprv, path, derive_type, apostrophe } => {
                // For public string, convert to xpub
                let xpub = xprv.to_public();
                let mut s = encode_xpub(&xpub, Network::Mainnet);
                s.push_str(&format_path(path, *apostrophe));
                match derive_type {
                    DeriveType::NonRanged => {}
                    DeriveType::UnhardenedRanged => s.push_str("/*"),
                    DeriveType::HardenedRanged => {
                        if *apostrophe {
                            s.push_str("/*'");
                        } else {
                            s.push_str("/*h");
                        }
                    }
                }
                s
            }
            KeyProvider::WithOrigin {
                origin,
                inner,
                apostrophe,
            } => {
                format!(
                    "{}{}",
                    origin.to_string_with_apostrophe(*apostrophe),
                    inner.to_public_string()
                )
            }
        }
    }
}

// =============================================================================
// Descriptor types
// =============================================================================

/// A parsed output descriptor.
#[derive(Clone, Debug)]
pub enum Descriptor {
    /// pk(KEY) - Pay to pubkey.
    Pk(KeyProvider),

    /// pkh(KEY) - Pay to pubkey hash.
    Pkh(KeyProvider),

    /// wpkh(KEY) - Pay to witness pubkey hash.
    Wpkh(KeyProvider),

    /// sh(SCRIPT) - Pay to script hash.
    Sh(Box<Descriptor>),

    /// wsh(SCRIPT) - Pay to witness script hash.
    Wsh(Box<Descriptor>),

    /// tr(KEY) - Taproot key-path only.
    TrKeyOnly(KeyProvider),

    /// tr(KEY, TREE) - Taproot with script tree.
    TrWithTree {
        /// The internal key.
        internal_key: KeyProvider,
        /// The script tree (simplified: list of leaf scripts with depths).
        tree: Vec<(Box<Descriptor>, u8)>,
    },

    /// multi(K, KEY1, KEY2, ...) - K-of-N multisig.
    Multi {
        /// Number of required signatures.
        threshold: usize,
        /// The public keys.
        keys: Vec<KeyProvider>,
    },

    /// sortedmulti(K, KEY1, KEY2, ...) - K-of-N multisig with sorted keys.
    SortedMulti {
        /// Number of required signatures.
        threshold: usize,
        /// The public keys.
        keys: Vec<KeyProvider>,
    },

    /// addr(ADDR) - Raw address.
    Addr(Address),

    /// raw(HEX) - Raw scriptPubKey.
    Raw(Vec<u8>),

    /// combo(KEY) - P2PK + P2PKH + P2WPKH + P2SH-P2WPKH.
    Combo(KeyProvider),
}

impl Descriptor {
    /// Returns true if this is a ranged descriptor.
    pub fn is_range(&self) -> bool {
        match self {
            Descriptor::Pk(k)
            | Descriptor::Pkh(k)
            | Descriptor::Wpkh(k)
            | Descriptor::TrKeyOnly(k)
            | Descriptor::Combo(k) => k.is_range(),
            Descriptor::Sh(inner) | Descriptor::Wsh(inner) => inner.is_range(),
            Descriptor::TrWithTree { internal_key, tree } => {
                internal_key.is_range() || tree.iter().any(|(d, _)| d.is_range())
            }
            Descriptor::Multi { keys, .. } | Descriptor::SortedMulti { keys, .. } => {
                keys.iter().any(|k| k.is_range())
            }
            Descriptor::Addr(_) | Descriptor::Raw(_) => false,
        }
    }

    /// Derive the scriptPubKey at the given position.
    pub fn derive_script(&self, pos: u32, network: Network) -> Result<Vec<u8>, DescriptorError> {
        self.derive_scripts(pos, network)
            .map(|scripts| scripts.into_iter().next().unwrap_or_default())
    }

    /// Derive all scriptPubKeys at the given position.
    ///
    /// Most descriptors produce a single script, but `combo()` produces multiple.
    pub fn derive_scripts(&self, pos: u32, network: Network) -> Result<Vec<Vec<u8>>, DescriptorError> {
        match self {
            Descriptor::Pk(key) => {
                let pubkey = key.get_pubkey(pos)?;
                let script = make_p2pk_script(&pubkey);
                Ok(vec![script])
            }
            Descriptor::Pkh(key) => {
                let pubkey = key.get_pubkey(pos)?;
                let script = make_p2pkh_script(&pubkey);
                Ok(vec![script])
            }
            Descriptor::Wpkh(key) => {
                let pubkey = key.get_pubkey(pos)?;
                // P2WPKH requires compressed pubkey
                if pubkey.serialize().len() != 33 {
                    return Err(DescriptorError::InvalidKey(
                        "P2WPKH requires compressed pubkey".into(),
                    ));
                }
                let script = make_p2wpkh_script(&pubkey);
                Ok(vec![script])
            }
            Descriptor::Sh(inner) => {
                let inner_scripts = inner.derive_scripts(pos, network)?;
                let mut result = Vec::new();
                for inner_script in inner_scripts {
                    let script = make_p2sh_script(&inner_script);
                    result.push(script);
                }
                Ok(result)
            }
            Descriptor::Wsh(inner) => {
                let inner_scripts = inner.derive_scripts(pos, network)?;
                let mut result = Vec::new();
                for inner_script in inner_scripts {
                    let script = make_p2wsh_script(&inner_script);
                    result.push(script);
                }
                Ok(result)
            }
            Descriptor::TrKeyOnly(key) => {
                let pubkey = key.get_pubkey(pos)?;
                let script = make_p2tr_script(&pubkey, None)?;
                Ok(vec![script])
            }
            Descriptor::TrWithTree { internal_key, tree } => {
                let pubkey = internal_key.get_pubkey(pos)?;
                // Compute Merkle root from tree
                let merkle_root = compute_taproot_merkle_root(tree, pos, network)?;
                let script = make_p2tr_script(&pubkey, Some(&merkle_root))?;
                Ok(vec![script])
            }
            Descriptor::Multi { threshold, keys } => {
                let pubkeys: Result<Vec<_>, _> =
                    keys.iter().map(|k| k.get_pubkey(pos)).collect();
                let script = make_multisig_script(*threshold, &pubkeys?, false)?;
                Ok(vec![script])
            }
            Descriptor::SortedMulti { threshold, keys } => {
                let pubkeys: Result<Vec<_>, _> =
                    keys.iter().map(|k| k.get_pubkey(pos)).collect();
                let script = make_multisig_script(*threshold, &pubkeys?, true)?;
                Ok(vec![script])
            }
            Descriptor::Addr(addr) => Ok(vec![addr.to_script_pubkey()]),
            Descriptor::Raw(script) => Ok(vec![script.clone()]),
            Descriptor::Combo(key) => {
                let pubkey = key.get_pubkey(pos)?;
                let mut scripts = vec![make_p2pk_script(&pubkey), make_p2pkh_script(&pubkey)];

                // If compressed, also add SegWit variants
                if pubkey.serialize().len() == 33 {
                    let p2wpkh = make_p2wpkh_script(&pubkey);
                    let p2sh_p2wpkh = make_p2sh_script(&p2wpkh);
                    scripts.push(p2wpkh);
                    scripts.push(p2sh_p2wpkh);
                }
                Ok(scripts)
            }
        }
    }

    /// Derive addresses at the given position.
    pub fn derive_addresses(&self, pos: u32, network: Network) -> Result<Vec<Address>, DescriptorError> {
        let scripts = self.derive_scripts(pos, network)?;
        scripts
            .into_iter()
            .map(|script| script_to_address(&script, network))
            .collect()
    }

    /// Derive addresses for a range of positions.
    pub fn derive_addresses_range(
        &self,
        range: std::ops::Range<u32>,
        network: Network,
    ) -> Result<Vec<Address>, DescriptorError> {
        let mut addresses = Vec::new();
        for pos in range {
            addresses.extend(self.derive_addresses(pos, network)?);
        }
        Ok(addresses)
    }

    /// Get the descriptor string with checksum.
    pub fn to_string_with_checksum(&self) -> String {
        let desc = self.to_string();
        add_checksum(&desc).unwrap_or(desc)
    }

    /// Get the output type of this descriptor.
    pub fn output_type(&self) -> Option<OutputType> {
        match self {
            Descriptor::Pk(_) => Some(OutputType::Bare),
            Descriptor::Pkh(_) => Some(OutputType::Pkh),
            Descriptor::Wpkh(_) => Some(OutputType::Wpkh),
            Descriptor::Sh(inner) => {
                if matches!(**inner, Descriptor::Wpkh(_)) {
                    Some(OutputType::ShWpkh)
                } else if matches!(**inner, Descriptor::Wsh(_)) {
                    Some(OutputType::ShWsh)
                } else {
                    Some(OutputType::Sh)
                }
            }
            Descriptor::Wsh(_) => Some(OutputType::Wsh),
            Descriptor::TrKeyOnly(_) | Descriptor::TrWithTree { .. } => Some(OutputType::Tr),
            Descriptor::Multi { .. } | Descriptor::SortedMulti { .. } => Some(OutputType::Bare),
            Descriptor::Addr(addr) => match addr {
                Address::P2PKH { .. } => Some(OutputType::Pkh),
                Address::P2SH { .. } => Some(OutputType::Sh),
                Address::P2WPKH { .. } => Some(OutputType::Wpkh),
                Address::P2WSH { .. } => Some(OutputType::Wsh),
                Address::P2TR { .. } => Some(OutputType::Tr),
            },
            Descriptor::Raw(_) => None,
            Descriptor::Combo(_) => None, // combo produces multiple types
        }
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Descriptor::Pk(key) => write!(f, "pk({})", key.to_public_string()),
            Descriptor::Pkh(key) => write!(f, "pkh({})", key.to_public_string()),
            Descriptor::Wpkh(key) => write!(f, "wpkh({})", key.to_public_string()),
            Descriptor::Sh(inner) => write!(f, "sh({})", inner),
            Descriptor::Wsh(inner) => write!(f, "wsh({})", inner),
            Descriptor::TrKeyOnly(key) => write!(f, "tr({})", key.to_public_string()),
            Descriptor::TrWithTree { internal_key, tree } => {
                write!(f, "tr({}", internal_key.to_public_string())?;
                for (desc, _depth) in tree {
                    write!(f, ",{}", desc)?;
                }
                write!(f, ")")
            }
            Descriptor::Multi { threshold, keys } => {
                write!(f, "multi({}", threshold)?;
                for key in keys {
                    write!(f, ",{}", key.to_public_string())?;
                }
                write!(f, ")")
            }
            Descriptor::SortedMulti { threshold, keys } => {
                write!(f, "sortedmulti({}", threshold)?;
                for key in keys {
                    write!(f, ",{}", key.to_public_string())?;
                }
                write!(f, ")")
            }
            Descriptor::Addr(addr) => write!(f, "addr({})", addr),
            Descriptor::Raw(script) => write!(f, "raw({})", hex::encode(script)),
            Descriptor::Combo(key) => write!(f, "combo({})", key.to_public_string()),
        }
    }
}

/// Output types for descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputType {
    /// Bare scripts (P2PK, bare multisig).
    Bare,
    /// P2PKH (legacy).
    Pkh,
    /// P2SH (legacy script hash).
    Sh,
    /// P2SH-P2WPKH (nested SegWit).
    ShWpkh,
    /// P2SH-P2WSH (nested SegWit script).
    ShWsh,
    /// P2WPKH (native SegWit).
    Wpkh,
    /// P2WSH (native SegWit script).
    Wsh,
    /// P2TR (Taproot).
    Tr,
}

// =============================================================================
// Descriptor info
// =============================================================================

/// Information about a descriptor.
#[derive(Clone, Debug)]
pub struct DescriptorInfo {
    /// The descriptor string (without checksum).
    pub descriptor: String,
    /// The checksum.
    pub checksum: String,
    /// Whether this is a ranged descriptor.
    pub is_range: bool,
    /// Whether this descriptor requires private keys for signing.
    pub is_solvable: bool,
    /// Whether this descriptor has embedded scripts.
    pub has_private_keys: bool,
}

impl DescriptorInfo {
    /// Get info for a parsed descriptor.
    pub fn from_descriptor(desc: &Descriptor) -> Self {
        let descriptor_str = desc.to_string();
        let checksum = descriptor_checksum(&descriptor_str).unwrap_or_default();
        Self {
            descriptor: descriptor_str,
            checksum,
            is_range: desc.is_range(),
            is_solvable: true, // Most descriptors are solvable
            has_private_keys: false, // Would need to check key providers
        }
    }
}

// =============================================================================
// Script construction helpers
// =============================================================================

/// Create a P2PK script: <pubkey> OP_CHECKSIG
fn make_p2pk_script(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_bytes = pubkey.serialize();
    let mut script = Vec::with_capacity(pubkey_bytes.len() + 2);
    script.push(pubkey_bytes.len() as u8);
    script.extend_from_slice(&pubkey_bytes);
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Create a P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
fn make_p2pkh_script(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_bytes = pubkey.serialize();
    let hash = hash160(&pubkey_bytes);
    let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 <push 20>
    script.extend_from_slice(&hash.0);
    script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    script
}

/// Create a P2WPKH script: OP_0 <20-byte-hash>
fn make_p2wpkh_script(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_bytes = pubkey.serialize();
    let hash = hash160(&pubkey_bytes);
    let mut script = vec![0x00, 0x14]; // OP_0 <push 20>
    script.extend_from_slice(&hash.0);
    script
}

/// Create a P2SH script: OP_HASH160 <hash> OP_EQUAL
fn make_p2sh_script(redeem_script: &[u8]) -> Vec<u8> {
    let hash = hash160(redeem_script);
    let mut script = vec![0xa9, 0x14]; // OP_HASH160 <push 20>
    script.extend_from_slice(&hash.0);
    script.push(0x87); // OP_EQUAL
    script
}

/// Create a P2WSH script: OP_0 <32-byte-hash>
fn make_p2wsh_script(witness_script: &[u8]) -> Vec<u8> {
    let hash = sha256(witness_script);
    let mut script = vec![0x00, 0x20]; // OP_0 <push 32>
    script.extend_from_slice(&hash);
    script
}

/// Create a P2TR script: OP_1 <32-byte-output-key>
fn make_p2tr_script(internal_key: &PublicKey, merkle_root: Option<&[u8; 32]>) -> Result<Vec<u8>, DescriptorError> {
    // Get x-only internal key (32 bytes)
    let internal_bytes = internal_key.serialize();
    let x_only = &internal_bytes[1..33];

    // Compute tweak
    let tweak = if let Some(root) = merkle_root {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(x_only);
        data.extend_from_slice(root);
        tagged_hash("TapTweak", &data)
    } else {
        tagged_hash("TapTweak", x_only)
    };

    // Tweak the internal key
    let secp = secp256k1::Secp256k1::new();
    let tweak_scalar = secp256k1::Scalar::from_be_bytes(tweak)
        .map_err(|_| DescriptorError::KeyDerivation)?;
    let tweaked = internal_key
        .add_exp_tweak(&secp, &tweak_scalar)
        .map_err(|_| DescriptorError::KeyDerivation)?;

    // Get x-only output key
    let output_bytes = tweaked.serialize();
    let output_x_only = &output_bytes[1..33];

    // Build P2TR script: OP_1 <32-byte-key>
    let mut script = vec![0x51, 0x20]; // OP_1 <push 32>
    script.extend_from_slice(output_x_only);
    Ok(script)
}

/// Create a multisig script: OP_<k> <key1> <key2> ... OP_<n> OP_CHECKMULTISIG
fn make_multisig_script(
    threshold: usize,
    keys: &[PublicKey],
    sorted: bool,
) -> Result<Vec<u8>, DescriptorError> {
    if threshold > keys.len() || threshold == 0 {
        return Err(DescriptorError::InvalidThreshold {
            k: threshold,
            n: keys.len(),
        });
    }
    if keys.len() > 20 {
        return Err(DescriptorError::InvalidThreshold {
            k: threshold,
            n: keys.len(),
        });
    }

    let mut sorted_keys: Vec<Vec<u8>> = keys.iter().map(|k| k.serialize().to_vec()).collect();
    if sorted {
        sorted_keys.sort();
    }

    let mut script = Vec::new();
    // OP_<k>
    script.push(0x50 + threshold as u8);

    // Push each key
    for key_bytes in &sorted_keys {
        script.push(key_bytes.len() as u8);
        script.extend_from_slice(key_bytes);
    }

    // OP_<n>
    script.push(0x50 + keys.len() as u8);
    // OP_CHECKMULTISIG
    script.push(0xae);

    Ok(script)
}

/// Compute Taproot Merkle root from a script tree.
fn compute_taproot_merkle_root(
    tree: &[(Box<Descriptor>, u8)],
    _pos: u32,
    _network: Network,
) -> Result<[u8; 32], DescriptorError> {
    if tree.is_empty() {
        return Err(DescriptorError::InvalidScript("empty script tree".into()));
    }

    // Simplified: compute leaf hashes and combine them
    // Full implementation would build proper Huffman tree
    let mut hashes: Vec<[u8; 32]> = Vec::new();

    for (desc, _depth) in tree {
        // Get the script for this leaf
        let scripts = desc.derive_scripts(0, Network::Mainnet)?;
        let script = &scripts[0];

        // Compute leaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)
        let leaf_version = 0xc0u8; // Tapscript
        let mut leaf_data = Vec::new();
        leaf_data.push(leaf_version);
        // Add compact size
        if script.len() < 0xfd {
            leaf_data.push(script.len() as u8);
        } else {
            return Err(DescriptorError::InvalidScript("script too large".into()));
        }
        leaf_data.extend_from_slice(script);
        hashes.push(tagged_hash("TapLeaf", &leaf_data));
    }

    // Combine hashes into Merkle root
    while hashes.len() > 1 {
        let mut new_hashes = Vec::new();
        let mut i = 0;
        while i < hashes.len() {
            if i + 1 < hashes.len() {
                // Combine two hashes (sort lexicographically)
                let (left, right) = if hashes[i] < hashes[i + 1] {
                    (&hashes[i], &hashes[i + 1])
                } else {
                    (&hashes[i + 1], &hashes[i])
                };
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(left);
                combined.extend_from_slice(right);
                new_hashes.push(tagged_hash("TapBranch", &combined));
                i += 2;
            } else {
                new_hashes.push(hashes[i]);
                i += 1;
            }
        }
        hashes = new_hashes;
    }

    Ok(hashes[0])
}

/// Convert a scriptPubKey to an address.
fn script_to_address(script: &[u8], network: Network) -> Result<Address, DescriptorError> {
    // P2PKH: OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&script[3..23]);
        return Ok(Address::P2PKH {
            hash: Hash160::from_bytes(hash_bytes),
            network,
        });
    }

    // P2SH: OP_HASH160 <20> ... OP_EQUAL
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&script[2..22]);
        return Ok(Address::P2SH {
            hash: Hash160::from_bytes(hash_bytes),
            network,
        });
    }

    // P2WPKH: OP_0 <20>
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&script[2..22]);
        return Ok(Address::P2WPKH {
            hash: Hash160::from_bytes(hash_bytes),
            network,
        });
    }

    // P2WSH: OP_0 <32>
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&script[2..34]);
        return Ok(Address::P2WSH {
            hash: rustoshi_primitives::Hash256::from_bytes(hash_bytes),
            network,
        });
    }

    // P2TR: OP_1 <32>
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&script[2..34]);
        return Ok(Address::P2TR {
            output_key: key_bytes,
            network,
        });
    }

    Err(DescriptorError::InvalidScript(
        "cannot convert script to address".into(),
    ))
}

// =============================================================================
// Extended key encoding
// =============================================================================

/// Version bytes for xpub/xprv.
const XPUB_VERSION_MAINNET: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const XPRV_VERSION_MAINNET: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const XPUB_VERSION_TESTNET: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
const XPRV_VERSION_TESTNET: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// Encode an extended public key to xpub format.
pub fn encode_xpub(xpub: &ExtendedPubKey, network: Network) -> String {
    let version = match network {
        Network::Mainnet => XPUB_VERSION_MAINNET,
        Network::Testnet | Network::Regtest => XPUB_VERSION_TESTNET,
    };

    let mut data = Vec::with_capacity(78);
    data.extend_from_slice(&version);
    data.push(xpub.depth);
    data.extend_from_slice(&xpub.parent_fingerprint);
    data.extend_from_slice(&xpub.child_number.to_be_bytes());
    data.extend_from_slice(&xpub.chain_code);
    data.extend_from_slice(&xpub.public_key.serialize());

    rustoshi_crypto::base58check_encode(&data)
}

/// Encode an extended private key to xprv format.
pub fn encode_xprv(xprv: &ExtendedPrivKey, network: Network) -> String {
    let version = match network {
        Network::Mainnet => XPRV_VERSION_MAINNET,
        Network::Testnet | Network::Regtest => XPRV_VERSION_TESTNET,
    };

    let mut data = Vec::with_capacity(78);
    data.extend_from_slice(&version);
    data.push(xprv.depth);
    data.extend_from_slice(&xprv.parent_fingerprint);
    data.extend_from_slice(&xprv.child_number.to_be_bytes());
    data.extend_from_slice(&xprv.chain_code);
    data.push(0x00); // Private key prefix
    data.extend_from_slice(&xprv.secret_key.secret_bytes());

    rustoshi_crypto::base58check_encode(&data)
}

/// Decode an xpub string to an ExtendedPubKey.
pub fn decode_xpub(s: &str) -> Result<(ExtendedPubKey, Network), DescriptorError> {
    let data = rustoshi_crypto::base58check_decode(s)
        .map_err(|e| DescriptorError::InvalidExtKey(format!("base58 error: {}", e)))?;

    if data.len() != 78 {
        return Err(DescriptorError::InvalidExtKey(format!(
            "invalid length: {}",
            data.len()
        )));
    }

    let version: [u8; 4] = data[0..4].try_into().unwrap();
    let network = if version == XPUB_VERSION_MAINNET {
        Network::Mainnet
    } else if version == XPUB_VERSION_TESTNET {
        Network::Testnet
    } else {
        return Err(DescriptorError::InvalidExtKey(format!(
            "unknown version: {:?}",
            version
        )));
    };

    let depth = data[4];
    let mut parent_fingerprint = [0u8; 4];
    parent_fingerprint.copy_from_slice(&data[5..9]);
    let child_number = u32::from_be_bytes(data[9..13].try_into().unwrap());
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&data[13..45]);
    let public_key = PublicKey::from_slice(&data[45..78])
        .map_err(|e| DescriptorError::InvalidExtKey(format!("invalid pubkey: {}", e)))?;

    Ok((
        ExtendedPubKey {
            public_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_number,
        },
        network,
    ))
}

/// Decode an xprv string to an ExtendedPrivKey.
pub fn decode_xprv(s: &str) -> Result<(ExtendedPrivKey, Network), DescriptorError> {
    let data = rustoshi_crypto::base58check_decode(s)
        .map_err(|e| DescriptorError::InvalidExtKey(format!("base58 error: {}", e)))?;

    if data.len() != 78 {
        return Err(DescriptorError::InvalidExtKey(format!(
            "invalid length: {}",
            data.len()
        )));
    }

    let version: [u8; 4] = data[0..4].try_into().unwrap();
    let network = if version == XPRV_VERSION_MAINNET {
        Network::Mainnet
    } else if version == XPRV_VERSION_TESTNET {
        Network::Testnet
    } else {
        return Err(DescriptorError::InvalidExtKey(format!(
            "unknown version: {:?}",
            version
        )));
    };

    let depth = data[4];
    let mut parent_fingerprint = [0u8; 4];
    parent_fingerprint.copy_from_slice(&data[5..9]);
    let child_number = u32::from_be_bytes(data[9..13].try_into().unwrap());
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&data[13..45]);

    // data[45] should be 0x00
    if data[45] != 0x00 {
        return Err(DescriptorError::InvalidExtKey(
            "invalid private key prefix".into(),
        ));
    }

    let secret_key = secp256k1::SecretKey::from_slice(&data[46..78])
        .map_err(|e| DescriptorError::InvalidExtKey(format!("invalid secret key: {}", e)))?;

    Ok((
        ExtendedPrivKey {
            secret_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_number,
        },
        network,
    ))
}

// =============================================================================
// Descriptor parsing
// =============================================================================

/// Parse a descriptor string.
///
/// If the descriptor has a checksum (`#checksum`), it will be validated.
/// If no checksum is present, parsing proceeds without validation.
pub fn parse_descriptor(desc: &str) -> Result<Descriptor, DescriptorError> {
    let desc = desc.trim();

    // Check for checksum
    let desc_without_checksum = if desc.contains('#') {
        verify_checksum(desc)?
    } else {
        desc
    };

    parse_descriptor_inner(desc_without_checksum)
}

/// Parse a descriptor string (internal, without checksum).
fn parse_descriptor_inner(desc: &str) -> Result<Descriptor, DescriptorError> {
    // Find the function name and arguments
    let (func_name, args) = split_descriptor(desc)?;

    match func_name {
        "pk" => {
            let key = parse_key_expression(args)?;
            Ok(Descriptor::Pk(key))
        }
        "pkh" => {
            let key = parse_key_expression(args)?;
            Ok(Descriptor::Pkh(key))
        }
        "wpkh" => {
            let key = parse_key_expression(args)?;
            Ok(Descriptor::Wpkh(key))
        }
        "sh" => {
            let inner = parse_descriptor_inner(args)?;
            Ok(Descriptor::Sh(Box::new(inner)))
        }
        "wsh" => {
            let inner = parse_descriptor_inner(args)?;
            Ok(Descriptor::Wsh(Box::new(inner)))
        }
        "tr" => parse_tr_descriptor(args),
        "multi" => parse_multi_descriptor(args, false),
        "sortedmulti" => parse_multi_descriptor(args, true),
        "addr" => {
            let addr = Address::from_string(args, None)
                .map_err(|e| DescriptorError::InvalidAddress(e.to_string()))?;
            Ok(Descriptor::Addr(addr))
        }
        "raw" => {
            let script = hex::decode(args)
                .map_err(|e| DescriptorError::InvalidHex(e.to_string()))?;
            Ok(Descriptor::Raw(script))
        }
        "combo" => {
            let key = parse_key_expression(args)?;
            Ok(Descriptor::Combo(key))
        }
        "rawtr" => {
            // Raw Taproot output key
            let key = parse_key_expression(args)?;
            Ok(Descriptor::TrKeyOnly(key))
        }
        _ => Err(DescriptorError::UnsupportedType(func_name.into())),
    }
}

/// Split a descriptor into function name and arguments.
fn split_descriptor(desc: &str) -> Result<(&str, &str), DescriptorError> {
    let open = desc
        .find('(')
        .ok_or_else(|| DescriptorError::InvalidSyntax("missing opening parenthesis".into()))?;
    let close = desc
        .rfind(')')
        .ok_or_else(|| DescriptorError::InvalidSyntax("missing closing parenthesis".into()))?;

    if close < open {
        return Err(DescriptorError::InvalidSyntax("malformed parentheses".into()));
    }

    let func_name = &desc[..open];
    let args = &desc[open + 1..close];

    Ok((func_name, args))
}

/// Parse a Taproot descriptor.
fn parse_tr_descriptor(args: &str) -> Result<Descriptor, DescriptorError> {
    // Split on comma at depth 0
    let parts = split_args(args);

    if parts.is_empty() {
        return Err(DescriptorError::InvalidSyntax("tr() requires at least one argument".into()));
    }

    let internal_key = parse_key_expression(parts[0])?;

    if parts.len() == 1 {
        // Key-only spend
        Ok(Descriptor::TrKeyOnly(internal_key))
    } else {
        // Has script tree
        let mut tree = Vec::new();
        for part in &parts[1..] {
            // Parse as a script descriptor
            let script_desc = parse_descriptor_inner(part)?;
            tree.push((Box::new(script_desc), 0u8)); // depth 0 for now
        }
        Ok(Descriptor::TrWithTree { internal_key, tree })
    }
}

/// Parse a multi/sortedmulti descriptor.
fn parse_multi_descriptor(args: &str, sorted: bool) -> Result<Descriptor, DescriptorError> {
    let parts = split_args(args);

    if parts.len() < 2 {
        return Err(DescriptorError::InvalidSyntax(
            "multi() requires threshold and at least one key".into(),
        ));
    }

    let threshold: usize = parts[0]
        .parse()
        .map_err(|_| DescriptorError::InvalidSyntax("invalid threshold".into()))?;

    let mut keys = Vec::new();
    for part in &parts[1..] {
        let key = parse_key_expression(part)?;
        keys.push(key);
    }

    if threshold > keys.len() || threshold == 0 {
        return Err(DescriptorError::InvalidThreshold {
            k: threshold,
            n: keys.len(),
        });
    }

    if sorted {
        Ok(Descriptor::SortedMulti { threshold, keys })
    } else {
        Ok(Descriptor::Multi { threshold, keys })
    }
}

/// Split arguments on commas at depth 0 (not inside parentheses/brackets).
fn split_args(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                result.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }

    let last = s[start..].trim();
    if !last.is_empty() {
        result.push(last);
    }

    result
}

/// Parse a key expression.
fn parse_key_expression(expr: &str) -> Result<KeyProvider, DescriptorError> {
    let expr = expr.trim();

    // Check for origin info: [fingerprint/path]key
    if expr.starts_with('[') {
        return parse_key_with_origin(expr);
    }

    // Check for xpub/xprv
    if expr.starts_with("xpub") || expr.starts_with("tpub") {
        return parse_xpub_key(expr);
    }
    if expr.starts_with("xprv") || expr.starts_with("tprv") {
        return parse_xprv_key(expr);
    }

    // Check for hex pubkey
    if expr.len() == 66 || expr.len() == 130 {
        // 33 bytes compressed or 65 bytes uncompressed
        if expr.chars().all(|c| c.is_ascii_hexdigit()) {
            return parse_hex_pubkey(expr);
        }
    }

    // Check for x-only pubkey (32 bytes = 64 hex chars)
    if expr.len() == 64 && expr.chars().all(|c| c.is_ascii_hexdigit()) {
        return parse_xonly_pubkey(expr);
    }

    Err(DescriptorError::InvalidKey(format!(
        "unrecognized key format: {}",
        expr
    )))
}

/// Parse a key with origin info: [fingerprint/path]key
fn parse_key_with_origin(expr: &str) -> Result<KeyProvider, DescriptorError> {
    let close = expr
        .find(']')
        .ok_or_else(|| DescriptorError::InvalidSyntax("missing ] in origin".into()))?;

    let origin_str = &expr[1..close];
    let key_str = &expr[close + 1..];

    // Parse origin: fingerprint/path
    let (fingerprint, path, apostrophe) = parse_origin(origin_str)?;

    // Parse the inner key
    let inner = parse_key_expression(key_str)?;

    Ok(KeyProvider::WithOrigin {
        origin: KeyOrigin::new(fingerprint, path),
        inner: Box::new(inner),
        apostrophe,
    })
}

/// Parse origin info: fingerprint/path
fn parse_origin(s: &str) -> Result<([u8; 4], Vec<u32>, bool), DescriptorError> {
    let parts: Vec<&str> = s.splitn(2, '/').collect();

    // Parse fingerprint (8 hex chars)
    if parts[0].len() != 8 {
        return Err(DescriptorError::InvalidKey(format!(
            "invalid fingerprint length: {}",
            parts[0].len()
        )));
    }
    let fp_bytes = hex::decode(parts[0])
        .map_err(|_| DescriptorError::InvalidKey("invalid fingerprint hex".into()))?;
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&fp_bytes);

    // Parse path if present
    if parts.len() == 1 {
        return Ok((fingerprint, vec![], true));
    }

    let path_str = parts[1];
    let apostrophe = path_str.contains('\'');
    let path = parse_derivation_path(path_str)
        .map_err(|e| DescriptorError::InvalidPath(e.to_string()))?;

    Ok((fingerprint, path, apostrophe))
}

/// Parse an xpub key expression.
fn parse_xpub_key(expr: &str) -> Result<KeyProvider, DescriptorError> {
    // Find where the xpub ends and path begins
    let (xpub_str, path_str, derive_type, apostrophe) = split_xpub_and_path(expr)?;

    let (xpub, _network) = decode_xpub(xpub_str)?;

    // Parse path
    let path = if path_str.is_empty() {
        vec![]
    } else {
        parse_derivation_path(path_str)
            .map_err(|e| DescriptorError::InvalidPath(e.to_string()))?
    };

    Ok(KeyProvider::Xpub {
        xpub,
        path,
        derive_type,
        apostrophe,
    })
}

/// Parse an xprv key expression.
fn parse_xprv_key(expr: &str) -> Result<KeyProvider, DescriptorError> {
    let (xprv_str, path_str, derive_type, apostrophe) = split_xpub_and_path(expr)?;

    let (xprv, _network) = decode_xprv(xprv_str)?;

    let path = if path_str.is_empty() {
        vec![]
    } else {
        parse_derivation_path(path_str)
            .map_err(|e| DescriptorError::InvalidPath(e.to_string()))?
    };

    Ok(KeyProvider::Xprv {
        xprv,
        path,
        derive_type,
        apostrophe,
    })
}

/// Split an xpub/xprv expression into the key and path parts.
fn split_xpub_and_path(expr: &str) -> Result<(&str, &str, DeriveType, bool), DescriptorError> {
    // xpub is always 111 chars (base58check of 78 bytes)
    // Check for path after xpub
    let xpub_end = expr
        .find('/')
        .unwrap_or(expr.len());

    let xpub_str = &expr[..xpub_end];
    let path_part = if xpub_end < expr.len() {
        &expr[xpub_end..]
    } else {
        ""
    };

    // Check for range indicator /*
    let (path_str, derive_type, apostrophe) = if let Some(s) = path_part.strip_suffix("/*'") {
        (s, DeriveType::HardenedRanged, true)
    } else if let Some(s) = path_part.strip_suffix("/*h") {
        (s, DeriveType::HardenedRanged, false)
    } else if let Some(s) = path_part.strip_suffix("/*") {
        (s, DeriveType::UnhardenedRanged, true)
    } else {
        (path_part, DeriveType::NonRanged, path_part.contains('\''))
    };

    Ok((xpub_str, path_str, derive_type, apostrophe))
}

/// Parse a hex-encoded public key.
fn parse_hex_pubkey(hex_str: &str) -> Result<KeyProvider, DescriptorError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| DescriptorError::InvalidHex(e.to_string()))?;
    let pubkey = PublicKey::from_slice(&bytes)
        .map_err(|e| DescriptorError::InvalidKey(format!("invalid pubkey: {}", e)))?;
    Ok(KeyProvider::Const {
        pubkey,
        xonly: false,
    })
}

/// Parse an x-only public key (32 bytes).
fn parse_xonly_pubkey(hex_str: &str) -> Result<KeyProvider, DescriptorError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| DescriptorError::InvalidHex(e.to_string()))?;

    // Add the even y-coordinate prefix to make it a valid secp256k1 pubkey
    let mut full_bytes = vec![0x02];
    full_bytes.extend_from_slice(&bytes);

    let pubkey = PublicKey::from_slice(&full_bytes)
        .map_err(|e| DescriptorError::InvalidKey(format!("invalid x-only pubkey: {}", e)))?;

    Ok(KeyProvider::Const { pubkey, xonly: true })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        // Test vector from BIP-380
        let desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let checksum = descriptor_checksum(desc).unwrap();
        assert_eq!(checksum, "gn28ywm7");

        // Test round-trip
        let with_checksum = add_checksum(desc).unwrap();
        assert_eq!(with_checksum, format!("{}#{}", desc, checksum));
        assert!(verify_checksum(&with_checksum).is_ok());
    }

    #[test]
    fn test_invalid_checksum() {
        let with_bad_checksum = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#xxxxxxxx";
        assert!(matches!(
            verify_checksum(with_bad_checksum),
            Err(DescriptorError::InvalidChecksum)
        ));
    }

    #[test]
    fn test_parse_pk() {
        let desc = parse_descriptor("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        assert!(matches!(desc, Descriptor::Pk(_)));
        assert!(!desc.is_range());
    }

    #[test]
    fn test_parse_pkh() {
        let desc = parse_descriptor("pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        assert!(matches!(desc, Descriptor::Pkh(_)));
    }

    #[test]
    fn test_parse_wpkh() {
        let desc = parse_descriptor("wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        assert!(matches!(desc, Descriptor::Wpkh(_)));
    }

    #[test]
    fn test_parse_sh_wpkh() {
        let desc = parse_descriptor("sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))").unwrap();
        if let Descriptor::Sh(inner) = desc {
            assert!(matches!(*inner, Descriptor::Wpkh(_)));
        } else {
            panic!("Expected Sh descriptor");
        }
    }

    #[test]
    fn test_parse_multi() {
        let desc = parse_descriptor(
            "multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,\
             02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
        ).unwrap();
        if let Descriptor::Multi { threshold, keys } = desc {
            assert_eq!(threshold, 2);
            assert_eq!(keys.len(), 2);
        } else {
            panic!("Expected Multi descriptor");
        }
    }

    #[test]
    fn test_parse_addr() {
        let desc = parse_descriptor("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)").unwrap();
        if let Descriptor::Addr(addr) = desc {
            assert!(matches!(addr, Address::P2WPKH { .. }));
        } else {
            panic!("Expected Addr descriptor");
        }
    }

    #[test]
    fn test_parse_raw() {
        let desc = parse_descriptor("raw(76a914751e76e8199196d454941c45d1b3a323f1433bd688ac)").unwrap();
        if let Descriptor::Raw(script) = desc {
            assert_eq!(hex::encode(&script), "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac");
        } else {
            panic!("Expected Raw descriptor");
        }
    }

    #[test]
    fn test_derive_pkh_script() {
        let desc = parse_descriptor("pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        let script = desc.derive_script(0, Network::Mainnet).unwrap();
        // P2PKH script for the generator point
        assert_eq!(
            hex::encode(&script),
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        );
    }

    #[test]
    fn test_derive_wpkh_script() {
        let desc = parse_descriptor("wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        let script = desc.derive_script(0, Network::Mainnet).unwrap();
        // P2WPKH script
        assert_eq!(
            hex::encode(&script),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn test_derive_address() {
        let desc = parse_descriptor("wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        let addrs = desc.derive_addresses(0, Network::Mainnet).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].to_string(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_combo_descriptor() {
        let desc = parse_descriptor("combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        let scripts = desc.derive_scripts(0, Network::Mainnet).unwrap();
        // combo produces P2PK, P2PKH, P2WPKH, P2SH-P2WPKH for compressed keys
        assert_eq!(scripts.len(), 4);
    }

    #[test]
    fn test_descriptor_to_string() {
        let desc = parse_descriptor("pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        let s = desc.to_string();
        assert!(s.starts_with("pkh("));
        assert!(s.ends_with(")"));
    }

    #[test]
    fn test_descriptor_with_checksum() {
        let desc = parse_descriptor("wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        let with_checksum = desc.to_string_with_checksum();
        assert!(with_checksum.contains('#'));
        // Parse again with checksum
        assert!(parse_descriptor(&with_checksum).is_ok());
    }

    #[test]
    fn test_xpub_encode_decode() {
        // Create a test xpub from a seed
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = master.to_public();

        let encoded = encode_xpub(&xpub, Network::Mainnet);
        assert!(encoded.starts_with("xpub"));

        let (decoded, network) = decode_xpub(&encoded).unwrap();
        assert_eq!(network, Network::Mainnet);
        assert_eq!(decoded.public_key, xpub.public_key);
        assert_eq!(decoded.chain_code, xpub.chain_code);
        assert_eq!(decoded.depth, xpub.depth);
    }

    #[test]
    fn test_parse_xpub_descriptor() {
        // Use BIP-32 test vector 1 master key
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = master.to_public();
        let encoded = encode_xpub(&xpub, Network::Mainnet);

        let desc_str = format!("wpkh({})", encoded);
        let desc = parse_descriptor(&desc_str).unwrap();
        assert!(matches!(desc, Descriptor::Wpkh(_)));
        assert!(!desc.is_range());
    }

    #[test]
    fn test_parse_xpub_with_path() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = master.to_public();
        let encoded = encode_xpub(&xpub, Network::Mainnet);

        let desc_str = format!("wpkh({}/0/*)", encoded);
        let desc = parse_descriptor(&desc_str).unwrap();
        assert!(desc.is_range());
    }

    #[test]
    fn test_parse_key_with_origin() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = master.to_public();
        let encoded = encode_xpub(&xpub, Network::Mainnet);
        let fp = hex::encode(master.fingerprint());

        let desc_str = format!("wpkh([{}/84'/0'/0']{}/*)", fp, encoded);
        let desc = parse_descriptor(&desc_str).unwrap();
        assert!(desc.is_range());
    }

    #[test]
    fn test_sortedmulti() {
        // Keys in non-sorted order
        let key1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let key2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        let desc = parse_descriptor(&format!("sortedmulti(1,{},{})", key2, key1)).unwrap();
        if let Descriptor::SortedMulti { threshold, keys } = &desc {
            assert_eq!(*threshold, 1);
            assert_eq!(keys.len(), 2);
        } else {
            panic!("Expected SortedMulti");
        }

        // The script should have keys in sorted order
        let script = desc.derive_script(0, Network::Mainnet).unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_derive_addresses_range() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = master.to_public();
        let encoded = encode_xpub(&xpub, Network::Mainnet);

        let desc_str = format!("wpkh({}/0/*)", encoded);
        let desc = parse_descriptor(&desc_str).unwrap();

        let addrs = desc.derive_addresses_range(0..5, Network::Mainnet).unwrap();
        assert_eq!(addrs.len(), 5);

        // Each address should be different
        for i in 0..addrs.len() {
            for j in i + 1..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }

    #[test]
    fn test_output_type() {
        let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let pkh = parse_descriptor(&format!("pkh({})", pubkey)).unwrap();
        assert_eq!(pkh.output_type(), Some(OutputType::Pkh));

        let wpkh = parse_descriptor(&format!("wpkh({})", pubkey)).unwrap();
        assert_eq!(wpkh.output_type(), Some(OutputType::Wpkh));

        let sh_wpkh = parse_descriptor(&format!("sh(wpkh({}))", pubkey)).unwrap();
        assert_eq!(sh_wpkh.output_type(), Some(OutputType::ShWpkh));
    }
}
