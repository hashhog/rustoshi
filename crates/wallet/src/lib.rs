//! Rustoshi HD Wallet
//!
//! This crate implements a BIP-32/44/49/84/86 compatible hierarchical deterministic wallet
//! for Bitcoin, supporting:
//!
//! - **BIP-32**: Hierarchical deterministic key derivation from a master seed
//! - **BIP-44**: Derivation paths for legacy P2PKH addresses
//! - **BIP-49**: Derivation paths for wrapped SegWit P2SH-P2WPKH addresses
//! - **BIP-84**: Derivation paths for native SegWit P2WPKH addresses
//! - **BIP-86**: Derivation paths for Taproot P2TR addresses
//!
//! # Features
//!
//! - HD key derivation with hardened and non-hardened paths
//! - Address generation (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
//! - UTXO tracking and balance calculation
//! - Transaction building with automatic UTXO selection
//! - BnB (Branch and Bound) and Knapsack coin selection algorithms
//! - Transaction signing for legacy, SegWit, and Taproot inputs
//! - BIP-125 Replace-By-Fee support
//!
//! # Example
//!
//! ```rust,ignore
//! use rustoshi_wallet::{Wallet, AddressType};
//! use rustoshi_crypto::address::Network;
//!
//! // Create a wallet from a 64-byte seed (e.g., from BIP-39 mnemonic)
//! let seed = [0u8; 64];
//! let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2TR)?;
//!
//! // Generate receiving addresses
//! let addr1 = wallet.get_new_address()?;
//! let addr2 = wallet.get_new_address()?;
//!
//! // Generate change address
//! let change = wallet.get_change_address()?;
//!
//! // Check balance
//! println!("Balance: {} sats", wallet.balance());
//! ```

pub mod coin_selection;
pub mod db;
pub mod descriptor;
pub mod hd;
pub mod miniscript;
pub mod psbt;
pub mod wallet;

pub use coin_selection::{
    select_coins, select_coins_bnb, select_coins_knapsack, select_coins_largest_first,
    CoinSelectionParams, SelectionAlgorithm, SelectionResult,
};
pub use db::{SavedAddress, SavedUtxo, WalletDb, WalletMeta};
pub use descriptor::{
    add_checksum, decode_xprv, decode_xpub, descriptor_checksum, encode_xprv, encode_xpub,
    parse_descriptor, verify_checksum, DeriveType, Descriptor, DescriptorError, DescriptorInfo,
    KeyOrigin as DescriptorKeyOrigin, KeyProvider, OutputType,
};
pub use hd::{parse_derivation_path, ExtendedPrivKey, ExtendedPubKey, WalletError, HARDENED_FLAG};
pub use miniscript::{
    Analysis, BasicType, Fragment, Miniscript, MiniscriptError, MiniscriptKey, Satisfier,
    SatisfactionResult, ScriptContext, StrKey, Type, TypeProperties, Witness,
};
pub use psbt::{KeyOrigin, Psbt, PsbtError, PsbtInput, PsbtOutput, PsbtRole};
pub use wallet::{calculate_vsize, AddressType, Wallet, WalletUtxo};
