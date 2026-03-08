//! Rustoshi HD Wallet
//!
//! This crate implements a BIP-32/44/84 compatible hierarchical deterministic wallet
//! for Bitcoin, supporting:
//!
//! - **BIP-32**: Hierarchical deterministic key derivation from a master seed
//! - **BIP-44**: Derivation paths for legacy P2PKH addresses
//! - **BIP-84**: Derivation paths for native SegWit P2WPKH addresses
//! - **BIP-49**: Derivation paths for wrapped SegWit P2SH-P2WPKH addresses
//!
//! # Features
//!
//! - HD key derivation with hardened and non-hardened paths
//! - Address generation (P2WPKH, P2PKH, P2SH-P2WPKH)
//! - UTXO tracking and balance calculation
//! - Transaction building with automatic UTXO selection
//! - Transaction signing for SegWit and legacy inputs
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
//! let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH)?;
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

pub mod hd;
pub mod wallet;

pub use hd::{parse_derivation_path, ExtendedPrivKey, ExtendedPubKey, WalletError, HARDENED_FLAG};
pub use wallet::{calculate_vsize, AddressType, Wallet, WalletUtxo};
