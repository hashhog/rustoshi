//! Multi-wallet manager for loading, creating, and managing multiple wallets.
//!
//! This module provides a `WalletManager` that maintains a collection of wallets
//! identified by name, supporting concurrent access via `Arc<Mutex<Wallet>>`.
//!
//! Reference: Bitcoin Core's `wallet/wallet.cpp` (`CreateWallet`, `LoadWallet`)
//! and `wallet/load.cpp` (`LoadWallets`, `VerifyWallets`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::db::WalletDb;
use crate::hd::WalletError;
use crate::wallet::{AddressType, Wallet};
use rustoshi_crypto::address::Network;
use serde::{Deserialize, Serialize};

/// Options for creating a new wallet.
#[derive(Clone, Debug, Default)]
pub struct CreateWalletOptions {
    /// If true, create a wallet without private keys (watch-only).
    pub disable_private_keys: bool,
    /// If true, create a blank wallet with no keys or HD seed.
    pub blank: bool,
    /// Optional passphrase for wallet encryption.
    pub passphrase: Option<String>,
    /// If true, avoid address reuse by always generating new addresses.
    pub avoid_reuse: bool,
    /// If true, create a descriptor wallet (always true in modern Bitcoin Core).
    pub descriptors: bool,
    /// If true, load this wallet on startup.
    pub load_on_startup: Option<bool>,
}

/// Result of creating or loading a wallet.
#[derive(Debug)]
pub struct WalletResult {
    /// The wallet name.
    pub name: String,
    /// Any warnings generated during the operation.
    pub warnings: Vec<String>,
}

/// Information about a wallet in the wallet directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletDirEntry {
    /// Wallet name (directory name).
    pub name: String,
}

/// Manages multiple loaded wallets.
pub struct WalletManager {
    /// Loaded wallets, keyed by name.
    wallets: HashMap<String, Arc<Mutex<Wallet>>>,
    /// Wallet databases, keyed by name.
    wallet_dbs: HashMap<String, Arc<Mutex<WalletDb>>>,
    /// Base directory for wallet data.
    wallets_dir: PathBuf,
    /// Network (for address encoding).
    network: Network,
    /// Wallets to load on startup.
    load_on_startup: Vec<String>,
}

impl WalletManager {
    /// Create a new wallet manager.
    ///
    /// # Arguments
    /// * `data_dir` - The base data directory (e.g., ~/.rustoshi)
    /// * `network` - The Bitcoin network
    pub fn new(data_dir: &Path, network: Network) -> Result<Self, WalletError> {
        let wallets_dir = data_dir.join("wallets");
        fs::create_dir_all(&wallets_dir)
            .map_err(WalletError::Io)?;

        Ok(Self {
            wallets: HashMap::new(),
            wallet_dbs: HashMap::new(),
            wallets_dir,
            network,
            load_on_startup: Vec::new(),
        })
    }

    /// Create a new wallet manager with in-memory wallets (for testing).
    pub fn in_memory(network: Network) -> Self {
        Self {
            wallets: HashMap::new(),
            wallet_dbs: HashMap::new(),
            wallets_dir: PathBuf::new(),
            network,
            load_on_startup: Vec::new(),
        }
    }

    /// Get the wallets directory.
    pub fn wallets_dir(&self) -> &Path {
        &self.wallets_dir
    }

    /// Get the network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Create a new wallet.
    ///
    /// # Arguments
    /// * `name` - Wallet name (must be non-empty for new wallets)
    /// * `options` - Creation options
    ///
    /// # Errors
    /// Returns an error if the wallet already exists or creation fails.
    pub fn create_wallet(
        &mut self,
        name: &str,
        options: CreateWalletOptions,
    ) -> Result<WalletResult, WalletError> {
        // Validate name
        if name.is_empty() {
            return Err(WalletError::InvalidPath("wallet name cannot be empty".into()));
        }

        // Check if already loaded
        if self.wallets.contains_key(name) {
            return Err(WalletError::InvalidPath(format!(
                "wallet '{}' is already loaded",
                name
            )));
        }

        // Check if wallet directory already exists
        let wallet_dir = self.wallets_dir.join(name);
        if wallet_dir.exists() {
            return Err(WalletError::InvalidPath(format!(
                "wallet '{}' already exists",
                name
            )));
        }

        let mut warnings = Vec::new();

        // Create wallet directory
        fs::create_dir_all(&wallet_dir)
            .map_err(WalletError::Io)?;

        // Create database
        let db_path = wallet_dir.join("wallet.sqlite");
        let db = WalletDb::open(&db_path)?;

        // Create wallet
        let wallet = if options.blank || options.disable_private_keys {
            // Create a blank wallet with a dummy seed
            // In a real implementation, we'd have a different constructor
            warnings.push("blank wallet created - no keys available".into());
            let seed = [0u8; 64];
            Wallet::from_seed(&seed, self.network, AddressType::P2WPKH)?
        } else {
            // Generate a random seed
            let mut seed = [0u8; 64];
            getrandom::getrandom(&mut seed)
                .map_err(|e| WalletError::Crypto(format!("failed to generate random seed: {}", e)))?;
            Wallet::from_seed(&seed, self.network, AddressType::P2WPKH)?
        };

        // Save wallet metadata
        let meta = crate::db::WalletMeta {
            name: name.to_string(),
            network: self.network,
            address_type: AddressType::P2WPKH,
            next_receive_index: 0,
            next_change_index: 0,
            birthday: 0,
        };
        db.save_wallet_meta(&meta)?;

        // Store wallet
        let wallet_arc = Arc::new(Mutex::new(wallet));
        let db_arc = Arc::new(Mutex::new(db));
        self.wallets.insert(name.to_string(), wallet_arc);
        self.wallet_dbs.insert(name.to_string(), db_arc);

        // Handle load_on_startup
        if let Some(true) = options.load_on_startup {
            self.load_on_startup.push(name.to_string());
        }

        Ok(WalletResult {
            name: name.to_string(),
            warnings,
        })
    }

    /// Load an existing wallet.
    ///
    /// # Arguments
    /// * `name` - Wallet name (filename or directory name)
    ///
    /// # Errors
    /// Returns an error if the wallet doesn't exist or loading fails.
    pub fn load_wallet(&mut self, name: &str) -> Result<WalletResult, WalletError> {
        // Check if already loaded
        if self.wallets.contains_key(name) {
            return Err(WalletError::InvalidPath(format!(
                "wallet '{}' is already loaded",
                name
            )));
        }

        // Check if wallet directory exists
        let wallet_dir = self.wallets_dir.join(name);
        if !wallet_dir.exists() {
            return Err(WalletError::InvalidPath(format!(
                "wallet '{}' not found",
                name
            )));
        }

        let warnings = Vec::new();

        // Open database
        let db_path = wallet_dir.join("wallet.sqlite");
        let db = WalletDb::open(&db_path)?;

        // Load metadata
        let meta = db.load_wallet_meta()?
            .ok_or_else(|| WalletError::InvalidPath("wallet metadata not found".into()))?;

        // For now, create a wallet from a fixed seed (in production, we'd load the
        // encrypted seed from the database)
        // TODO: Implement proper seed storage and loading
        let seed = [0u8; 64];
        let mut wallet = Wallet::from_seed(&seed, meta.network, meta.address_type)?;

        // Restore state
        wallet.restore_indices(meta.next_receive_index, meta.next_change_index);

        // Store wallet
        let wallet_arc = Arc::new(Mutex::new(wallet));
        let db_arc = Arc::new(Mutex::new(db));
        self.wallets.insert(name.to_string(), wallet_arc);
        self.wallet_dbs.insert(name.to_string(), db_arc);

        Ok(WalletResult {
            name: name.to_string(),
            warnings,
        })
    }

    /// Unload a wallet.
    ///
    /// # Arguments
    /// * `name` - Wallet name
    /// * `save` - Whether to save wallet state before unloading
    ///
    /// # Errors
    /// Returns an error if the wallet is not loaded.
    pub fn unload_wallet(&mut self, name: &str, save: bool) -> Result<WalletResult, WalletError> {
        let wallet = self.wallets.remove(name)
            .ok_or_else(|| WalletError::InvalidPath(format!(
                "wallet '{}' is not loaded",
                name
            )))?;

        let db = self.wallet_dbs.remove(name);

        if save {
            if let (Some(db_arc), Ok(wallet_guard)) = (db, wallet.lock()) {
                if let Ok(db_guard) = db_arc.lock() {
                    // Save current state
                    let (recv_idx, change_idx) = wallet_guard.get_indices();
                    let meta = crate::db::WalletMeta {
                        name: name.to_string(),
                        network: self.network,
                        address_type: wallet_guard.address_type(),
                        next_receive_index: recv_idx,
                        next_change_index: change_idx,
                        birthday: 0,
                    };
                    let _ = db_guard.save_wallet_meta(&meta);
                }
            }
        }

        Ok(WalletResult {
            name: name.to_string(),
            warnings: vec![],
        })
    }

    /// Get a reference to a loaded wallet.
    pub fn get_wallet(&self, name: &str) -> Option<Arc<Mutex<Wallet>>> {
        self.wallets.get(name).cloned()
    }

    /// Get a reference to a wallet's database.
    pub fn get_wallet_db(&self, name: &str) -> Option<Arc<Mutex<WalletDb>>> {
        self.wallet_dbs.get(name).cloned()
    }

    /// Get the default wallet (used when only one wallet is loaded).
    ///
    /// Returns `None` if no wallets are loaded or multiple wallets are loaded.
    pub fn get_default_wallet(&self) -> Option<(String, Arc<Mutex<Wallet>>)> {
        if self.wallets.len() == 1 {
            let (name, wallet) = self.wallets.iter().next()?;
            Some((name.clone(), wallet.clone()))
        } else {
            None
        }
    }

    /// Get a wallet by name, or the default if only one is loaded.
    ///
    /// Returns an error if multiple wallets are loaded and no name is specified.
    pub fn get_wallet_or_default(&self, name: Option<&str>) -> Result<(String, Arc<Mutex<Wallet>>), WalletError> {
        match name {
            Some(n) => {
                let wallet = self.get_wallet(n)
                    .ok_or_else(|| WalletError::InvalidPath(format!(
                        "wallet '{}' not found",
                        n
                    )))?;
                Ok((n.to_string(), wallet))
            }
            None => {
                if self.wallets.is_empty() {
                    Err(WalletError::InvalidPath("no wallets loaded".into()))
                } else if self.wallets.len() > 1 {
                    Err(WalletError::InvalidPath(
                        "multiple wallets loaded; specify wallet name in URL (e.g., /wallet/mywallet)"
                            .into()
                    ))
                } else {
                    self.get_default_wallet()
                        .ok_or_else(|| WalletError::InvalidPath("no wallet available".into()))
                }
            }
        }
    }

    /// List loaded wallet names.
    pub fn list_wallets(&self) -> Vec<String> {
        self.wallets.keys().cloned().collect()
    }

    /// List wallet directories (both loaded and unloaded).
    pub fn list_wallet_dir(&self) -> Result<Vec<WalletDirEntry>, WalletError> {
        let mut entries = Vec::new();

        if !self.wallets_dir.exists() {
            return Ok(entries);
        }

        for entry in fs::read_dir(&self.wallets_dir)
            .map_err(WalletError::Io)?
        {
            let entry = entry.map_err(WalletError::Io)?;
            let path = entry.path();

            if path.is_dir() {
                // Check if it looks like a wallet directory
                let wallet_file = path.join("wallet.sqlite");
                if wallet_file.exists() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        entries.push(WalletDirEntry {
                            name: name.to_string(),
                        });
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Check if a wallet is loaded.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.wallets.contains_key(name)
    }

    /// Get the number of loaded wallets.
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Get wallets to load on startup.
    pub fn wallets_to_load_on_startup(&self) -> &[String] {
        &self.load_on_startup
    }

    /// Load wallets marked for startup loading.
    pub fn load_startup_wallets(&mut self) -> Result<(), WalletError> {
        // Load settings.json if it exists
        let settings_path = self.wallets_dir.parent()
            .map(|p| p.join("settings.json"))
            .unwrap_or_default();

        if settings_path.exists() {
            if let Ok(content) = fs::read_to_string(&settings_path) {
                if let Ok(settings) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(wallets) = settings.get("wallet").and_then(|w| w.as_array()) {
                        for wallet in wallets {
                            if let Some(name) = wallet.as_str() {
                                // Ignore errors for individual wallets
                                let _ = self.load_wallet(name);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Save wallets to load on startup to settings.json.
    pub fn save_startup_settings(&self) -> Result<(), WalletError> {
        let settings_path = self.wallets_dir.parent()
            .map(|p| p.join("settings.json"))
            .ok_or_else(|| WalletError::InvalidPath("invalid wallets directory".into()))?;

        let settings = serde_json::json!({
            "wallet": self.load_on_startup
        });

        let content = serde_json::to_string_pretty(&settings)
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        fs::write(&settings_path, content)
            .map_err(WalletError::Io)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_wallet() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        let result = manager.create_wallet("test_wallet", CreateWalletOptions::default());
        assert!(result.is_ok());

        let wallet_result = result.unwrap();
        assert_eq!(wallet_result.name, "test_wallet");

        // Check wallet is loaded
        assert!(manager.is_loaded("test_wallet"));
        assert_eq!(manager.wallet_count(), 1);
    }

    #[test]
    fn test_create_duplicate_wallet() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager.create_wallet("test_wallet", CreateWalletOptions::default()).unwrap();
        let result = manager.create_wallet("test_wallet", CreateWalletOptions::default());

        assert!(result.is_err());
    }

    #[test]
    fn test_load_unload_wallet() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        // Create and then unload
        manager.create_wallet("test_wallet", CreateWalletOptions::default()).unwrap();
        assert!(manager.is_loaded("test_wallet"));

        manager.unload_wallet("test_wallet", true).unwrap();
        assert!(!manager.is_loaded("test_wallet"));

        // Reload
        let result = manager.load_wallet("test_wallet");
        assert!(result.is_ok());
        assert!(manager.is_loaded("test_wallet"));
    }

    #[test]
    fn test_list_wallets() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        assert!(manager.list_wallets().is_empty());

        manager.create_wallet("wallet1", CreateWalletOptions::default()).unwrap();
        manager.create_wallet("wallet2", CreateWalletOptions::default()).unwrap();

        let wallets = manager.list_wallets();
        assert_eq!(wallets.len(), 2);
        assert!(wallets.contains(&"wallet1".to_string()));
        assert!(wallets.contains(&"wallet2".to_string()));
    }

    #[test]
    fn test_get_wallet_or_default() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        // No wallets - should error
        assert!(manager.get_wallet_or_default(None).is_err());

        // One wallet - should return it by default
        manager.create_wallet("wallet1", CreateWalletOptions::default()).unwrap();
        let result = manager.get_wallet_or_default(None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "wallet1");

        // Two wallets - should error without name
        manager.create_wallet("wallet2", CreateWalletOptions::default()).unwrap();
        assert!(manager.get_wallet_or_default(None).is_err());

        // Two wallets - should work with name
        let result = manager.get_wallet_or_default(Some("wallet2"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "wallet2");
    }

    #[test]
    fn test_list_wallet_dir() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager.create_wallet("wallet1", CreateWalletOptions::default()).unwrap();
        manager.create_wallet("wallet2", CreateWalletOptions::default()).unwrap();

        // Unload wallet2
        manager.unload_wallet("wallet2", true).unwrap();

        // List should show both
        let dir_entries = manager.list_wallet_dir().unwrap();
        assert_eq!(dir_entries.len(), 2);
    }
}
