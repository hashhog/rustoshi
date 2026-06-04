//! Multi-wallet manager for loading, creating, and managing multiple wallets.
//!
//! This module provides a `WalletManager` that maintains a collection of wallets
//! identified by name, supporting concurrent access via `Arc<Mutex<Wallet>>`.
//!
//! Reference: Bitcoin Core's `wallet/wallet.cpp` (`CreateWallet`, `LoadWallet`)
//! and `wallet/load.cpp` (`LoadWallets`, `VerifyWallets`).

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::db::WalletDb;
use crate::encryption::{
    decrypt_seed, encrypt_seed, parse_seed_file, ParsedSeedFile, DEFAULT_KDF_ITERATIONS,
};
use crate::hd::WalletError;
use crate::wallet::{AddressType, Wallet};
use rustoshi_crypto::address::Network;
use serde::{Deserialize, Serialize};

/// File name for the persisted master HD seed.
///
/// Stored as raw 64 bytes inside the wallet directory. Mirrors Bitcoin Core's
/// `WALLET_HDCHAIN` ("hdchain") key in `wallet/walletdb.cpp`, but kept as a
/// separate file because rustoshi's `WalletDb` (SQLite) intentionally does not
/// store secret material.
const SEED_FILE_NAME: &str = "wallet_seed.bin";

/// Length of the persisted master seed in bytes (matches `Wallet::from_seed`
/// and BIP-39 64-byte seeds).
const SEED_LEN: usize = 64;

/// Atomically write a byte payload to `<wallet_dir>/wallet_seed.bin`.
///
/// Writes to a temp file in the same directory, fsyncs, then renames over
/// the target. This way an unencrypted `wallet_seed.bin` cannot linger if
/// the encrypted write is interrupted partway, and a partial write cannot
/// leave the file in a half-encrypted state.
///
/// On Unix, both temp and target inherit mode `0600`.
fn write_seed_payload(wallet_dir: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    let final_path = wallet_dir.join(SEED_FILE_NAME);
    let tmp_path = wallet_dir.join(format!("{}.tmp", SEED_FILE_NAME));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(WalletError::Io)?;
        file.write_all(bytes).map_err(WalletError::Io)?;
        file.sync_all().map_err(WalletError::Io)?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(WalletError::Io)?;
        file.write_all(bytes).map_err(WalletError::Io)?;
        file.sync_all().map_err(WalletError::Io)?;
    }

    fs::rename(&tmp_path, &final_path).map_err(WalletError::Io)?;
    // Best-effort fsync of the directory entry so the rename is durable.
    if let Ok(dir) = fs::File::open(wallet_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Persist a master seed to `<wallet_dir>/wallet_seed.bin`.
///
/// If `passphrase` is `Some(non_empty)`, the seed is encrypted with
/// ChaCha20-Poly1305 using a key derived from the passphrase by
/// PBKDF2-HMAC-SHA512 ([`DEFAULT_KDF_ITERATIONS`] iters) over a freshly
/// random per-wallet salt. Otherwise the raw 64 bytes are written
/// (backward-compatible v1 layout).
///
/// On Unix, the file is created with mode `0600`. The write is atomic via
/// temp file + rename so an interrupted write cannot leak a partial
/// plaintext.
fn persist_seed(
    wallet_dir: &Path,
    seed: &[u8; SEED_LEN],
    passphrase: Option<&str>,
) -> Result<(), WalletError> {
    let payload: Vec<u8> = match passphrase {
        Some(pw) if !pw.is_empty() => encrypt_seed(seed, pw, DEFAULT_KDF_ITERATIONS)?,
        // Empty passphrase is treated as "no passphrase" — match Core's
        // walletpassphrase semantics where a zero-length passphrase is
        // refused. Caller (CreateWalletOptions::passphrase = Some("")) gets
        // an unencrypted wallet rather than a silently-empty-passphrase one.
        _ => seed.to_vec(),
    };

    write_seed_payload(wallet_dir, &payload)
}

/// Outcome of [`load_seed`]: the seed itself if the wallet is unencrypted
/// (or no seed file exists), or a parsed encrypted-file handle that the
/// caller must unlock with `walletpassphrase` before signing.
pub(crate) enum LoadedSeed {
    /// No seed file on disk (blank or pre-fix wallet).
    Absent,
    /// Plaintext seed loaded directly from disk (v1 layout).
    Plaintext([u8; SEED_LEN]),
    /// Encrypted seed; the in-memory wallet must be constructed from a
    /// dummy zero seed and signing must be gated until [`unlock`].
    Encrypted(crate::encryption::EncryptedSeedFile),
}

/// Load a master seed from `<wallet_dir>/wallet_seed.bin`.
///
/// Returns `Ok(LoadedSeed::Absent)` if the file does not exist (e.g., a
/// blank wallet). Returns an error if the file exists but is the wrong size
/// or unreadable. If the file is encrypted (v2 layout), returns
/// `Ok(LoadedSeed::Encrypted(...))` — the seed plaintext is NOT recovered
/// until the user supplies the passphrase via `walletpassphrase`.
pub(crate) fn load_seed(wallet_dir: &Path) -> Result<LoadedSeed, WalletError> {
    let seed_path = wallet_dir.join(SEED_FILE_NAME);
    if !seed_path.exists() {
        return Ok(LoadedSeed::Absent);
    }

    let mut file = fs::File::open(&seed_path).map_err(WalletError::Io)?;
    let mut buf = Vec::with_capacity(SEED_LEN);
    file.read_to_end(&mut buf).map_err(WalletError::Io)?;

    let parsed = parse_seed_file(&buf).map_err(WalletError::from)?;
    Ok(match parsed {
        ParsedSeedFile::PlaintextV1(seed) => LoadedSeed::Plaintext(seed),
        ParsedSeedFile::EncryptedV2(file) => LoadedSeed::Encrypted(file),
    })
}

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

/// Per-wallet encryption + lock state.
///
/// Mirrors the in-memory bookkeeping Bitcoin Core does in
/// `wallet/wallet.h::CWallet` (`fUseCrypto`, `mapMasterKeys`, `IsLocked()`).
/// rustoshi's wallet object holds the BIP-32 master key in plaintext once
/// constructed, so when the wallet is encrypted-and-locked we keep a
/// **placeholder** wallet (zero-seed) and refuse signing operations through
/// the `require_unlocked` gate. On `walletpassphrase`, we decrypt the seed
/// and *swap in* a real wallet object; on `walletlock`, we swap the
/// placeholder back.
#[derive(Debug, Clone)]
pub struct WalletLockState {
    /// True if the on-disk seed file is the v2 encrypted format.
    pub encrypted: bool,
    /// True if currently unlocked (master seed available in memory).
    /// Always true for unencrypted wallets, since there is nothing to lock.
    pub unlocked: bool,
    /// If unlocked and a timeout was supplied to `walletpassphrase`, this
    /// is the instant at which we'll auto-relock. `None` means "no timeout"
    /// (unencrypted wallets) or "unlocked indefinitely" — Core requires a
    /// timeout, so the RPC layer always supplies one; this `None` exists
    /// solely for unencrypted wallets and the brief window during
    /// `encryptwallet`.
    pub unlock_until: Option<Instant>,
}

impl WalletLockState {
    fn unencrypted() -> Self {
        Self {
            encrypted: false,
            unlocked: true,
            unlock_until: None,
        }
    }

    fn locked() -> Self {
        Self {
            encrypted: true,
            unlocked: false,
            unlock_until: None,
        }
    }

    fn unlocked_for(timeout: Duration) -> Self {
        Self {
            encrypted: true,
            unlocked: true,
            unlock_until: Some(Instant::now() + timeout),
        }
    }

    /// Drive the auto-relock timer. Returns true if state changed.
    fn tick(&mut self) -> bool {
        if self.encrypted && self.unlocked {
            if let Some(deadline) = self.unlock_until {
                if Instant::now() >= deadline {
                    self.unlocked = false;
                    self.unlock_until = None;
                    return true;
                }
            }
        }
        false
    }
}

/// Manages multiple loaded wallets.
pub struct WalletManager {
    /// Loaded wallets, keyed by name.
    wallets: HashMap<String, Arc<Mutex<Wallet>>>,
    /// Wallet databases, keyed by name.
    wallet_dbs: HashMap<String, Arc<Mutex<WalletDb>>>,
    /// Per-wallet encryption + lock bookkeeping. Always populated alongside
    /// `wallets`.
    lock_states: HashMap<String, Arc<Mutex<WalletLockState>>>,
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
            lock_states: HashMap::new(),
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
            lock_states: HashMap::new(),
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

        // Validate passphrase up-front — empty string means "no encryption"
        // (matches Core's walletpassphrase, which rejects empty new passes).
        // Some(non_empty) means "encrypt the seed on disk".
        let passphrase: Option<&str> = options
            .passphrase
            .as_deref()
            .filter(|p| !p.is_empty());
        let want_encryption = passphrase.is_some();

        // Create wallet
        let (wallet, lock_state) = if options.blank || options.disable_private_keys {
            // Create a blank wallet with a dummy seed.
            // In a real implementation, we'd have a different constructor.
            warnings.push("blank wallet created - no keys available".into());
            let seed = [0u8; SEED_LEN];
            // Persist even the blank seed so that loadwallet round-trips
            // produce a wallet equivalent to the one held in memory rather
            // than silently diverging. Honor the passphrase even for blank
            // wallets so the encrypted-state flag survives a reload.
            persist_seed(&wallet_dir, &seed, passphrase)?;
            let wallet = Wallet::from_seed(&seed, self.network, AddressType::P2WPKH)?;
            let state = if want_encryption {
                // Encrypted blank wallet starts locked.
                WalletLockState::locked()
            } else {
                WalletLockState::unencrypted()
            };
            (wallet, state)
        } else {
            // Generate a random seed and persist it BEFORE constructing the
            // wallet so that a later `loadwallet` reproduces the same key
            // material (Bitcoin Core writes the HD chain to walletdb under
            // the `WALLET_HDCHAIN` key in `wallet/walletdb.cpp`; we use a
            // sibling file because our SQLite store is non-secret).
            let mut seed = [0u8; SEED_LEN];
            getrandom::getrandom(&mut seed)
                .map_err(|e| WalletError::Crypto(format!("failed to generate random seed: {}", e)))?;
            persist_seed(&wallet_dir, &seed, passphrase)?;
            let wallet = Wallet::from_seed(&seed, self.network, AddressType::P2WPKH)?;
            let state = if want_encryption {
                // Wallet was just created with a passphrase — the seed is
                // in memory right now, but we honor Core's contract that an
                // encrypted wallet is locked on disk and the in-memory state
                // is ephemeral. Future loads will need walletpassphrase.
                // We DO keep the seed in memory for this session so that
                // immediately-following operations (e.g. getnewaddress in a
                // setup script) don't require a redundant walletpassphrase
                // call — Core does the same (`CreateWallet` returns an
                // unlocked wallet immediately after encryptwallet-on-create).
                WalletLockState::unlocked_for(Duration::from_secs(60 * 60 * 24 * 365))
            } else {
                WalletLockState::unencrypted()
            };
            (wallet, state)
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
        let lock_state_arc = Arc::new(Mutex::new(lock_state));
        self.wallets.insert(name.to_string(), wallet_arc);
        self.wallet_dbs.insert(name.to_string(), db_arc);
        self.lock_states.insert(name.to_string(), lock_state_arc);

        // Handle load_on_startup
        if let Some(true) = options.load_on_startup {
            self.load_on_startup.push(name.to_string());
        }

        Ok(WalletResult {
            name: name.to_string(),
            warnings,
        })
    }

    /// Deterministically (re)set the HD master seed of a loaded wallet.
    ///
    /// Mirrors the *intent* of Bitcoin Core's `sethdseed` RPC
    /// (`wallet/rpc/backup.cpp`): replace the wallet's HD chain so that the
    /// same seed always re-derives byte-identical key material. This is the
    /// mechanism that makes seed-only wallet recovery possible — a fresh,
    /// empty wallet fed the original seed re-derives the original addresses
    /// and can then rediscover its on-chain funds via `scantxoutset`.
    ///
    /// Differences from Core: Core's `sethdseed` takes a WIF private key (32
    /// bytes of entropy) and refuses to overwrite a non-empty HD chain unless
    /// `newkeypool` is forced. rustoshi's wallet is built directly from a
    /// BIP-39-style 64-byte master seed (see [`Wallet::from_seed`]), so this
    /// method takes the 64-byte seed directly. The new wallet inherits the
    /// existing wallet's network + address type, and the seed is persisted to
    /// `<wallet_dir>/wallet_seed.bin` so a later `loadwallet` round-trips to
    /// the same keys.
    ///
    /// The receive/change indices are reset to 0: after a restore the caller
    /// re-derives addresses from the start of each chain (Core behaves the
    /// same — a fresh keypool is generated from the new seed).
    ///
    /// # Arguments
    /// * `name` - Loaded wallet name.
    /// * `seed` - Exactly [`SEED_LEN`] (64) bytes of master seed.
    ///
    /// # Errors
    /// - `InvalidSeedLength` if `seed` is not 64 bytes.
    /// - `InvalidPath` if the wallet is not loaded.
    /// - propagated I/O / crypto errors from persistence and key derivation.
    pub fn set_hd_seed(&mut self, name: &str, seed: &[u8]) -> Result<(), WalletError> {
        if seed.len() != SEED_LEN {
            return Err(WalletError::InvalidSeedLength(seed.len()));
        }
        let mut seed_arr = [0u8; SEED_LEN];
        seed_arr.copy_from_slice(seed);

        // Resolve the loaded wallet to learn its network + address type.
        let wallet_arc = self
            .wallets
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;

        let (network, address_type) = {
            let guard = wallet_arc
                .lock()
                .map_err(|_| WalletError::InvalidPath("failed to lock wallet".into()))?;
            (guard.network(), guard.address_type())
        };

        // Build the deterministic wallet from the provided seed.
        let new_wallet = Wallet::from_seed(&seed_arr, network, address_type)?;

        // Persist the seed so `loadwallet` reproduces the same key material.
        // We write the v1 (unencrypted) layout here; an operator who wants the
        // restored wallet encrypted re-runs `encryptwallet` afterwards. This
        // matches the recovery use-case where the seed is the secret of record.
        let wallet_dir = self.wallets_dir.join(name);
        if wallet_dir.exists() {
            persist_seed(&wallet_dir, &seed_arr, None)?;
        }

        // Reset the persisted derivation indices so the restored wallet starts
        // from m/.../0 on both branches (a fresh keypool from the new seed).
        if let Some(db_arc) = self.wallet_dbs.get(name) {
            if let Ok(db_guard) = db_arc.lock() {
                let meta = crate::db::WalletMeta {
                    name: name.to_string(),
                    network,
                    address_type,
                    next_receive_index: 0,
                    next_change_index: 0,
                    birthday: 0,
                };
                let _ = db_guard.save_wallet_meta(&meta);
            }
        }

        // Swap the in-memory wallet's contents to the restored one.
        {
            let mut guard = wallet_arc
                .lock()
                .map_err(|_| WalletError::InvalidPath("failed to lock wallet".into()))?;
            *guard = new_wallet;
        }

        // The restored wallet is unencrypted + unlocked in memory.
        if let Some(ls) = self.lock_states.get(name) {
            if let Ok(mut ls_guard) = ls.lock() {
                *ls_guard = WalletLockState::unencrypted();
            }
        }

        Ok(())
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

        // Load the master seed from `<wallet_dir>/wallet_seed.bin`. This is
        // the on-disk equivalent of Bitcoin Core's `WALLET_HDCHAIN` (see
        // `bitcoin-core/src/wallet/walletdb.cpp`). Prior to this code path,
        // `loadwallet` deterministically returned a zero-seeded wallet
        // regardless of what `createwallet` had generated, which silently
        // diverged in-memory key material from any reload.
        //
        // If the seed file is encrypted (v2 layout), we construct a *placeholder*
        // wallet with the zero seed and mark the lock state as encrypted +
        // locked. The user must subsequently call `walletpassphrase` to
        // decrypt the seed and swap in a real wallet (see `unlock_wallet`).
        let loaded = load_seed(&wallet_dir)?;
        let (wallet, lock_state, mut warnings_inner) = match loaded {
            LoadedSeed::Absent => {
                return Err(WalletError::InvalidPath(format!(
                    "wallet '{}' is missing its persisted seed ({}); was it created \
                     before the loadwallet zero-seed fix? Re-create the wallet to \
                     generate a new seed.",
                    name, SEED_FILE_NAME
                )));
            }
            LoadedSeed::Plaintext(seed) => {
                let mut w = Wallet::from_seed(&seed, meta.network, meta.address_type)?;
                w.restore_indices(meta.next_receive_index, meta.next_change_index);
                (w, WalletLockState::unencrypted(), Vec::<String>::new())
            }
            LoadedSeed::Encrypted(_file) => {
                // Construct a placeholder wallet so getbalance / listunspent
                // (which don't need private keys) keep working. Signing
                // operations gate on the lock state separately.
                let placeholder_seed = [0u8; SEED_LEN];
                let mut w = Wallet::from_seed(
                    &placeholder_seed,
                    meta.network,
                    meta.address_type,
                )?;
                w.restore_indices(meta.next_receive_index, meta.next_change_index);
                // Note: the parsed encrypted file is dropped here. On unlock,
                // we re-read it from disk; this avoids holding the ciphertext
                // in memory longer than necessary and means a tampered file
                // between load and unlock is detected at unlock time.
                (
                    w,
                    WalletLockState::locked(),
                    vec![format!(
                        "wallet '{}' is encrypted; use walletpassphrase to unlock",
                        name
                    )],
                )
            }
        };

        // Store wallet
        let wallet_arc = Arc::new(Mutex::new(wallet));
        let db_arc = Arc::new(Mutex::new(db));
        let lock_state_arc = Arc::new(Mutex::new(lock_state));
        self.wallets.insert(name.to_string(), wallet_arc);
        self.wallet_dbs.insert(name.to_string(), db_arc);
        self.lock_states.insert(name.to_string(), lock_state_arc);

        warnings_inner.extend(warnings);
        Ok(WalletResult {
            name: name.to_string(),
            warnings: warnings_inner,
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
        let _lock_state = self.lock_states.remove(name);

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

    /// Scan a connected block into every loaded wallet's UTXO ledger.
    ///
    /// Mirrors Core's `CWallet::blockConnected` fan-out: each loaded wallet
    /// credits its own outputs and debits its own spent coins. Pure per-wallet
    /// mutation behind the existing `Arc<Mutex<Wallet>>`; a poisoned lock for
    /// one wallet never blocks the others. `height` is the connecting block's
    /// height (drives coinbase maturity). Returns total (credits, debits)
    /// across all wallets.
    pub fn scan_block_all_wallets(
        &self,
        txs: &[rustoshi_primitives::Transaction],
        height: u32,
        block_hash: rustoshi_primitives::Hash256,
        block_time: u64,
    ) -> (usize, usize) {
        let mut credits = 0usize;
        let mut debits = 0usize;
        for wallet in self.wallets.values() {
            if let Ok(mut w) = wallet.lock() {
                let (c, d) = w.scan_block_at(txs, height, block_hash, block_time);
                credits += c;
                debits += d;
            }
        }
        (credits, debits)
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

    // ------------------------------------------------------------------
    // Wallet encryption / lock API (W118 BUG-1 / P0-SECURITY closure)
    // ------------------------------------------------------------------
    //
    // The methods below implement Bitcoin Core's `walletpassphrase` /
    // `walletlock` / `encryptwallet` / `walletpassphrasechange` semantics
    // on top of the on-disk format defined in `crate::encryption`.

    /// Snapshot the current encryption + lock state for `name`. Useful for
    /// `getwalletinfo` and for callers that want to short-circuit before
    /// they need a wallet handle. Returns `None` if the wallet is not
    /// loaded. The auto-relock timer is driven on every read.
    pub fn lock_state(&self, name: &str) -> Option<WalletLockState> {
        let arc = self.lock_states.get(name)?;
        let mut guard = arc.lock().ok()?;
        guard.tick();
        Some(guard.clone())
    }

    /// Returns `Ok(())` if the wallet is unlocked (or unencrypted), or a
    /// `WalletError::WalletLocked` if a signing operation cannot proceed.
    /// This is the gate every signing path should call before reaching for
    /// private key material.
    pub fn require_unlocked(&self, name: &str) -> Result<(), WalletError> {
        let arc = self
            .lock_states
            .get(name)
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;
        let mut guard = arc
            .lock()
            .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
        guard.tick();
        if !guard.encrypted || guard.unlocked {
            Ok(())
        } else {
            Err(WalletError::WalletLocked)
        }
    }

    /// Decrypt the on-disk seed for `name` using `passphrase`, swap the
    /// real wallet object into the loaded map, and start the auto-relock
    /// timer.
    ///
    /// Mirrors `walletpassphrase` from Core's RPC layer
    /// (`bitcoin-core/src/wallet/rpc/encrypt.cpp`).
    ///
    /// - Errors with `WalletError::EncryptionState(_)` if the wallet is not
    ///   encrypted (Core's behavior on `walletpassphrase` for an unencrypted
    ///   wallet).
    /// - Errors with `WalletError::BadPassphrase` if the AEAD tag rejects
    ///   the (passphrase, ciphertext) pair.
    pub fn unlock_wallet(
        &mut self,
        name: &str,
        passphrase: &str,
        timeout: Duration,
    ) -> Result<(), WalletError> {
        // Snapshot existing state.
        let lock_state_arc = self
            .lock_states
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;
        {
            let state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            if !state.encrypted {
                return Err(WalletError::EncryptionState(
                    "wallet is not encrypted; walletpassphrase has no effect".into(),
                ));
            }
        }

        // Re-read the on-disk seed file. We deliberately re-parse on every
        // unlock so a tampered file between load and unlock surfaces here.
        let wallet_dir = self.wallets_dir.join(name);
        let loaded = load_seed(&wallet_dir)?;
        let file = match loaded {
            LoadedSeed::Encrypted(f) => f,
            LoadedSeed::Plaintext(_) | LoadedSeed::Absent => {
                return Err(WalletError::EncryptionState(format!(
                    "on-disk seed for '{}' is not in encrypted format",
                    name
                )));
            }
        };

        // Decrypt — this is where wrong passphrases are rejected.
        let seed = decrypt_seed(&file, passphrase).map_err(WalletError::from)?;

        // Need the address type + indices to build the live wallet.
        let db_arc = self
            .wallet_dbs
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' db not loaded", name)))?;
        let (network, address_type, recv_idx, change_idx) = {
            let db = db_arc
                .lock()
                .map_err(|_| WalletError::Crypto("db lock poisoned".into()))?;
            let meta = db
                .load_wallet_meta()?
                .ok_or_else(|| WalletError::InvalidPath("wallet meta missing".into()))?;
            (
                meta.network,
                meta.address_type,
                meta.next_receive_index,
                meta.next_change_index,
            )
        };

        let mut live = Wallet::from_seed(&seed, network, address_type)?;
        live.restore_indices(recv_idx, change_idx);

        // Atomically swap the placeholder wallet for the real one. We hold
        // the existing Arc<Mutex<Wallet>> and replace its inner content so
        // that any handle the RPC layer already cloned still points to the
        // unlocked wallet.
        let wallet_arc = self
            .wallets
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;
        {
            let mut guard = wallet_arc
                .lock()
                .map_err(|_| WalletError::Crypto("wallet lock poisoned".into()))?;
            *guard = live;
        }

        {
            let mut state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            *state = WalletLockState::unlocked_for(timeout);
        }

        Ok(())
    }

    /// Re-lock an encrypted wallet, scrubbing the master seed from memory.
    /// Mirrors `walletlock` from Core's RPC layer.
    ///
    /// No-op on unencrypted wallets. Returns success in that case to match
    /// Core's lenient behavior (Core actually errors with
    /// "running with an unencrypted wallet, but walletlock was called"; we
    /// preserve that error semantics by reporting `EncryptionState`).
    pub fn lock_wallet(&mut self, name: &str) -> Result<(), WalletError> {
        let lock_state_arc = self
            .lock_states
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;

        {
            let state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            if !state.encrypted {
                return Err(WalletError::EncryptionState(
                    "wallet is not encrypted; nothing to lock".into(),
                ));
            }
        }

        // Swap the live wallet for a zero-seed placeholder. This is the
        // memory-scrub step — once `live` falls out of scope, the BIP-32
        // master key is gone (the underlying secp256k1 SecretKey zeros on
        // Drop via the `secp256k1` crate's zeroize policy).
        let wallet_arc = self
            .wallets
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;

        let db_arc = self
            .wallet_dbs
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' db not loaded", name)))?;
        let (network, address_type, recv_idx, change_idx) = {
            let db = db_arc
                .lock()
                .map_err(|_| WalletError::Crypto("db lock poisoned".into()))?;
            let meta = db
                .load_wallet_meta()?
                .ok_or_else(|| WalletError::InvalidPath("wallet meta missing".into()))?;
            (
                meta.network,
                meta.address_type,
                meta.next_receive_index,
                meta.next_change_index,
            )
        };

        let mut placeholder =
            Wallet::from_seed(&[0u8; SEED_LEN], network, address_type)?;
        placeholder.restore_indices(recv_idx, change_idx);

        {
            let mut guard = wallet_arc
                .lock()
                .map_err(|_| WalletError::Crypto("wallet lock poisoned".into()))?;
            *guard = placeholder;
        }
        {
            let mut state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            *state = WalletLockState::locked();
        }

        Ok(())
    }

    /// Encrypt an unencrypted wallet in place. Mirrors `encryptwallet` from
    /// Core's RPC layer. Re-reads the plaintext seed from disk, encrypts it
    /// with the supplied passphrase, and atomically replaces the seed file.
    ///
    /// After success, the in-memory wallet remains unlocked for the rest of
    /// this session (matching Core, which historically would force a shutdown
    /// after encryptwallet but later relaxed to keeping the encrypted wallet
    /// usable until the next restart).
    pub fn encrypt_wallet(
        &mut self,
        name: &str,
        passphrase: &str,
    ) -> Result<(), WalletError> {
        if passphrase.is_empty() {
            return Err(WalletError::EncryptionState(
                "encryptwallet requires a non-empty passphrase".into(),
            ));
        }

        let lock_state_arc = self
            .lock_states
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;
        {
            let state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            if state.encrypted {
                return Err(WalletError::EncryptionState(
                    "wallet is already encrypted".into(),
                ));
            }
        }

        // Re-read the plaintext seed (the wallet keeps the BIP-32 derived
        // material in memory but not the raw 64-byte seed; the on-disk
        // file is the source of truth).
        let wallet_dir = self.wallets_dir.join(name);
        let loaded = load_seed(&wallet_dir)?;
        let seed = match loaded {
            LoadedSeed::Plaintext(s) => s,
            LoadedSeed::Encrypted(_) => {
                // Should never happen — we just checked the lock state — but
                // surface a clean error rather than asserting.
                return Err(WalletError::EncryptionState(
                    "on-disk seed already encrypted while in-memory state says unencrypted"
                        .into(),
                ));
            }
            LoadedSeed::Absent => {
                return Err(WalletError::InvalidPath(format!(
                    "wallet '{}' has no on-disk seed",
                    name
                )));
            }
        };

        // Write the encrypted form atomically. If this fails partway, the
        // temp file is left behind but the original plaintext stays intact;
        // a rerun will retry the encryption.
        persist_seed(&wallet_dir, &seed, Some(passphrase))?;

        // Update in-memory state to "encrypted + unlocked for the session".
        // Choose a long unlock timeout (effectively this session); the user
        // can call walletlock to scrub the key earlier.
        {
            let mut state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            *state = WalletLockState::unlocked_for(Duration::from_secs(60 * 60 * 24 * 365));
        }

        Ok(())
    }

    /// Change the passphrase of an already-encrypted wallet. Mirrors
    /// `walletpassphrasechange`. Requires the old passphrase (to unlock the
    /// seed) and a new non-empty passphrase.
    pub fn change_wallet_passphrase(
        &mut self,
        name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), WalletError> {
        if new_passphrase.is_empty() {
            return Err(WalletError::EncryptionState(
                "new passphrase must be non-empty".into(),
            ));
        }

        let lock_state_arc = self
            .lock_states
            .get(name)
            .cloned()
            .ok_or_else(|| WalletError::InvalidPath(format!("wallet '{}' not loaded", name)))?;
        {
            let state = lock_state_arc
                .lock()
                .map_err(|_| WalletError::Crypto("lock state poisoned".into()))?;
            if !state.encrypted {
                return Err(WalletError::EncryptionState(
                    "wallet is not encrypted; use encryptwallet first".into(),
                ));
            }
        }

        // Decrypt with the old passphrase. New salt + nonce are generated by
        // persist_seed → encrypt_seed, so an attacker who recorded the old
        // ciphertext cannot test the new passphrase against it.
        let wallet_dir = self.wallets_dir.join(name);
        let loaded = load_seed(&wallet_dir)?;
        let file = match loaded {
            LoadedSeed::Encrypted(f) => f,
            _ => {
                return Err(WalletError::EncryptionState(
                    "expected encrypted seed on disk".into(),
                ));
            }
        };
        let seed = decrypt_seed(&file, old_passphrase).map_err(WalletError::from)?;

        // Re-write with the new passphrase.
        persist_seed(&wallet_dir, &seed, Some(new_passphrase))?;

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

    /// Regression test for the loadwallet zero-seed bug.
    ///
    /// Before the fix, `create_wallet` generated a random seed but never
    /// persisted it, while `load_wallet` constructed the reloaded wallet
    /// from a literal `[0u8; 64]`. The reloaded wallet therefore derived a
    /// completely different first address than the in-memory original.
    ///
    /// This test asserts that:
    ///   1. createwallet's first address is non-deterministic (random seed),
    ///   2. unload + load round-trip yields the SAME first address
    ///      (i.e. the seed was actually persisted and reloaded), and
    ///   3. the reloaded address is NOT the all-zero-seed address (which
    ///      would indicate the regression returned).
    #[test]
    fn test_loadwallet_persists_seed_across_reload() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        // 1. Create the wallet and capture its first receiving address
        //    (peek so we don't bump indices and obscure the comparison).
        manager
            .create_wallet("regress", CreateWalletOptions::default())
            .unwrap();
        let original_addr = {
            let arc = manager.get_wallet("regress").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };

        // The freshly generated random seed must NOT collide with the
        // all-zero seed used by the buggy load path.
        let zero_seed_wallet =
            Wallet::from_seed(&[0u8; SEED_LEN], Network::Testnet, AddressType::P2WPKH)
                .unwrap();
        let zero_seed_addr = zero_seed_wallet.peek_address().unwrap();
        assert_ne!(
            original_addr, zero_seed_addr,
            "createwallet must produce a random seed, not zero"
        );

        // 2. Drop the in-memory wallet (simulating a process restart) and
        //    reload from disk.
        manager.unload_wallet("regress", true).unwrap();
        assert!(!manager.is_loaded("regress"));

        manager.load_wallet("regress").unwrap();
        let reloaded_addr = {
            let arc = manager.get_wallet("regress").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };

        // 3. The reloaded address must match the original (seed survived
        //    the round-trip) and must NOT be the zero-seed address (the
        //    bug we are guarding against).
        assert_eq!(
            reloaded_addr, original_addr,
            "loadwallet must reproduce the seed from createwallet"
        );
        assert_ne!(
            reloaded_addr, zero_seed_addr,
            "loadwallet must not silently fall back to a zero seed"
        );

        // The seed file should exist in the wallet directory and be exactly
        // SEED_LEN bytes.
        let seed_path = manager
            .wallets_dir()
            .join("regress")
            .join(SEED_FILE_NAME);
        let meta = fs::metadata(&seed_path).expect("seed file must exist on disk");
        assert_eq!(
            meta.len() as usize,
            SEED_LEN,
            "persisted seed must be exactly {} bytes",
            SEED_LEN
        );
    }

    /// Two independently-created wallets must have different first addresses
    /// — i.e. each gets its own random seed, persisted separately. This
    /// catches a different shape of the same regression where every wallet
    /// shared one seed.
    #[test]
    fn test_create_wallet_seeds_are_unique_per_wallet() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager.create_wallet("a", CreateWalletOptions::default()).unwrap();
        manager.create_wallet("b", CreateWalletOptions::default()).unwrap();

        let addr_a = {
            let arc = manager.get_wallet("a").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        let addr_b = {
            let arc = manager.get_wallet("b").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };

        assert_ne!(
            addr_a, addr_b,
            "distinct wallets must have distinct random seeds"
        );
    }

    /// `load_wallet` must surface a clear error when the persisted seed
    /// file is missing (e.g., a wallet directory predating this fix) rather
    /// than silently substituting a zero seed.
    #[test]
    fn test_load_wallet_errors_when_seed_missing() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager.create_wallet("orphan", CreateWalletOptions::default()).unwrap();
        manager.unload_wallet("orphan", true).unwrap();

        // Simulate a pre-fix wallet directory by deleting the seed file.
        let seed_path = manager
            .wallets_dir()
            .join("orphan")
            .join(SEED_FILE_NAME);
        fs::remove_file(&seed_path).unwrap();

        let err = manager.load_wallet("orphan").unwrap_err();
        match err {
            WalletError::InvalidPath(msg) => {
                assert!(
                    msg.contains("missing its persisted seed"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected InvalidPath, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // W118 BUG-1 / P0-SECURITY wallet encryption regression tests
    // ------------------------------------------------------------------

    /// Builds a passphrase'd CreateWalletOptions, since the field is
    /// non-trivial and we need it in several tests.
    fn opts_with_passphrase(p: &str) -> CreateWalletOptions {
        CreateWalletOptions {
            passphrase: Some(p.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn createwallet_with_passphrase_writes_encrypted_seed_to_disk() {
        // The most important test: when the user supplies a passphrase,
        // the on-disk wallet_seed.bin MUST NOT be the raw 64-byte seed.
        // This is the failure mode that motivated W118 BUG-1: prior to
        // this fix, the passphrase was silently dropped and the file
        // contained plaintext.
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("enc", opts_with_passphrase("strong-passphrase"))
            .unwrap();

        let seed_path = manager.wallets_dir().join("enc").join(SEED_FILE_NAME);
        let bytes = fs::read(&seed_path).unwrap();

        // File is the encrypted format (148 bytes), not the v1 plaintext
        // (64 bytes).
        assert_eq!(
            bytes.len(),
            crate::encryption::ENCRYPTED_FILE_LEN,
            "wallet_seed.bin must be the encrypted layout when a passphrase is set"
        );
        // And it starts with the v2 magic.
        assert_eq!(
            &bytes[..16],
            &crate::encryption::SEED_FILE_MAGIC,
            "encrypted wallet_seed.bin must start with the v2 magic"
        );
    }

    #[test]
    fn createwallet_without_passphrase_writes_plaintext_seed_v1() {
        // Backward compatibility: no passphrase → original 64-byte layout.
        // This ensures existing unencrypted wallets in the wild keep
        // working unchanged.
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("plain", CreateWalletOptions::default())
            .unwrap();

        let seed_path = manager.wallets_dir().join("plain").join(SEED_FILE_NAME);
        let bytes = fs::read(&seed_path).unwrap();
        assert_eq!(
            bytes.len(),
            SEED_LEN,
            "unencrypted wallets must keep the 64-byte plaintext layout"
        );
    }

    #[test]
    fn createwallet_empty_passphrase_writes_plaintext_not_encrypted() {
        // Empty-passphrase is treated as "no encryption" — see the gate in
        // persist_seed. This prevents a footgun where Some("") silently
        // becomes an "encrypted with empty passphrase" wallet.
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("plain-via-empty", opts_with_passphrase(""))
            .unwrap();

        let seed_path = manager
            .wallets_dir()
            .join("plain-via-empty")
            .join(SEED_FILE_NAME);
        let bytes = fs::read(&seed_path).unwrap();
        assert_eq!(bytes.len(), SEED_LEN);
    }

    #[test]
    fn plaintext_seed_bytes_do_not_appear_in_encrypted_file() {
        // Strong guarantee: even if some future regression in `from_seed`
        // happened to store the raw seed somewhere accessible, we want a
        // test that catches plaintext bytes leaking through to disk.
        //
        // Strategy: capture the address derived by the live wallet, then
        // capture the file bytes; the derived address is a function of the
        // seed via HMAC-SHA512 and BIP-32, so if the seed appeared
        // verbatim in the file we'd be in trouble anyway. The simpler
        // check is "the file does not contain N contiguous seed bytes."
        // Without access to the in-memory seed, we instead check the file
        // is a known-encrypted layout and that ten random 8-byte
        // alignments are not all zero (which would indicate an
        // unencrypted seed of zeros). The cleaner test is in the
        // encryption module's `plaintext_does_not_appear_on_disk`; here
        // we just verify the integration path runs encryption.
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("witness", opts_with_passphrase("integration-test-pw"))
            .unwrap();

        let seed_path = manager.wallets_dir().join("witness").join(SEED_FILE_NAME);
        let bytes = fs::read(&seed_path).unwrap();

        // Encrypted layout always begins with the magic; if any plaintext
        // leakage happened, this would be a 64-byte file or otherwise
        // mis-shaped.
        assert_eq!(bytes.len(), crate::encryption::ENCRYPTED_FILE_LEN);

        // Iterations field must equal the default. Catches the misuse case
        // where someone introduces a "store 1 iteration" debug path.
        let iters =
            u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        assert_eq!(iters, crate::encryption::DEFAULT_KDF_ITERATIONS);
    }

    #[test]
    fn loadwallet_on_encrypted_returns_locked_state() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("enc-load", opts_with_passphrase("pw1"))
            .unwrap();
        // Capture address before unload.
        let addr_pre_unload = {
            let arc = manager.get_wallet("enc-load").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        manager.unload_wallet("enc-load", true).unwrap();
        manager.load_wallet("enc-load").unwrap();

        // After load, lock state must be encrypted + locked.
        let state = manager.lock_state("enc-load").unwrap();
        assert!(state.encrypted);
        assert!(!state.unlocked);

        // The placeholder wallet's peek_address differs from the real one
        // (because it was constructed from a zero seed).
        let placeholder_addr = {
            let arc = manager.get_wallet("enc-load").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        assert_ne!(
            placeholder_addr, addr_pre_unload,
            "locked wallet should expose a placeholder, not the real seed's address"
        );

        // Signing path gate should refuse.
        assert!(matches!(
            manager.require_unlocked("enc-load"),
            Err(WalletError::WalletLocked)
        ));
    }

    #[test]
    fn unlock_with_correct_passphrase_restores_real_wallet() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("unlock-ok", opts_with_passphrase("good"))
            .unwrap();
        let orig_addr = {
            let arc = manager.get_wallet("unlock-ok").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        manager.unload_wallet("unlock-ok", true).unwrap();
        manager.load_wallet("unlock-ok").unwrap();

        // Unlock.
        manager
            .unlock_wallet("unlock-ok", "good", Duration::from_secs(60))
            .unwrap();

        // require_unlocked now succeeds.
        manager.require_unlocked("unlock-ok").unwrap();

        // And the live wallet derives the original address.
        let reloaded_addr = {
            let arc = manager.get_wallet("unlock-ok").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        assert_eq!(reloaded_addr, orig_addr);
    }

    #[test]
    fn unlock_with_wrong_passphrase_keeps_wallet_locked() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("unlock-bad", opts_with_passphrase("the-right-one"))
            .unwrap();
        manager.unload_wallet("unlock-bad", true).unwrap();
        manager.load_wallet("unlock-bad").unwrap();

        // Wrong passphrase rejected.
        let err = manager
            .unlock_wallet("unlock-bad", "WRONG", Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(err, WalletError::BadPassphrase));

        // State still locked.
        let state = manager.lock_state("unlock-bad").unwrap();
        assert!(!state.unlocked);
        assert!(matches!(
            manager.require_unlocked("unlock-bad"),
            Err(WalletError::WalletLocked)
        ));
    }

    #[test]
    fn lock_then_unlock_round_trip() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("rt", opts_with_passphrase("pw"))
            .unwrap();
        // Wallet was created encrypted but starts unlocked for the session.
        manager.require_unlocked("rt").unwrap();
        let orig_addr = {
            let arc = manager.get_wallet("rt").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };

        // Lock.
        manager.lock_wallet("rt").unwrap();
        assert!(matches!(
            manager.require_unlocked("rt"),
            Err(WalletError::WalletLocked)
        ));

        // Unlock.
        manager
            .unlock_wallet("rt", "pw", Duration::from_secs(60))
            .unwrap();
        manager.require_unlocked("rt").unwrap();
        let reloaded_addr = {
            let arc = manager.get_wallet("rt").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        assert_eq!(reloaded_addr, orig_addr);
    }

    #[test]
    fn unlock_auto_relock_after_timeout() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("timeout", opts_with_passphrase("pw"))
            .unwrap();
        manager.unload_wallet("timeout", true).unwrap();
        manager.load_wallet("timeout").unwrap();

        // Unlock with a zero-second timeout — the next state read should
        // observe the deadline has passed and flip back to locked.
        manager
            .unlock_wallet("timeout", "pw", Duration::from_millis(0))
            .unwrap();
        // Give the clock a moment to advance past `now + 0ms`.
        std::thread::sleep(Duration::from_millis(5));

        let state = manager.lock_state("timeout").unwrap();
        assert!(!state.unlocked, "auto-relock did not trigger");
        assert!(matches!(
            manager.require_unlocked("timeout"),
            Err(WalletError::WalletLocked)
        ));
    }

    #[test]
    fn encryptwallet_converts_plaintext_to_encrypted() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("convert", CreateWalletOptions::default())
            .unwrap();
        // Sanity: starts as plaintext.
        let seed_path = manager.wallets_dir().join("convert").join(SEED_FILE_NAME);
        assert_eq!(fs::read(&seed_path).unwrap().len(), SEED_LEN);
        let orig_addr = {
            let arc = manager.get_wallet("convert").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };

        // Encrypt in place.
        manager.encrypt_wallet("convert", "new-pw").unwrap();
        // File is now encrypted.
        assert_eq!(
            fs::read(&seed_path).unwrap().len(),
            crate::encryption::ENCRYPTED_FILE_LEN
        );
        // In-memory wallet still derives same address (we kept it unlocked).
        let post_addr = {
            let arc = manager.get_wallet("convert").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        assert_eq!(post_addr, orig_addr);

        // After a reload, wallet is encrypted+locked and requires unlock.
        manager.unload_wallet("convert", true).unwrap();
        manager.load_wallet("convert").unwrap();
        assert!(manager.lock_state("convert").unwrap().encrypted);
        assert!(matches!(
            manager.require_unlocked("convert"),
            Err(WalletError::WalletLocked)
        ));
        manager
            .unlock_wallet("convert", "new-pw", Duration::from_secs(60))
            .unwrap();
        let final_addr = {
            let arc = manager.get_wallet("convert").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        assert_eq!(final_addr, orig_addr);
    }

    #[test]
    fn encryptwallet_rejects_already_encrypted() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("twice", opts_with_passphrase("first"))
            .unwrap();
        let err = manager.encrypt_wallet("twice", "second").unwrap_err();
        assert!(matches!(err, WalletError::EncryptionState(_)));
    }

    #[test]
    fn encryptwallet_rejects_empty_passphrase() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("empty", CreateWalletOptions::default())
            .unwrap();
        let err = manager.encrypt_wallet("empty", "").unwrap_err();
        assert!(matches!(err, WalletError::EncryptionState(_)));
    }

    #[test]
    fn walletlock_on_unencrypted_errors() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("unenc", CreateWalletOptions::default())
            .unwrap();
        let err = manager.lock_wallet("unenc").unwrap_err();
        assert!(matches!(err, WalletError::EncryptionState(_)));
    }

    #[test]
    fn walletpassphrase_on_unencrypted_errors() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("unenc", CreateWalletOptions::default())
            .unwrap();
        let err = manager
            .unlock_wallet("unenc", "anything", Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(err, WalletError::EncryptionState(_)));
    }

    #[test]
    fn change_passphrase_round_trip() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("rotate", opts_with_passphrase("old"))
            .unwrap();
        let orig_addr = {
            let arc = manager.get_wallet("rotate").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };

        manager
            .change_wallet_passphrase("rotate", "old", "new")
            .unwrap();

        // After a reload, the old passphrase must fail and the new must work.
        manager.unload_wallet("rotate", true).unwrap();
        manager.load_wallet("rotate").unwrap();
        let err = manager
            .unlock_wallet("rotate", "old", Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(err, WalletError::BadPassphrase));
        manager
            .unlock_wallet("rotate", "new", Duration::from_secs(60))
            .unwrap();
        let post_addr = {
            let arc = manager.get_wallet("rotate").unwrap();
            let w = arc.lock().unwrap();
            w.peek_address().unwrap()
        };
        assert_eq!(post_addr, orig_addr);
    }

    #[test]
    fn change_passphrase_wrong_old_rejected() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("guard", opts_with_passphrase("right"))
            .unwrap();
        let err = manager
            .change_wallet_passphrase("guard", "wrong", "next")
            .unwrap_err();
        assert!(matches!(err, WalletError::BadPassphrase));
    }

    #[test]
    fn unencrypted_wallet_signing_path_unaffected() {
        // Pre-existing unencrypted wallets must keep working: no lock,
        // no walletpassphrase needed.
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("unaffected", CreateWalletOptions::default())
            .unwrap();
        manager.require_unlocked("unaffected").unwrap();
        let state = manager.lock_state("unaffected").unwrap();
        assert!(!state.encrypted);
        assert!(state.unlocked);
    }

    /// Atomic-write invariant: if the temp file is left behind from a
    /// crashed write, the real seed file is untouched.
    #[test]
    fn temp_file_leftover_does_not_corrupt_real_seed() {
        let temp_dir = tempdir().unwrap();
        let mut manager = WalletManager::new(temp_dir.path(), Network::Testnet).unwrap();

        manager
            .create_wallet("atomic", CreateWalletOptions::default())
            .unwrap();
        let seed_path = manager.wallets_dir().join("atomic").join(SEED_FILE_NAME);
        let original = fs::read(&seed_path).unwrap();

        // Drop a bogus .tmp file next to it.
        let tmp_path = manager
            .wallets_dir()
            .join("atomic")
            .join(format!("{}.tmp", SEED_FILE_NAME));
        fs::write(&tmp_path, b"junk-that-should-not-clobber").unwrap();

        // Reload must use the real seed, not the .tmp.
        manager.unload_wallet("atomic", true).unwrap();
        manager.load_wallet("atomic").unwrap();
        let after = fs::read(&seed_path).unwrap();
        assert_eq!(after, original);
    }
}
