//! cffix-rustoshi-sethdseed-encrypted-wallet
//!
//! `WalletManager::set_hd_seed` (the engine behind the `sethdseed` RPC) used
//! to ignore wallet encryption entirely: it wrote the new seed with
//! `persist_seed(.., None)` — i.e. as 64 PLAINTEXT bytes over the encrypted
//! `wallet_seed.bin` — then reset the lock state to "unencrypted". A locked,
//! encrypted wallet therefore lost both its encryption and its old seed to a
//! single RPC call that needed no passphrase.
//!
//! Core reference: the legacy `sethdseed` (Core v28.0,
//! `src/wallet/rpc/wallet.cpp`) called `EnsureWalletIsUnlocked` first, then
//! stored the new HD seed encrypted under the wallet's master key and kept
//! the old keys in the keystore. (The RPC was removed with legacy wallets and
//! is not in Core v31.1; descriptor wallets have no seed-replacing RPC.)
//!
//! These tests pin that contract for rustoshi:
//! - locked + encrypted → refuse, seed file byte-identical;
//! - unlocked + encrypted → new seed persisted ENCRYPTED under the same
//!   passphrase, wallet stays encrypted;
//! - the previous seed file is never destroyed (archived verbatim).

use rustoshi_crypto::address::Network;
use rustoshi_wallet::{
    decrypt_seed, parse_seed_file, AddressType, CreateWalletOptions, ParsedSeedFile, Wallet,
    WalletError, WalletManager, ENCRYPTED_FILE_LEN,
};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

const PASS: &str = "correct horse battery staple";
const NEW_SEED: [u8; 64] = [0x42; 64];

fn seed_path(root: &Path, name: &str) -> PathBuf {
    root.join("wallets").join(name).join("wallet_seed.bin")
}

/// Archived copies of earlier seed files left next to `wallet_seed.bin`.
fn archived_seed_files(root: &Path, name: &str) -> Vec<Vec<u8>> {
    let dir = root.join("wallets").join(name);
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let fname = e.file_name().to_string_lossy().to_string();
            if fname.starts_with("wallet_seed.bin.replaced-") {
                Some((fname, std::fs::read(e.path()).unwrap()))
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.into_iter().map(|(_, b)| b).collect()
}

fn encrypted_wallet(dir: &TempDir, name: &str) -> WalletManager {
    let mut mgr = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    mgr.create_wallet(
        name,
        CreateWalletOptions {
            passphrase: Some(PASS.to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    mgr
}

fn peek(mgr: &WalletManager, name: &str) -> String {
    mgr.get_wallet(name)
        .unwrap()
        .lock()
        .unwrap()
        .peek_address()
        .unwrap()
}

fn expected_first_address(seed: &[u8; 64]) -> String {
    Wallet::from_seed(seed, Network::Regtest, AddressType::P2WPKH)
        .unwrap()
        .peek_address()
        .unwrap()
}

/// The item's named fail-on-master test.
#[test]
fn sethdseed_refuses_locked_encrypted_wallet() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    mgr.lock_wallet("w").unwrap();

    let before = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    assert_eq!(before.len(), ENCRYPTED_FILE_LEN);

    let res = mgr.set_hd_seed("w", &NEW_SEED);
    assert!(
        matches!(res, Err(WalletError::WalletLocked)),
        "set_hd_seed on a locked encrypted wallet must refuse with WalletLocked, got {:?}",
        res
    );

    let after = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    assert_eq!(
        before, after,
        "wallet_seed.bin must be byte-identical after a refused set_hd_seed"
    );
    let ls = mgr.lock_state("w").unwrap();
    assert!(
        ls.encrypted && !ls.unlocked,
        "wallet must stay encrypted + locked"
    );
    assert!(
        archived_seed_files(dir.path(), "w").is_empty(),
        "a refused call must not touch the wallet dir"
    );
}

/// Auto-relock (walletpassphrase timeout elapsed) counts as locked.
#[test]
fn sethdseed_refuses_after_unlock_timeout_expires() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    mgr.lock_wallet("w").unwrap();
    mgr.unlock_wallet("w", PASS, Duration::from_secs(0))
        .unwrap();

    let before = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    let res = mgr.set_hd_seed("w", &NEW_SEED);
    assert!(
        matches!(res, Err(WalletError::WalletLocked)),
        "got {:?}",
        res
    );
    assert_eq!(before, std::fs::read(seed_path(dir.path(), "w")).unwrap());
}

/// Unlocked via walletpassphrase: the new seed is written ENCRYPTED under the
/// same passphrase, the wallet stays encrypted, and a lock/unlock round trip
/// with the original passphrase recovers the NEW seed's keys.
#[test]
fn sethdseed_unlocked_encrypted_wallet_persists_encrypted() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    mgr.lock_wallet("w").unwrap();
    mgr.unlock_wallet("w", PASS, Duration::from_secs(600))
        .unwrap();

    mgr.set_hd_seed("w", &NEW_SEED).unwrap();

    let bytes = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    assert_eq!(
        bytes.len(),
        ENCRYPTED_FILE_LEN,
        "seed must stay in the encrypted layout, not 64 plaintext bytes"
    );
    assert_eq!(&bytes[..16], b"RUSTOSHI_WALLET\0");
    assert!(
        !bytes.windows(64).any(|w| w == NEW_SEED),
        "plaintext new seed must not appear in the seed file"
    );
    let ls = mgr.lock_state("w").unwrap();
    assert!(
        ls.encrypted && ls.unlocked,
        "wallet stays encrypted (and unlocked)"
    );

    let want = expected_first_address(&NEW_SEED);
    assert_eq!(peek(&mgr, "w"), want, "in-memory wallet runs the new seed");

    mgr.lock_wallet("w").unwrap();
    assert!(matches!(
        mgr.set_hd_seed("w", &[7u8; 64]),
        Err(WalletError::WalletLocked)
    ));
    mgr.unlock_wallet("w", PASS, Duration::from_secs(600))
        .unwrap();
    assert_eq!(
        peek(&mgr, "w"),
        want,
        "original passphrase must decrypt the NEW seed after a relock"
    );
}

/// Unloaded and re-loaded from disk: still encrypted, still locked, and the
/// original passphrase unlocks the new seed.
#[test]
fn sethdseed_encrypted_survives_reload() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    // Freshly-created encrypted wallets are unlocked for the session.
    mgr.set_hd_seed("w", &NEW_SEED).unwrap();
    mgr.unload_wallet("w", true).unwrap();

    let mut mgr = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    mgr.load_wallet("w").unwrap();
    let ls = mgr.lock_state("w").unwrap();
    assert!(
        ls.encrypted && !ls.unlocked,
        "reloaded wallet must be encrypted + locked"
    );
    assert!(matches!(
        mgr.set_hd_seed("w", &[7u8; 64]),
        Err(WalletError::WalletLocked)
    ));
    mgr.unlock_wallet("w", PASS, Duration::from_secs(600))
        .unwrap();
    assert_eq!(peek(&mgr, "w"), expected_first_address(&NEW_SEED));
}

/// encryptwallet leaves the wallet unlocked for the session; sethdseed then
/// must encrypt under the passphrase encryptwallet just set.
#[test]
fn sethdseed_after_encryptwallet_uses_that_passphrase() {
    let dir = TempDir::new().unwrap();
    let mut mgr = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    mgr.create_wallet("w", CreateWalletOptions::default())
        .unwrap();
    mgr.encrypt_wallet("w", PASS).unwrap();

    mgr.set_hd_seed("w", &NEW_SEED).unwrap();
    assert_eq!(
        std::fs::read(seed_path(dir.path(), "w")).unwrap().len(),
        ENCRYPTED_FILE_LEN
    );
    mgr.lock_wallet("w").unwrap();
    mgr.unlock_wallet("w", PASS, Duration::from_secs(600))
        .unwrap();
    assert_eq!(peek(&mgr, "w"), expected_first_address(&NEW_SEED));
}

/// walletpassphrasechange while unlocked, then sethdseed: the new seed must be
/// encrypted under the NEW passphrase (a stale session key would lock the
/// operator out of their own wallet).
#[test]
fn sethdseed_after_passphrase_change_uses_new_passphrase() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    mgr.lock_wallet("w").unwrap();
    mgr.unlock_wallet("w", PASS, Duration::from_secs(600))
        .unwrap();
    mgr.change_wallet_passphrase("w", PASS, "second passphrase")
        .unwrap();

    mgr.set_hd_seed("w", &NEW_SEED).unwrap();
    mgr.lock_wallet("w").unwrap();
    assert!(
        mgr.unlock_wallet("w", PASS, Duration::from_secs(600))
            .is_err(),
        "old passphrase must no longer unlock"
    );
    mgr.unlock_wallet("w", "second passphrase", Duration::from_secs(600))
        .unwrap();
    assert_eq!(peek(&mgr, "w"), expected_first_address(&NEW_SEED));
}

/// The previous seed is never silently destroyed: the old wallet_seed.bin is
/// archived byte-for-byte (still encrypted) before the new one replaces it.
#[test]
fn sethdseed_keeps_old_seed_file() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    let old = std::fs::read(seed_path(dir.path(), "w")).unwrap();

    mgr.set_hd_seed("w", &NEW_SEED).unwrap();
    let archived = archived_seed_files(dir.path(), "w");
    assert_eq!(
        archived,
        vec![old.clone()],
        "old encrypted seed archived verbatim"
    );

    // A second replacement archives the first replacement too, without
    // overwriting the earlier archive.
    let mid = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    mgr.set_hd_seed("w", &[0x24; 64]).unwrap();
    let archived = archived_seed_files(dir.path(), "w");
    assert_eq!(archived.len(), 2);
    assert!(archived.contains(&old) && archived.contains(&mid));
}

/// Unencrypted wallets keep the plaintext restore behaviour (no regression),
/// and their old seed is archived too.
#[test]
fn sethdseed_unencrypted_wallet_still_plaintext() {
    let dir = TempDir::new().unwrap();
    let mut mgr = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    mgr.create_wallet("w", CreateWalletOptions::default())
        .unwrap();
    let old = std::fs::read(seed_path(dir.path(), "w")).unwrap();

    mgr.set_hd_seed("w", &NEW_SEED).unwrap();
    assert_eq!(
        std::fs::read(seed_path(dir.path(), "w")).unwrap(),
        NEW_SEED.to_vec()
    );
    let ls = mgr.lock_state("w").unwrap();
    assert!(!ls.encrypted && ls.unlocked);
    assert_eq!(peek(&mgr, "w"), expected_first_address(&NEW_SEED));
    assert_eq!(archived_seed_files(dir.path(), "w"), vec![old]);
}

/// Open an archived (or live) seed file with `passphrase`.
fn open_seed_file(bytes: &[u8], passphrase: &str) -> Option<[u8; 64]> {
    match parse_seed_file(bytes).unwrap() {
        ParsedSeedFile::PlaintextV1(_) => None,
        ParsedSeedFile::EncryptedV2(f) => decrypt_seed(&f, passphrase).ok(),
    }
}

/// The archive files must not break re-running backupwallet to the same
/// destination (an earlier backup is recognised by its file names).
#[test]
fn sethdseed_archive_does_not_break_repeat_backup() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    mgr.set_hd_seed("w", &NEW_SEED).unwrap();

    let dest = dir.path().join("w.bak");
    let d = dest.to_string_lossy().into_owned();
    mgr.backup_wallet("w", &d).expect("first backup");
    mgr.backup_wallet("w", &d)
        .expect("second backup over the first");
    let n = std::fs::read_dir(&dest)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("wallet_seed.bin.replaced-")
        })
        .count();
    assert_eq!(n, 1, "the archived seed is part of the backup");
}

/// An unencrypted wallet's archived seed is plaintext; encryptwallet must
/// encrypt it too, or the old seed stays readable at rest after the RPC says
/// the wallet is encrypted.
#[test]
fn encryptwallet_after_sethdseed_encrypts_archived_seed() {
    let dir = TempDir::new().unwrap();
    let mut mgr = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    mgr.create_wallet("w", CreateWalletOptions::default())
        .unwrap();
    let old = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    assert_eq!(old.len(), 64);
    mgr.set_hd_seed("w", &NEW_SEED).unwrap();

    mgr.encrypt_wallet("w", PASS).unwrap();
    let archived = archived_seed_files(dir.path(), "w");
    assert_eq!(archived.len(), 1);
    assert_eq!(
        archived[0].len(),
        ENCRYPTED_FILE_LEN,
        "archived seed must be encrypted by encryptwallet"
    );
    assert!(!archived[0].windows(64).any(|w| w == &old[..]));
    assert_eq!(
        open_seed_file(&archived[0], PASS).map(|s| s.to_vec()),
        Some(old),
        "the wallet passphrase opens the archived old seed"
    );
}

/// walletpassphrasechange must re-wrap archived seeds: afterwards the old
/// passphrase opens nothing, the new one opens the archive.
#[test]
fn passphrase_change_rewraps_archived_seeds() {
    let dir = TempDir::new().unwrap();
    let mut mgr = encrypted_wallet(&dir, "w");
    let old_live = std::fs::read(seed_path(dir.path(), "w")).unwrap();
    let old_seed = open_seed_file(&old_live, PASS).unwrap();
    mgr.set_hd_seed("w", &NEW_SEED).unwrap();

    mgr.change_wallet_passphrase("w", PASS, "second passphrase")
        .unwrap();
    let archived = archived_seed_files(dir.path(), "w");
    assert_eq!(archived.len(), 1);
    assert_eq!(
        open_seed_file(&archived[0], PASS),
        None,
        "old passphrase opens nothing"
    );
    assert_eq!(
        open_seed_file(&archived[0], "second passphrase"),
        Some(old_seed)
    );
}
