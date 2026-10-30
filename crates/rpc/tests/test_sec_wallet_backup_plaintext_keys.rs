//! Security audit `audits/security/rustoshi-2026-10-28.md`, findings H5 and H6.
//!
//! H5: `backupwallet <dest>` used to `remove_dir_all` / `remove_file` whatever
//! already sat at `<dest>` before copying the wallet there, so a typo (or
//! `backupwallet ~`) wiped unrelated data. Core's `SQLiteDatabase::Backup`
//! opens `<dest>` as an SQLite database and fails on a directory or a
//! non-wallet file; it never deletes anything. rustoshi must refuse such a
//! destination with -4 and leave it untouched, while still letting a later
//! backup overwrite an earlier rustoshi backup at the same path (which Core's
//! file backup also allows).
//!
//! H6: `importdescriptors wpkh(<WIF>)` persisted the descriptor exactly as
//! given, so the raw private key sat in `wallet.sqlite` (world-readable under
//! umask 002) and stayed there after `encryptwallet`. The descriptor table
//! must hold only the public form, and `wallet.sqlite` must be 0600.
//!
//! Every test runs on a fresh temp datadir with the RPC handlers in-process;
//! no node and no network are involved.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustoshi_crypto::address::Network;
use rustoshi_rpc::{ImportDescriptorRequest, WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{descriptor_checksum, encode_xprv, ExtendedPrivKey, WalletManager};
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::RwLock;

/// RPC_WALLET_ERROR (Core rpc/protocol.h).
const RPC_WALLET_ERROR: i32 = -4;

/// Regtest WIF used by the audit's repro (compressed, testnet/regtest prefix).
const WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

struct Fixture {
    _dir: TempDir,
    datadir: PathBuf,
    rpc: WalletRpcImpl,
}

impl Fixture {
    async fn new(wallet: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let datadir = dir.path().to_path_buf();
        let manager = WalletManager::new(&datadir, Network::Regtest).expect("manager");
        let state = Arc::new(RwLock::new(WalletRpcState::new(manager, datadir.clone())));
        let rpc = WalletRpcImpl::with_target_wallet(state, wallet.to_string());
        rpc.create_wallet(Some(wallet.to_string()), None, None, None, None, None, None)
            .await
            .expect("createwallet");
        Fixture {
            _dir: dir,
            datadir,
            rpc,
        }
    }

    fn wallet_dir(&self, wallet: &str) -> PathBuf {
        self.datadir.join("wallets").join(wallet)
    }

    async fn import(&self, desc: &str) {
        let body = desc.split('#').next().unwrap();
        let desc = format!("{}#{}", body, descriptor_checksum(body).unwrap());
        let res = self
            .rpc
            .import_descriptors(vec![ImportDescriptorRequest {
                desc,
                active: false,
                range: None,
                timestamp: json!("now"),
                internal: false,
                label: None,
            }])
            .await
            .expect("importdescriptors");
        assert!(res[0].success, "import failed: {:?}", res[0].error);
    }
}

/// Every byte of every regular file under `dir`, recursively.
fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.is_dir() {
            out.extend(all_bytes(&p));
        } else {
            out.extend(fs::read(&p).unwrap());
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------- H5

#[tokio::test]
async fn backupwallet_refuses_existing_directory_and_keeps_its_files() {
    let fx = Fixture::new("w").await;
    let dest = fx.datadir.join("precious");
    fs::create_dir_all(dest.join("sub")).unwrap();
    fs::write(dest.join("precious.txt"), b"do not delete").unwrap();
    fs::write(dest.join("sub").join("nested.txt"), b"nested").unwrap();

    let err = fx
        .rpc
        .backup_wallet(dest.to_string_lossy().into_owned())
        .await
        .expect_err("backupwallet into a non-backup directory must fail");
    assert_eq!(err.code(), RPC_WALLET_ERROR, "{err:?}");

    assert_eq!(
        fs::read(dest.join("precious.txt")).unwrap(),
        b"do not delete"
    );
    assert_eq!(
        fs::read(dest.join("sub").join("nested.txt")).unwrap(),
        b"nested"
    );
    assert!(
        !dest.join("wallet.sqlite").exists(),
        "nothing may be written into it"
    );
}

#[tokio::test]
async fn backupwallet_refuses_existing_plain_file_and_keeps_it() {
    let fx = Fixture::new("w").await;
    let dest = fx.datadir.join("notes.txt");
    fs::write(&dest, b"my notes").unwrap();

    let err = fx
        .rpc
        .backup_wallet(dest.to_string_lossy().into_owned())
        .await
        .expect_err("backupwallet onto a non-wallet file must fail");
    assert_eq!(err.code(), RPC_WALLET_ERROR, "{err:?}");
    assert!(
        dest.is_file(),
        "the file must not be replaced by a directory"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"my notes");
}

#[tokio::test]
async fn backupwallet_refuses_the_datadir_itself() {
    let fx = Fixture::new("w").await;
    let marker = fx.datadir.join("blocks-marker");
    fs::write(&marker, b"chain").unwrap();

    let err = fx
        .rpc
        .backup_wallet(fx.datadir.to_string_lossy().into_owned())
        .await
        .expect_err("backupwallet <datadir> must fail");
    assert_eq!(err.code(), RPC_WALLET_ERROR, "{err:?}");
    assert_eq!(fs::read(&marker).unwrap(), b"chain");
    assert!(fx.wallet_dir("w").join("wallet.sqlite").exists());
}

/// Control: re-backing up to the same path must keep working (Core overwrites
/// an earlier backup file), and the backup must restore.
#[tokio::test]
async fn backupwallet_overwrites_an_earlier_backup_and_restores() {
    let fx = Fixture::new("w").await;
    let dest = fx.datadir.join("w.bak");
    let d = dest.to_string_lossy().into_owned();
    fx.rpc.backup_wallet(d.clone()).await.expect("first backup");
    fx.rpc
        .backup_wallet(d.clone())
        .await
        .expect("second backup over the first");
    assert!(dest.join("wallet.sqlite").is_file());
    assert!(dest.join("wallet_seed.bin").is_file());

    let res = fx
        .rpc
        .restore_wallet("w2".into(), d, None)
        .await
        .expect("restorewallet from the overwritten backup");
    assert_eq!(res.name, "w2");
}

// ---------------------------------------------------------------- H6

#[tokio::test]
async fn importdescriptors_wif_is_not_stored_in_wallet_db_even_after_encryptwallet() {
    let fx = Fixture::new("w").await;
    fx.import(&format!("wpkh({WIF})")).await;

    let wdir = fx.wallet_dir("w");
    assert!(
        !contains(&all_bytes(&wdir), WIF),
        "the imported WIF is stored in plaintext under {}",
        wdir.display()
    );

    fx.rpc
        .encrypt_wallet("hunter2".into())
        .await
        .expect("encryptwallet");
    assert!(
        !contains(&all_bytes(&wdir), WIF),
        "the imported WIF is still on disk in plaintext after encryptwallet"
    );

    // The watch set must still survive a reload from the public form.
    let listed = fx
        .rpc
        .list_descriptors(None)
        .await
        .expect("listdescriptors");
    let desc = listed["descriptors"][0]["desc"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        desc.starts_with("wpkh(0"),
        "public form expected, got {desc}"
    );
    fx.rpc
        .unload_wallet(Some("w".into()), None)
        .await
        .expect("unloadwallet");
    fx.rpc
        .load_wallet("w".into(), None)
        .await
        .expect("loadwallet");
    let listed = fx
        .rpc
        .list_descriptors(None)
        .await
        .expect("listdescriptors");
    assert_eq!(listed["descriptors"][0]["desc"].as_str().unwrap(), desc);
}

#[tokio::test]
async fn importdescriptors_xprv_is_not_stored_in_wallet_db() {
    let fx = Fixture::new("w").await;
    let master = ExtendedPrivKey::from_seed(&[7u8; 32]).unwrap();
    let xprv = encode_xprv(&master, Network::Testnet);
    fx.import(&format!("wpkh({xprv}/0/5)")).await;

    let wdir = fx.wallet_dir("w");
    assert!(
        !contains(&all_bytes(&wdir), &xprv),
        "the imported xprv is stored in plaintext under {}",
        wdir.display()
    );
}

#[tokio::test]
async fn wallet_files_and_backups_are_owner_only() {
    let fx = Fixture::new("w").await;
    let wdir = fx.wallet_dir("w");
    assert_eq!(
        mode(&wdir.join("wallet.sqlite")),
        0o600,
        "wallet.sqlite mode"
    );
    assert_eq!(mode(&wdir), 0o700, "wallet directory mode");

    let dest = fx.datadir.join("w.bak");
    fx.rpc
        .backup_wallet(dest.to_string_lossy().into_owned())
        .await
        .expect("backup");
    assert_eq!(mode(&dest), 0o700, "backup directory mode");
    assert_eq!(
        mode(&dest.join("wallet.sqlite")),
        0o600,
        "backup wallet.sqlite mode"
    );
    assert_eq!(
        mode(&dest.join("wallet_seed.bin")),
        0o600,
        "backup seed mode"
    );
}
