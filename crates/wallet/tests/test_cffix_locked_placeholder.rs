//! A locked encrypted wallet must never hand out, index or sign with keys
//! derived from the all-zero placeholder seed.
//!
//! While an encrypted wallet is locked (after `loadwallet`, or after
//! `walletlock`), `WalletManager` keeps a placeholder `Wallet` in memory
//! because the real seed is only on disk, encrypted. That placeholder is
//! built from `[0u8; 64]`, whose keys anyone can derive. Before this fix the
//! placeholder answered `get_new_address()` with the zero seed's addresses:
//! coins sent there could be spent by anyone, and the real wallet never
//! tracked them.
//!
//! Core's `getnewaddress` (`src/wallet/rpc/addresses.cpp:21`,
//! `GetNewDestination`) derives only from the wallet's own descriptor
//! (cached public keys); it never substitutes other key material. Here every
//! address-minting path either refuses with `WalletLocked` (RPC -13) or
//! returns the real seed's address at that index. It must never return a
//! zero-seed address.

use rustoshi_crypto::address::{Address, Network};
use rustoshi_wallet::{AddressType, CreateWalletOptions, Wallet, WalletError, WalletManager};

const NET: Network = Network::Regtest;
const LOOKAHEAD: u32 = 25;

fn encrypted() -> CreateWalletOptions {
    CreateWalletOptions {
        passphrase: Some("pw".to_string()),
        ..Default::default()
    }
}

/// Addresses the public all-zero seed derives for `addr_type`, receive and
/// change branches, indices `0..LOOKAHEAD`.
fn zero_seed_addresses(addr_type: AddressType) -> Vec<String> {
    let mut z = Wallet::from_seed(&[0u8; 64], NET, AddressType::P2WPKH).unwrap();
    let mut out = Vec::new();
    for _ in 0..LOOKAHEAD {
        out.push(z.get_new_address_of_type(addr_type).unwrap());
    }
    let mut z = Wallet::from_seed(&[0u8; 64], NET, addr_type).unwrap();
    for _ in 0..LOOKAHEAD {
        out.push(z.get_change_address().unwrap());
    }
    out
}

/// The real wallet's receive (`false`) or change (`true`) address at `i`,
/// read while it is still unlocked.
fn real_addresses(m: &WalletManager, name: &str, change: bool) -> Vec<String> {
    let arc = m.get_wallet(name).unwrap();
    let mut w = arc.lock().unwrap();
    (0..LOOKAHEAD).map(|i| w.get_address_at(change, i).unwrap()).collect()
}

/// Whatever a locked wallet returns for a fresh address must be `WalletLocked`
/// or the real seed's address; a zero-seed address fails.
fn assert_safe(what: &str, got: Result<String, WalletError>, real: &[String], zero: &[String]) {
    match got {
        Err(WalletError::WalletLocked) => {}
        Ok(a) => {
            assert!(
                !zero.contains(&a),
                "{what}: locked wallet minted {a}, an address of the PUBLIC all-zero seed"
            );
            assert!(
                real.contains(&a),
                "{what}: locked wallet minted {a}, which the real seed does not derive"
            );
        }
        Err(e) => panic!("{what}: expected WalletLocked or a real address, got {e:?}"),
    }
}

fn check_locked(m: &WalletManager, name: &str, real_recv: &[String], real_change: &[String]) {
    let zero = zero_seed_addresses(AddressType::P2WPKH);
    let arc = m.get_wallet(name).unwrap();
    let mut w = arc.lock().unwrap();

    for i in 0..3 {
        assert_safe(&format!("get_new_address #{i}"), w.get_new_address(), real_recv, &zero);
    }
    assert_safe("get_change_address", w.get_change_address(), real_change, &zero);
    assert_safe("peek_address", w.peek_address(), real_recv, &zero);
    assert_safe("get_address_at(recv, 0)", w.get_address_at(false, 0), real_recv, &zero);
    assert_safe("get_address_at(change, 0)", w.get_address_at(true, 0), real_change, &zero);

    for t in [AddressType::P2PKH, AddressType::P2shP2wpkh, AddressType::P2TR] {
        let zero_t = zero_seed_addresses(t);
        match w.get_new_address_of_type(t) {
            Err(WalletError::WalletLocked) => {}
            Ok(a) => assert!(!zero_t.contains(&a), "get_new_address_of_type({t:?}) minted zero-seed {a}"),
            Err(e) => panic!("get_new_address_of_type({t:?}): unexpected {e:?}"),
        }
    }
}

#[test]
fn locked_wallet_never_mints_zero_seed_address() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = WalletManager::new(dir.path(), NET).unwrap();
    m.create_wallet("enc", encrypted()).unwrap();
    let real_recv = real_addresses(&m, "enc", false);
    let real_change = real_addresses(&m, "enc", true);

    m.unload_wallet("enc", true).unwrap();
    m.load_wallet("enc").unwrap();
    assert!(matches!(m.require_unlocked("enc"), Err(WalletError::WalletLocked)));

    check_locked(&m, "enc", &real_recv, &real_change);
}

#[test]
fn walletlock_never_mints_zero_seed_address() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = WalletManager::new(dir.path(), NET).unwrap();
    m.create_wallet("enc", encrypted()).unwrap();
    let real_recv = real_addresses(&m, "enc", false);
    let real_change = real_addresses(&m, "enc", true);

    m.lock_wallet("enc").unwrap();
    assert!(matches!(m.require_unlocked("enc"), Err(WalletError::WalletLocked)));

    check_locked(&m, "enc", &real_recv, &real_change);
}

/// A block paying a zero-seed address must not be credited to a locked
/// wallet: the placeholder's HD lookahead must not claim the public seed's
/// scripts as the wallet's own.
#[test]
fn locked_wallet_does_not_claim_zero_seed_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = WalletManager::new(dir.path(), NET).unwrap();
    m.create_wallet("enc", encrypted()).unwrap();
    m.unload_wallet("enc", true).unwrap();
    m.load_wallet("enc").unwrap();

    let arc = m.get_wallet("enc").unwrap();
    let w = arc.lock().unwrap();
    for a in zero_seed_addresses(AddressType::P2WPKH) {
        let spk = Address::from_string(&a, Some(NET)).unwrap().to_script_pubkey();
        assert!(!w.is_mine_script(&spk), "locked wallet claims zero-seed script of {a}");
    }
}

/// Control: after `walletpassphrase` the wallet derives its real addresses
/// again, starting where it left off, so the refusal is tied to the lock and
/// not to encryption.
#[test]
fn unlocked_wallet_mints_real_addresses_again() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = WalletManager::new(dir.path(), NET).unwrap();
    m.create_wallet("enc", encrypted()).unwrap();
    let real_recv = real_addresses(&m, "enc", false);
    m.unload_wallet("enc", true).unwrap();
    m.load_wallet("enc").unwrap();
    {
        let arc = m.get_wallet("enc").unwrap();
        let mut w = arc.lock().unwrap();
        let _ = w.get_new_address();
    }
    m.unlock_wallet("enc", "pw", std::time::Duration::from_secs(60)).unwrap();
    let arc = m.get_wallet("enc").unwrap();
    let mut w = arc.lock().unwrap();
    let a = w.get_new_address().unwrap();
    assert_eq!(a, real_recv[0], "unlocked wallet must hand out the real seed's index-0 address");
    let spk = Address::from_string(&a, Some(NET)).unwrap().to_script_pubkey();
    assert!(w.is_mine_script(&spk));
}

/// Control: the oracle is the instrument the tests claim. The zero-seed list
/// really is what `Wallet::from_seed(&[0; 64])` mints, and an unencrypted
/// wallet's real addresses are not in it.
#[test]
fn control_zero_seed_oracle_is_real() {
    let mut z = Wallet::from_seed(&[0u8; 64], NET, AddressType::P2WPKH).unwrap();
    let zero = zero_seed_addresses(AddressType::P2WPKH);
    assert_eq!(zero[0], z.get_new_address().unwrap());
    assert_eq!(zero.len() as u32, 2 * LOOKAHEAD);

    let dir = tempfile::tempdir().unwrap();
    let mut m = WalletManager::new(dir.path(), NET).unwrap();
    m.create_wallet("plain", CreateWalletOptions::default()).unwrap();
    let real = real_addresses(&m, "plain", false);
    assert!(real.iter().all(|a| !zero.contains(a)));
}
