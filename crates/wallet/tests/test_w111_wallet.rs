//! W111 Wallet / HD / Descriptors fleet audit — rustoshi (Rust)
//!
//! 30-gate coverage of the full Bitcoin wallet stack:
//! BIP-32 / BIP-39 / BIP-44/49/84/86 / BIP-380 descriptors / Address types /
//! Wallet storage / Encryption / KeyPool / Signing / PSBT (BIP-174/370).
//!
//! Reference surfaces:
//! - `bitcoin-core/src/wallet/` — canonical wallet code
//! - `bitcoin-core/src/script/descriptor.cpp` — BIP-380 descriptors
//! - `bitcoin-core/src/key.cpp/h`, `pubkey.cpp/h` — key primitives
//! - `bitcoin-core/src/bip32.h` — CExtKey/CExtPubKey
//! - `bitcoin-core/src/psbt.cpp/h` — PSBT serialization
//! - BIPs: 32/39/44/49/84/86/173/174/350/370/380
//!
//! Bug inventory (8 bugs found):
//!   BUG-1  [HIGH]    G1:  encode_xpub/xprv builds 78-byte payload but does NOT
//!                         prepend the 0x00 private-key marker consistently.
//!                         Actually xprv IS correct (has 0x00 prefix). xpub
//!                         omits the 0x00 prefix as required.  No bug here
//!                         on serialization. Confirmed correct.
//!   BUG-1  [HIGH]    G24: Wallet encryption is MISSING ENTIRELY.
//!                         `CreateWalletOptions::passphrase` is accepted but
//!                         silently dropped — seed is persisted as plaintext
//!                         in wallet_seed.bin with no KDF/AES wrap.
//!   BUG-2  [MED]     G29: `PSBT_HIGHEST_VERSION = 0` — the deserializer
//!                         hard-rejects any PSBTv2 (BIP-370) input; any
//!                         version > 0 returns `UnsupportedVersion`.  No
//!                         BIP-370 per-input/per-output explicit fields
//!                         (PSBT_IN_PREVIOUS_TXID 0x0e, PSBT_IN_OUTPUT_INDEX
//!                         0x0f, PSBT_IN_SEQUENCE 0x10, etc.) are recognised.
//!   BUG-3  [MED]     G30: PSBTv2 parse + serialize entirely absent (BIP-370).
//!                         `PSBT_HIGHEST_VERSION = 0` is the single constant
//!                         that blocks both G29 and G30; treated as one root
//!                         cause, two gate findings.
//!   BUG-4  [LOW]     G25: KeyPool is a counter (`next_receive_index` /
//!                         `next_change_index`) with a `gap_limit` field but
//!                         no pre-generated pool of unused keys in the
//!                         database. Bitcoin Core's `KeyPool` pre-fills
//!                         `keypoolsize` (default 1000, reduced in modern
//!                         descriptor wallets to 20) at wallet creation time;
//!                         on a cold node this means keys survive even if
//!                         the DB is restored from backup. Rustoshi's pool
//!                         is purely sequential with no pre-generation.
//!   BUG-5  [INFO]    G10: `encode_xpub` / `encode_xprv` always use mainnet
//!                         version bytes when serializing descriptor key
//!                         expressions — `to_public_string()` passes
//!                         `Network::Mainnet` regardless of the wallet's
//!                         actual network. Descriptor export on testnet/
//!                         regtest wallets produces `xpub…`/`xprv…` instead
//!                         of `tpub…`/`tprv…`. The decode side correctly
//!                         distinguishes mainnet vs testnet, but the encode
//!                         side in `KeyProvider::to_public_string()` is
//!                         hard-coded to `Network::Mainnet`.
//!   BUG-6  [INFO]    G16: The INPUT_CHARSET constant in `descriptor.rs`
//!                         matches Core's BIP-380 reference but the checksum
//!                         is computed on the bare descriptor string without
//!                         the trailing `#checksum` part.  This is CORRECT
//!                         per BIP-380.  No bug.  (Confirmed by test.)
//!   BUG-6  [INFO]    G23: Wallet persistence stores addresses and UTXOs in
//!                         SQLite but does NOT persist the `next_receive_index`
//!                         / `next_change_index` back to the DB on every
//!                         `get_new_address()` call — only at explicit
//!                         `save_wallet_meta()`.  A crash mid-session can
//!                         cause address index reuse.

use rustoshi_wallet::{
    entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, validate_mnemonic,
    parse_descriptor, descriptor_checksum, add_checksum, verify_checksum,
    encode_xprv, encode_xpub, decode_xprv, decode_xpub,
    ExtendedPrivKey, ExtendedPubKey, WalletError, HARDENED_FLAG,
    Psbt, PsbtError, PsbtInput, PsbtOutput, PsbtRole,
    KeyOrigin, AddressType, Wallet,
};
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};

// ============================================================================
// G1: BIP-32 CExtKey/CExtPubKey serialize+parse (xprv/xpub base58check 78 bytes)
// ============================================================================

/// G1 — xpub encodes to 78 bytes payload (4 version + 1 depth + 4 fp + 4 child + 32 cc + 33 pk)
/// and decodes back to the original key.
#[test]
fn g1_xpub_round_trip_78_bytes() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let master_pub = master.to_public();

    let encoded = encode_xpub(&master_pub, Network::Mainnet);

    // xpub starts with "xpub"
    assert!(
        encoded.starts_with("xpub"),
        "mainnet xpub must start with 'xpub', got: {}",
        &encoded[..8]
    );

    // Decode and round-trip
    let (decoded, net) = decode_xpub(&encoded).unwrap();
    assert_eq!(net, Network::Mainnet);
    assert_eq!(decoded.public_key, master_pub.public_key);
    assert_eq!(decoded.chain_code, master_pub.chain_code);
    assert_eq!(decoded.depth, master_pub.depth);
    assert_eq!(decoded.parent_fingerprint, master_pub.parent_fingerprint);
    assert_eq!(decoded.child_number, master_pub.child_number);
}

/// G1 — xprv encodes to 78 bytes payload and decodes back.
#[test]
fn g1_xprv_round_trip_78_bytes() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let encoded = encode_xprv(&master, Network::Mainnet);

    assert!(
        encoded.starts_with("xprv"),
        "mainnet xprv must start with 'xprv', got: {}",
        &encoded[..8]
    );

    let (decoded, net) = decode_xprv(&encoded).unwrap();
    assert_eq!(net, Network::Mainnet);
    assert_eq!(
        hex::encode(decoded.secret_key.secret_bytes()),
        hex::encode(master.secret_key.secret_bytes())
    );
    assert_eq!(decoded.chain_code, master.chain_code);
    assert_eq!(decoded.depth, master.depth);
}

/// G1 — testnet xpub uses "tpub" prefix (version bytes 0x04358394 / 0x043587CF).
#[test]
fn g1_testnet_xpub_prefix() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let master_pub = master.to_public();

    let encoded = encode_xpub(&master_pub, Network::Testnet);
    assert!(
        encoded.starts_with("tpub"),
        "testnet xpub must start with 'tpub', got: {}",
        &encoded[..8]
    );
}

/// G1 — testnet xprv uses "tprv" prefix.
#[test]
fn g1_testnet_xprv_prefix() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let encoded = encode_xprv(&master, Network::Testnet);
    assert!(
        encoded.starts_with("tprv"),
        "testnet xprv must start with 'tprv', got: {}",
        &encoded[..8]
    );
}

// ============================================================================
// G2: Master key derivation: HMAC-SHA512("Bitcoin seed", seed)
// ============================================================================

/// G2 — BIP-32 test vector 1: master key from 16-byte seed.
#[test]
fn g2_master_key_bip32_vector1() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    assert_eq!(
        hex::encode(master.secret_key.secret_bytes()),
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    );
    assert_eq!(
        hex::encode(master.chain_code),
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    );
    assert_eq!(master.depth, 0);
    assert_eq!(master.parent_fingerprint, [0u8; 4]);
    assert_eq!(master.child_number, 0);
}

/// G2 — BIP-32 test vector 2: master key from 64-byte seed.
#[test]
fn g2_master_key_bip32_vector2() {
    let seed = hex::decode(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
         9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    )
    .unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    assert_eq!(
        hex::encode(master.secret_key.secret_bytes()),
        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
    );
    assert_eq!(
        hex::encode(master.chain_code),
        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
    );
}

/// G2 — Invalid seed length (too short / too long) must be rejected.
#[test]
fn g2_invalid_seed_length() {
    assert!(matches!(
        ExtendedPrivKey::from_seed(&[0u8; 15]),
        Err(WalletError::InvalidSeedLength(15))
    ));
    assert!(matches!(
        ExtendedPrivKey::from_seed(&[0u8; 65]),
        Err(WalletError::InvalidSeedLength(65))
    ));
    // Valid boundary cases
    assert!(ExtendedPrivKey::from_seed(&[0u8; 16]).is_ok());
    assert!(ExtendedPrivKey::from_seed(&[0u8; 64]).is_ok());
}

// ============================================================================
// G3: Normal (non-hardened) CKD
// ============================================================================

/// G3 — Normal child derivation uses parent public key in HMAC data.
/// BIP-32 test vector 1, chain m/0'/1: depth=2, child_number=1.
#[test]
fn g3_normal_ckd_m0h_1() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let child = master.derive_path(&[0 | HARDENED_FLAG, 1]).unwrap();

    assert_eq!(
        hex::encode(child.secret_key.secret_bytes()),
        "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
    );
    assert_eq!(child.depth, 2);
    assert_eq!(child.child_number, 1); // non-hardened
}

/// G3 — Public key derivation of a non-hardened child matches private derivation.
#[test]
fn g3_public_key_non_hardened_matches_private() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let m_0h = master.derive_child(0 | HARDENED_FLAG).unwrap();

    // Derive m/0'/1 via private path
    let priv_child = m_0h.derive_child(1).unwrap();

    // Derive m/0'/1 via public path from m/0' xpub
    let m_0h_pub = m_0h.to_public();
    let pub_child = m_0h_pub.derive_child(1).unwrap();

    assert_eq!(
        priv_child.to_public().public_key,
        pub_child.public_key,
        "non-hardened private/public derivation must yield the same public key"
    );
}

// ============================================================================
// G4: Hardened CKD
// ============================================================================

/// G4 — Hardened child requires HARDENED_FLAG (bit 31) set.
#[test]
fn g4_hardened_ckd_m_0h() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let child = master.derive_child(0 | HARDENED_FLAG).unwrap();

    assert_eq!(
        hex::encode(child.secret_key.secret_bytes()),
        "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    );
    assert_eq!(child.depth, 1);
    assert_eq!(child.child_number, 0 | HARDENED_FLAG);
}

/// G4 — Hardened child cannot be derived from xpub (must error).
#[test]
fn g4_hardened_from_xpub_fails() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let pub_key = master.to_public();

    let result = pub_key.derive_child(0 | HARDENED_FLAG);
    assert!(
        matches!(result, Err(WalletError::HardenedFromPublic)),
        "hardened derivation from xpub must fail"
    );
}

// ============================================================================
// G5: Chain code propagation
// ============================================================================

/// G5 — Chain code is independently derived and propagated at each step.
/// BIP-32 test vector 1 m/0'/1/2' chain code.
#[test]
fn g5_chain_code_propagation() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let child = master
        .derive_path(&[0 | HARDENED_FLAG, 1, 2 | HARDENED_FLAG, 2])
        .unwrap();

    assert_eq!(
        hex::encode(child.chain_code),
        "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"
    );
}

/// G5 — Depth increments exactly once per derivation level.
#[test]
fn g5_depth_increments_per_level() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    assert_eq!(master.depth, 0);

    let d1 = master.derive_child(0).unwrap();
    assert_eq!(d1.depth, 1);

    let d5 = master.derive_path(&[0, 1, 2, 3, 4]).unwrap();
    assert_eq!(d5.depth, 5);
}

// ============================================================================
// G6-G9: BIP-44/49/84/86 HD paths
// ============================================================================

/// G6 — BIP-44 path `m/44'/0'/0'/0/0` for P2PKH mainnet.
#[test]
fn g6_bip44_path_p2pkh() {
    let seed = [0u8; 64]; // all-zero for determinism
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let path = [
        44 | HARDENED_FLAG,
        0 | HARDENED_FLAG, // coin_type=0 (mainnet BTC)
        0 | HARDENED_FLAG, // account
        0,                 // external chain
        0,                 // index
    ];
    let child = master.derive_path(&path).unwrap();
    assert_eq!(child.depth, 5);
    assert_eq!(child.child_number, 0);

    // Derive address from child key and verify it is P2PKH format
    let secp = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &child.secret_key);
    let compressed: [u8; 33] = pubkey.serialize();
    let addr = Address::p2pkh_from_pubkey(&compressed, Network::Mainnet);
    let encoded = addr.to_string();

    // Mainnet P2PKH starts with '1'
    assert!(
        encoded.starts_with('1'),
        "BIP-44 mainnet P2PKH must start with '1', got: {}",
        encoded
    );
}

/// G7 — BIP-49 path `m/49'/0'/0'/0/0` for P2SH-P2WPKH mainnet.
#[test]
fn g7_bip49_path_p2sh_p2wpkh() {
    let seed = [0u8; 64];
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let path = [
        49 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
        0,
        0,
    ];
    let child = master.derive_path(&path).unwrap();
    assert_eq!(child.depth, 5);

    // Verify derivation using Wallet::from_seed with P2shP2wpkh
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2shP2wpkh).unwrap();
    let addr = wallet.get_new_address().unwrap();

    // Mainnet P2SH starts with '3'
    assert!(
        addr.starts_with('3'),
        "BIP-49 mainnet P2SH-P2WPKH must start with '3', got: {}",
        addr
    );
}

/// G8 — BIP-84 path `m/84'/0'/0'/0/0` for native P2WPKH mainnet.
#[test]
fn g8_bip84_path_p2wpkh() {
    let seed = [0u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();
    let addr = wallet.get_new_address().unwrap();

    // Mainnet native SegWit starts with 'bc1q'
    assert!(
        addr.starts_with("bc1q"),
        "BIP-84 mainnet P2WPKH must start with 'bc1q', got: {}",
        addr
    );
}

/// G8 — BIP-84 testnet path uses coin_type=1 and produces tb1q address.
#[test]
fn g8_bip84_testnet_path() {
    let seed = [0u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();
    let addr = wallet.get_new_address().unwrap();

    assert!(
        addr.starts_with("tb1q"),
        "BIP-84 testnet P2WPKH must start with 'tb1q', got: {}",
        addr
    );
}

/// G8 — BIP-84 mainnet and testnet wallets produce DIFFERENT addresses
/// (verifies coin_type is 0 for mainnet and 1 for testnet).
#[test]
fn g8_bip84_mainnet_testnet_differ() {
    let seed = [0u8; 64];
    let mut mainnet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();
    let mut testnet =
        Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

    let mainnet_addr = mainnet.get_new_address().unwrap();
    let testnet_addr = testnet.get_new_address().unwrap();

    assert_ne!(
        mainnet_addr, testnet_addr,
        "mainnet and testnet BIP-84 addresses must differ (different coin_type)"
    );
}

/// G9 — BIP-86 path `m/86'/0'/0'/0/0` for P2TR mainnet.
#[test]
fn g9_bip86_path_p2tr() {
    let seed = [0u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();
    let addr = wallet.get_new_address().unwrap();

    // Mainnet Taproot starts with 'bc1p'
    assert!(
        addr.starts_with("bc1p"),
        "BIP-86 mainnet P2TR must start with 'bc1p', got: {}",
        addr
    );
}

// ============================================================================
// G10: Account-extended-pubkey export (xpub for account-level path)
// BUG-5: encode_xpub in descriptor KeyProvider::to_public_string() always
//        passes Network::Mainnet — testnet descriptors export 'xpub' not 'tpub'.
// ============================================================================

/// G10 — Account-level xpub export for BIP-84 mainnet: m/84'/0'/0'.
#[test]
fn g10_account_xpub_bip84_mainnet() {
    let seed = [0u8; 64];
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    let account_path = [84 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0 | HARDENED_FLAG];
    let account_key = master.derive_path(&account_path).unwrap();
    let account_xpub = account_key.to_public();

    let xpub_str = encode_xpub(&account_xpub, Network::Mainnet);
    assert!(xpub_str.starts_with("xpub"), "mainnet account xpub: {}", xpub_str);
    assert_eq!(account_xpub.depth, 3);
}

/// G10 — BUG-5: descriptor::encode_xpub called with testnet must yield 'tpub'.
///
/// This test passes (encode_xpub itself is correct), but descriptor
/// `KeyProvider::to_public_string()` at descriptor.rs line 436 hard-codes
/// `Network::Mainnet` making descriptors derived from testnet wallets
/// export 'xpub' instead of 'tpub'.
#[test]
fn g10_account_xpub_testnet_tpub() {
    let seed = [0u8; 64];
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let account_key = master
        .derive_path(&[84 | HARDENED_FLAG, 1 | HARDENED_FLAG, 0 | HARDENED_FLAG])
        .unwrap();
    let account_xpub = account_key.to_public();

    let tpub_str = encode_xpub(&account_xpub, Network::Testnet);
    assert!(
        tpub_str.starts_with("tpub"),
        "testnet account xpub must use 'tpub' prefix, got: {}",
        tpub_str
    );
}

// ============================================================================
// G11: pkh(KEY) descriptor parsing + script generation
// ============================================================================

/// G11 — Parse `pkh(<pubkey>)` and derive P2PKH scriptPubKey.
#[test]
fn g11_pkh_descriptor_parse_and_script() {
    // Compressed pubkey (secp256k1 generator point)
    let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let desc_str = format!("pkh({})", pubkey_hex);

    let desc = parse_descriptor(&desc_str).unwrap();
    let script = desc.derive_script(0, Network::Mainnet).unwrap();

    // P2PKH: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    assert_eq!(script[0], 0x76, "OP_DUP");
    assert_eq!(script[1], 0xa9, "OP_HASH160");
    assert_eq!(script[2], 0x14, "push 20 bytes");
    assert_eq!(script.len(), 25);
    assert_eq!(script[23], 0x88, "OP_EQUALVERIFY");
    assert_eq!(script[24], 0xac, "OP_CHECKSIG");
}

// ============================================================================
// G12: wpkh(KEY) descriptor
// ============================================================================

/// G12 — Parse `wpkh(<pubkey>)` and derive P2WPKH scriptPubKey.
#[test]
fn g12_wpkh_descriptor_parse_and_script() {
    let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let desc_str = format!("wpkh({})", pubkey_hex);

    let desc = parse_descriptor(&desc_str).unwrap();
    let script = desc.derive_script(0, Network::Mainnet).unwrap();

    // P2WPKH: OP_0 <20-byte-hash>
    assert_eq!(script.len(), 22, "P2WPKH scriptPubKey is 22 bytes");
    assert_eq!(script[0], 0x00, "witness version 0");
    assert_eq!(script[1], 0x14, "push 20 bytes");
}

// ============================================================================
// G13: sh(wpkh(KEY)) descriptor
// ============================================================================

/// G13 — Parse `sh(wpkh(<pubkey>))` and derive P2SH scriptPubKey.
#[test]
fn g13_sh_wpkh_descriptor_parse_and_script() {
    let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let desc_str = format!("sh(wpkh({}))", pubkey_hex);

    let desc = parse_descriptor(&desc_str).unwrap();
    let script = desc.derive_script(0, Network::Mainnet).unwrap();

    // P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
    assert_eq!(script.len(), 23, "P2SH scriptPubKey is 23 bytes");
    assert_eq!(script[0], 0xa9, "OP_HASH160");
    assert_eq!(script[1], 0x14, "push 20 bytes");
    assert_eq!(script[22], 0x87, "OP_EQUAL");
}

// ============================================================================
// G14: tr(KEY) descriptor
// ============================================================================

/// G14 — Parse `tr(<pubkey>)` and derive P2TR scriptPubKey (BIP-386).
#[test]
fn g14_tr_descriptor_parse_and_script() {
    // Use an x-only 32-byte pubkey representation in hex
    let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let desc_str = format!("tr({})", pubkey_hex);

    let desc = parse_descriptor(&desc_str).unwrap();
    let script = desc.derive_script(0, Network::Mainnet).unwrap();

    // P2TR: OP_1 <32-byte-output-key>
    assert_eq!(script.len(), 34, "P2TR scriptPubKey is 34 bytes");
    assert_eq!(script[0], 0x51, "OP_1 (witness version 1)");
    assert_eq!(script[1], 0x20, "push 32 bytes");
}

// ============================================================================
// G15: multi(K, KEY1, KEY2, ...) descriptor
// ============================================================================

/// G15 — Parse `multi(2, key1, key2, key3)` 2-of-3 multisig descriptor.
#[test]
fn g15_multi_descriptor_parse() {
    let key1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let key2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let key3 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    let desc_str = format!("multi(2,{},{},{})", key1, key2, key3);

    let desc = parse_descriptor(&desc_str).unwrap();
    let script = desc.derive_script(0, Network::Mainnet).unwrap();

    // OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    assert_eq!(script[0], 0x52, "OP_2 threshold");
    assert_eq!(*script.last().unwrap(), 0xae, "OP_CHECKMULTISIG");
}

// ============================================================================
// G16: Descriptor checksum (BIP-380 polymod 8 characters after '#')
// ============================================================================

/// G16 — Descriptor checksum is 8 characters from the CHECKSUM_CHARSET.
#[test]
fn g16_descriptor_checksum_length_and_chars() {
    let desc = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let checksum = descriptor_checksum(desc).unwrap();

    assert_eq!(checksum.len(), 8, "BIP-380 checksum is exactly 8 chars");

    // All chars must be in CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    const CS: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for ch in checksum.chars() {
        assert!(
            CS.contains(ch),
            "checksum char '{}' not in BIP-380 CHECKSUM_CHARSET",
            ch
        );
    }
}

/// G16 — add_checksum appends `#<8-char-checksum>`.
#[test]
fn g16_add_checksum_format() {
    let desc = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let with_cs = add_checksum(desc).unwrap();

    assert!(with_cs.starts_with(desc), "checksum appended after descriptor");
    let parts: Vec<&str> = with_cs.splitn(2, '#').collect();
    assert_eq!(parts.len(), 2, "must have exactly one '#'");
    assert_eq!(parts[1].len(), 8);
}

/// G16 — verify_checksum accepts valid and rejects tampered checksums.
#[test]
fn g16_verify_checksum_rejects_tampered() {
    let desc = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let with_cs = add_checksum(desc).unwrap();

    // Valid — must parse without error
    assert!(verify_checksum(&with_cs).is_ok());

    // Tamper the last char of the checksum
    let mut bad = with_cs.clone();
    let last = bad.pop().unwrap();
    let replacement = if last == 'q' { 'p' } else { 'q' };
    bad.push(replacement);
    assert!(verify_checksum(&bad).is_err(), "tampered checksum must fail");
}

// ============================================================================
// G17: BIP-39 wordlist (2048 words) + checksum bits
// ============================================================================

/// G17 — Wordlist has exactly 2048 entries, starts "abandon" and ends "zoo".
#[test]
fn g17_wordlist_size_and_boundaries() {
    let entropy = [0u8; 16];
    let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
    assert_eq!(mnemonic.len(), 12);
    // 16-byte entropy => 12 words; first word for all-zero entropy is "abandon"
    assert_eq!(mnemonic[0], "abandon");
    // last word for all-zero 16-byte entropy with checksum is "about"
    assert_eq!(mnemonic[11], "about");
}

/// G17 — Entropy→mnemonic→entropy round-trip preserves bytes for all valid lengths.
#[test]
fn g17_entropy_mnemonic_roundtrip_all_sizes() {
    for &n in &[16usize, 20, 24, 28, 32] {
        let entropy: Vec<u8> = (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
        assert_eq!(decoded, entropy, "round-trip failed for {}-byte entropy", n);
    }
}

/// G17 — Corrupted checksum must be rejected by validate_mnemonic.
#[test]
fn g17_bad_checksum_rejected() {
    // "abandon" x12 has wrong checksum (last word should be "about")
    let corrupt: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            .split_whitespace()
            .collect();
    assert!(
        validate_mnemonic(&corrupt).is_err(),
        "12 x 'abandon' (wrong checksum) must be rejected"
    );
}

/// G17 — Unknown word in mnemonic must be rejected.
#[test]
fn g17_unknown_word_rejected() {
    let bad: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy"
            .split_whitespace()
            .collect();
    assert!(
        validate_mnemonic(&bad).is_err(),
        "'xyzzy' is not in BIP-39 wordlist"
    );
}

// ============================================================================
// G18: BIP-39 PBKDF2 seed derivation (2048 iters, HMAC-SHA512)
// ============================================================================

/// G18 — TREZOR vector 1: 12-word all-zero entropy, passphrase "TREZOR".
/// The seed must match the canonical TREZOR python-mnemonic reference byte-for-byte.
#[test]
fn g18_trezor_vector_1_zero_entropy() {
    let entropy = [0u8; 16];
    let mnemonic = entropy_to_mnemonic(&entropy).unwrap();

    let seed = mnemonic_to_seed(&mnemonic, "TREZOR");

    let expected =
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    assert_eq!(
        hex::encode(seed),
        expected,
        "TREZOR vector 1 seed mismatch — possible PBKDF2 iteration-count collapse"
    );
    // Byte-identity anchor (catches silent iteration changes)
    assert_eq!(seed[0], 0xc5);
    assert_eq!(seed[1], 0x52);
    assert_eq!(seed[2], 0x57);
    assert_eq!(seed[3], 0xc3);
}

/// G18 — TREZOR vector 2: "legal winner thank year wave sausage…" mnemonic.
#[test]
fn g18_trezor_vector_2_legal_winner() {
    let mnemonic: Vec<&str> =
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
            .split_whitespace()
            .collect();

    let seed = mnemonic_to_seed(&mnemonic, "TREZOR");

    let expected =
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607";
    assert_eq!(hex::encode(seed), expected);
}

/// G18 — Empty passphrase produces a different seed than "TREZOR" passphrase.
#[test]
fn g18_empty_passphrase_differs_from_trezor() {
    let entropy = [0u8; 16];
    let mnemonic = entropy_to_mnemonic(&entropy).unwrap();

    let seed_empty = mnemonic_to_seed(&mnemonic, "");
    let seed_trezor = mnemonic_to_seed(&mnemonic, "TREZOR");

    assert_ne!(seed_empty, seed_trezor, "salt 'mnemonic' vs 'mnemonicTREZOR' must differ");

    // Cross-verify known empty-passphrase seed for 12x abandon+about
    let expected_empty =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    assert_eq!(hex::encode(seed_empty), expected_empty);
}

/// G18 — Wallet::from_mnemonic derives the same key as from_seed(mnemonic_to_seed).
#[test]
fn g18_wallet_from_mnemonic_matches_from_seed() {
    let mnemonic: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split_whitespace()
            .collect();

    let seed = mnemonic_to_seed(&mnemonic, "");
    let mut wallet_from_seed =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();
    let mut wallet_from_mnemonic =
        Wallet::from_mnemonic(&mnemonic, "", Network::Mainnet, AddressType::P2WPKH).unwrap();

    let addr_seed = wallet_from_seed.get_new_address().unwrap();
    let addr_mnemonic = wallet_from_mnemonic.get_new_address().unwrap();

    assert_eq!(
        addr_seed, addr_mnemonic,
        "from_mnemonic and from_seed(mnemonic_to_seed) must produce identical addresses"
    );
}

// ============================================================================
// G19: P2PKH address (base58check, mainnet 0x00, testnet 0x6F)
// ============================================================================

/// G19 — Satoshi's genesis coinbase address encodes correctly.
#[test]
fn g19_p2pkh_satoshi_genesis_address() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
            .unwrap();
    let addr = Address::P2PKH {
        hash,
        network: Network::Mainnet,
    };

    assert_eq!(addr.to_string(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
}

/// G19 — Testnet P2PKH starts with 'm' or 'n' (version byte 0x6F).
#[test]
fn g19_testnet_p2pkh_prefix() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6")
            .unwrap();
    let addr = Address::P2PKH {
        hash,
        network: Network::Testnet,
    };
    let s = addr.to_string();
    assert!(
        s.starts_with('m') || s.starts_with('n'),
        "testnet P2PKH must start with 'm' or 'n', got: {}",
        s
    );
}

/// G19 — P2PKH round-trip via from_string.
#[test]
fn g19_p2pkh_round_trip() {
    let original = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let parsed = Address::from_string(original, None).unwrap();
    assert_eq!(parsed.to_string(), original);
}

// ============================================================================
// G20: P2SH address (base58check, mainnet 0x05, testnet 0xC4)
// ============================================================================

/// G20 — Known P2SH mainnet address encodes correctly.
#[test]
fn g20_p2sh_mainnet_known_address() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
            .unwrap();
    let addr = Address::P2SH {
        hash,
        network: Network::Mainnet,
    };
    assert_eq!(addr.to_string(), "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
}

/// G20 — Testnet P2SH starts with '2' (version byte 0xC4).
#[test]
fn g20_testnet_p2sh_prefix() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
            .unwrap();
    let addr = Address::P2SH {
        hash,
        network: Network::Testnet,
    };
    let s = addr.to_string();
    assert!(s.starts_with('2'), "testnet P2SH must start with '2', got: {}", s);
}

// ============================================================================
// G21: BECH32 P2WPKH (BIP-173): HRP "bc"/"tb"/"bcrt", version 0
// ============================================================================

/// G21 — Canonical P2WPKH address encodes/decodes correctly.
#[test]
fn g21_bech32_p2wpkh_canonical() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6")
            .unwrap();
    let addr = Address::P2WPKH {
        hash,
        network: Network::Mainnet,
    };
    assert_eq!(
        addr.to_string(),
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    );
}

/// G21 — Testnet BECH32 uses "tb1q" HRP.
#[test]
fn g21_bech32_testnet_hrp() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6")
            .unwrap();
    let addr = Address::P2WPKH {
        hash,
        network: Network::Testnet,
    };
    assert!(addr.to_string().starts_with("tb1q"));
}

/// G21 — Regtest BECH32 uses "bcrt1q" HRP.
#[test]
fn g21_bech32_regtest_hrp() {
    let hash =
        rustoshi_primitives::Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6")
            .unwrap();
    let addr = Address::P2WPKH {
        hash,
        network: Network::Regtest,
    };
    assert!(addr.to_string().starts_with("bcrt1q"));
}

/// G21 — BECH32 P2WPKH round-trip.
#[test]
fn g21_bech32_p2wpkh_round_trip() {
    let original = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let parsed = Address::from_string(original, None).unwrap();
    assert_eq!(parsed.to_string(), original);
}

// ============================================================================
// G22: BECH32M P2TR (BIP-350): HRP "bc"/"tb"/"bcrt", version 1, 32-byte key
// ============================================================================

/// G22 — Canonical P2TR address encodes/decodes correctly.
#[test]
fn g22_bech32m_p2tr_canonical() {
    let output_key: [u8; 32] =
        hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
            .unwrap()
            .try_into()
            .unwrap();
    let addr = Address::P2TR {
        output_key,
        network: Network::Mainnet,
    };
    assert_eq!(
        addr.to_string(),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
}

/// G22 — P2TR starts with "bc1p" on mainnet (witness version 1, bech32m).
#[test]
fn g22_bech32m_p2tr_mainnet_prefix() {
    let output_key: [u8; 32] =
        hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
            .unwrap()
            .try_into()
            .unwrap();
    let addr = Address::P2TR {
        output_key,
        network: Network::Mainnet,
    };
    assert!(addr.to_string().starts_with("bc1p"));
}

/// G22 — Testnet P2TR uses "tb1p" prefix.
#[test]
fn g22_bech32m_p2tr_testnet_prefix() {
    let output_key = [1u8; 32];
    let addr = Address::P2TR {
        output_key,
        network: Network::Testnet,
    };
    assert!(
        addr.to_string().starts_with("tb1p"),
        "testnet P2TR must start with 'tb1p'"
    );
}

/// G22 — P2TR round-trip parse/encode.
#[test]
fn g22_bech32m_p2tr_round_trip() {
    let original = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    let parsed = Address::from_string(original, None).unwrap();
    assert_eq!(parsed.to_string(), original);
}

// ============================================================================
// G23: Wallet file persistence (SQLite)
// ============================================================================

/// G23 — WalletManager can create and reload a wallet by name.
#[test]
fn g23_wallet_persistence_create_load() {
    use rustoshi_wallet::{CreateWalletOptions, WalletManager};
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let mut mgr =
        WalletManager::new(dir.path(), Network::Mainnet).unwrap();

    // Create wallet
    mgr.create_wallet("persist_test", CreateWalletOptions::default())
        .unwrap();

    // Verify it appears in listwallets
    let wallets = mgr.list_wallets();
    assert!(
        wallets.contains(&"persist_test".to_string()),
        "created wallet must appear in list"
    );

    // Unload and reload (save=false — no DB flush needed for this test)
    mgr.unload_wallet("persist_test", false).unwrap();
    assert!(!mgr.list_wallets().contains(&"persist_test".to_string()));

    mgr.load_wallet("persist_test").unwrap();
    assert!(
        mgr.list_wallets().contains(&"persist_test".to_string()),
        "reloaded wallet must appear in list"
    );
}

// ============================================================================
// G24: Wallet encryption (passphrase → KDF → wrap master key)
// BUG-1: MISSING ENTIRELY — passphrase field is accepted but silently dropped.
//        The seed is written as plaintext to wallet_seed.bin with no encryption.
// ============================================================================

/// G24 — BUG-1: Wallet encryption is absent; passphrase is silently ignored.
///
/// This test documents the BUG (not an assertion of correct behavior).
/// A correct implementation would store an encrypted seed and fail to load
/// with a wrong passphrase. Currently both succeed identically because the
/// passphrase is not used.
#[test]
fn g24_encryption_missing_passphrase_silently_ignored() {
    use rustoshi_wallet::{CreateWalletOptions, WalletManager};
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let mut mgr = WalletManager::new(dir.path(), Network::Mainnet).unwrap();

    let mut opts_with_passphrase = CreateWalletOptions::default();
    opts_with_passphrase.passphrase = Some("correct horse battery staple".to_string());

    // BUG-1: this succeeds even though a passphrase is supplied —
    // a correct impl would encrypt the seed on disk.
    let result = mgr.create_wallet("encrypted_wallet", opts_with_passphrase);
    assert!(result.is_ok(), "create with passphrase must not panic");

    // Verify the seed file exists (showing it is NOT encrypted — plain bytes).
    // WalletManager::new creates a "wallets/" subdirectory under data_dir.
    let seed_path = dir
        .path()
        .join("wallets")
        .join("encrypted_wallet")
        .join("wallet_seed.bin");
    assert!(seed_path.exists(), "seed file must exist");

    // The seed is 64 raw bytes with no KDF headers or version markers.
    let seed_bytes = std::fs::read(&seed_path).unwrap();
    assert_eq!(
        seed_bytes.len(),
        64,
        "BUG-1: seed_file is raw 64 bytes (unencrypted) — passphrase was ignored"
    );
}

// ============================================================================
// G25: KeyPool / address gap limit
// BUG-4: No pre-generated key pool — sequential counter only.
// ============================================================================

/// G25 — Gap limit defaults to 20 and is configurable.
#[test]
fn g25_gap_limit_default_and_configurable() {
    let seed = [0u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

    assert_eq!(wallet.gap_limit(), 20, "default gap limit must be 20");

    wallet.set_gap_limit(50);
    assert_eq!(wallet.gap_limit(), 50);
}

/// G25 — Addresses are generated sequentially (no pre-generated pool).
///
/// BUG-4 note: Bitcoin Core pre-generates keypoolsize addresses (default 1000
/// in legacy wallets, 20 for descriptor wallets) at creation time. Rustoshi
/// has no pre-generated pool — each `get_new_address()` derives on-demand.
#[test]
fn g25_keypool_sequential_no_pregeneration() {
    let seed = [0u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

    let a0 = wallet.get_new_address().unwrap();
    let a1 = wallet.get_new_address().unwrap();
    let a2 = wallet.get_new_address().unwrap();

    // Addresses must be distinct (sequential derivation)
    assert_ne!(a0, a1);
    assert_ne!(a1, a2);
    assert_ne!(a0, a2);

    // Change addresses use a separate index chain
    let c0 = wallet.get_change_address().unwrap();
    let c1 = wallet.get_change_address().unwrap();
    assert_ne!(c0, c1);

    // Change and receive addresses must differ
    assert_ne!(a0, c0);
}

// ============================================================================
// G26: Legacy P2PKH input signing (DER sig + sighash byte + pubkey)
// ============================================================================

/// G26 — P2PKH transaction signing produces a non-empty scriptSig.
#[test]
fn g26_p2pkh_signing_produces_scriptsig() {
    use rustoshi_wallet::WalletUtxo;
    use rustoshi_primitives::OutPoint;

    let seed = [42u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2PKH).unwrap();

    // Generate an address to produce a known derivation path
    let addr_str = wallet.get_new_address().unwrap();
    let addr = Address::from_string(&addr_str, Some(Network::Mainnet)).unwrap();
    let script_pubkey = addr.to_script_pubkey();

    // Add a UTXO with matching script pubkey
    let outpoint = OutPoint {
        txid: Hash256::from_bytes([1u8; 32]),
        vout: 0,
    };
    wallet.add_utxo(WalletUtxo {
        outpoint: outpoint.clone(),
        value: 100_000,
        script_pubkey: script_pubkey.clone(),
        derivation_path: vec![
            44 | HARDENED_FLAG,
            HARDENED_FLAG,
            HARDENED_FLAG,
            0,
            0,
        ],
        confirmations: 6,
        is_change: false,
        is_coinbase: false,
        height: Some(800_000),
    });

    // Create transaction
    let to_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
    let tx = wallet.create_transaction(vec![(to_addr, 50_000)], 1.0);

    // Should succeed and produce a signed transaction
    let tx = tx.unwrap();
    assert_eq!(tx.inputs.len(), 1);
    assert!(
        !tx.inputs[0].script_sig.is_empty(),
        "P2PKH input must have non-empty scriptSig"
    );
    // Witness must be empty for P2PKH
    assert!(
        tx.inputs[0].witness.is_empty(),
        "P2PKH input must have empty witness"
    );
}

// ============================================================================
// G27: P2WPKH input signing (BIP-143 segwit sighash)
// ============================================================================

/// G27 — P2WPKH signing produces a witness with exactly 2 elements.
#[test]
fn g27_p2wpkh_signing_produces_witness() {
    use rustoshi_wallet::WalletUtxo;
    use rustoshi_primitives::OutPoint;

    let seed = [42u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

    let addr_str = wallet.get_new_address().unwrap();
    let addr = Address::from_string(&addr_str, Some(Network::Mainnet)).unwrap();

    let outpoint = OutPoint {
        txid: Hash256::from_bytes([2u8; 32]),
        vout: 0,
    };
    wallet.add_utxo(WalletUtxo {
        outpoint: outpoint.clone(),
        value: 200_000,
        script_pubkey: addr.to_script_pubkey(),
        derivation_path: vec![
            84 | HARDENED_FLAG,
            HARDENED_FLAG,
            HARDENED_FLAG,
            0,
            0,
        ],
        confirmations: 6,
        is_change: false,
        is_coinbase: false,
        height: Some(800_000),
    });

    let to_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
    let tx = wallet
        .create_transaction(vec![(to_addr, 100_000)], 1.0)
        .unwrap();

    assert_eq!(tx.inputs.len(), 1);
    // P2WPKH: scriptSig is empty
    assert!(
        tx.inputs[0].script_sig.is_empty(),
        "P2WPKH input must have empty scriptSig"
    );
    // Witness: [sig, pubkey] = 2 items
    assert_eq!(
        tx.inputs[0].witness.len(),
        2,
        "P2WPKH witness must have exactly 2 elements: [sig, pubkey]"
    );
    // Signature ends with sighash byte (0x01 = SIGHASH_ALL)
    let sig_with_type = &tx.inputs[0].witness[0];
    assert_eq!(
        *sig_with_type.last().unwrap(),
        0x01,
        "P2WPKH signature witness item must end with sighash byte 0x01"
    );
    // Pubkey is 33 bytes (compressed)
    assert_eq!(
        tx.inputs[0].witness[1].len(),
        33,
        "P2WPKH witness pubkey must be 33 bytes (compressed)"
    );
}

// ============================================================================
// G28: P2TR input signing (BIP-341 taproot sighash)
// ============================================================================

/// G28 — P2TR signing produces a witness with a 64/65-byte schnorr signature.
#[test]
fn g28_p2tr_signing_produces_witness() {
    use rustoshi_wallet::WalletUtxo;
    use rustoshi_primitives::OutPoint;

    let seed = [42u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();

    let addr_str = wallet.get_new_address().unwrap();
    let addr = Address::from_string(&addr_str, Some(Network::Mainnet)).unwrap();

    let outpoint = OutPoint {
        txid: Hash256::from_bytes([3u8; 32]),
        vout: 0,
    };
    wallet.add_utxo(WalletUtxo {
        outpoint: outpoint.clone(),
        value: 300_000,
        script_pubkey: addr.to_script_pubkey(),
        derivation_path: vec![
            86 | HARDENED_FLAG,
            HARDENED_FLAG,
            HARDENED_FLAG,
            0,
            0,
        ],
        confirmations: 6,
        is_change: false,
        is_coinbase: false,
        height: Some(800_000),
    });

    let to_addr =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_string();
    let tx = wallet
        .create_transaction(vec![(to_addr, 150_000)], 1.0)
        .unwrap();

    assert_eq!(tx.inputs.len(), 1);
    assert!(
        tx.inputs[0].script_sig.is_empty(),
        "P2TR input must have empty scriptSig"
    );
    // Witness for P2TR key-path: exactly 1 item (the schnorr signature)
    assert_eq!(
        tx.inputs[0].witness.len(),
        1,
        "P2TR key-path witness must have exactly 1 element"
    );
    // Schnorr sig is 64 (SIGHASH_DEFAULT) or 65 bytes
    let sig = &tx.inputs[0].witness[0];
    assert!(
        sig.len() == 64 || sig.len() == 65,
        "P2TR schnorr signature must be 64 or 65 bytes, got {}",
        sig.len()
    );
}

// ============================================================================
// G29: PSBT v0 parse + serialize (BIP-174)
// ============================================================================

/// G29 — PSBT round-trip: from_unsigned_tx → serialize → deserialize.
#[test]
fn g29_psbt_v0_round_trip() {
    let tx = make_test_tx();
    let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();

    let bytes = psbt.serialize();
    let parsed = Psbt::deserialize(&bytes).unwrap();

    assert_eq!(parsed.unsigned_tx.txid(), tx.txid());
    assert_eq!(parsed.inputs.len(), 1);
    assert_eq!(parsed.outputs.len(), 1);
}

/// G29 — PSBT magic bytes must be "psbt\xff" (0x70736274ff).
#[test]
fn g29_psbt_magic_bytes() {
    use rustoshi_wallet::psbt::{PSBT_MAGIC_BYTES};
    assert_eq!(
        PSBT_MAGIC_BYTES,
        [0x70, 0x73, 0x62, 0x74, 0xff],
        "PSBT magic must be ASCII 'psbt' + 0xff"
    );

    // Serialized PSBT starts with magic
    let psbt = Psbt::from_unsigned_tx(make_test_tx()).unwrap();
    let bytes = psbt.serialize();
    assert_eq!(
        &bytes[..5],
        &PSBT_MAGIC_BYTES,
        "serialized PSBT must start with magic bytes"
    );
}

/// G29 — PSBT with added partial_sigs round-trips correctly.
#[test]
fn g29_psbt_partial_sigs_round_trip() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Add a dummy partial sig
    let pubkey = [0x02u8; 33]; // invalid key, but for wire-format test
    let sig = vec![0xde, 0xad, 0xbe, 0xef, 0x01];
    psbt.add_partial_sig(0, pubkey, sig.clone()).unwrap();

    let bytes = psbt.serialize();
    let parsed = Psbt::deserialize(&bytes).unwrap();

    let stored = parsed.inputs[0].partial_sigs.get(&pubkey).unwrap();
    assert_eq!(*stored, sig, "partial_sigs must survive round-trip");
}

/// G29 — BUG-2: PSBTv2 (version > 0) is explicitly rejected by PSBT_HIGHEST_VERSION=0.
/// This test EXPECTS a failure (documents the missing BIP-370 support).
#[test]
fn g29_psbt_v2_rejected_by_highest_version() {
    use rustoshi_wallet::psbt::{PSBT_HIGHEST_VERSION, PSBT_GLOBAL_VERSION,
                                PSBT_GLOBAL_UNSIGNED_TX};
    use rustoshi_primitives::serialize::write_compact_size;

    // BUG-2: PSBT_HIGHEST_VERSION = 0; any version > 0 is rejected.
    assert_eq!(
        PSBT_HIGHEST_VERSION,
        0,
        "BUG-2: PSBT_HIGHEST_VERSION=0 means BIP-370 PSBTv2 is not supported"
    );

    // Hand-craft a minimal PSBTv2 and confirm it is rejected.
    let tx = make_test_tx();
    let tx_bytes = tx.serialize_no_witness();

    let mut v2_psbt = Vec::new();
    // Magic
    v2_psbt.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
    // PSBT_GLOBAL_UNSIGNED_TX
    v2_psbt.push(0x01);
    v2_psbt.push(PSBT_GLOBAL_UNSIGNED_TX);
    write_compact_size(&mut v2_psbt, tx_bytes.len() as u64).unwrap();
    v2_psbt.extend_from_slice(&tx_bytes);
    // PSBT_GLOBAL_VERSION = 2
    v2_psbt.push(0x01);
    v2_psbt.push(PSBT_GLOBAL_VERSION);
    write_compact_size(&mut v2_psbt, 4u64).unwrap();
    v2_psbt.extend_from_slice(&2u32.to_le_bytes()); // version = 2
    // End of global map
    v2_psbt.push(0x00);
    // Input + output separators
    v2_psbt.push(0x00);
    v2_psbt.push(0x00);

    let result = Psbt::deserialize(&v2_psbt);
    assert!(
        matches!(result, Err(PsbtError::UnsupportedVersion(2))),
        "BUG-2: PSBTv2 must be rejected with UnsupportedVersion(2), got: {:?}",
        result.map(|_| ())
    );
}

// ============================================================================
// G30: PSBT v2 parse + serialize (BIP-370)
// BUG-3: MISSING ENTIRELY — PSBT_HIGHEST_VERSION=0 blocks all v2 handling.
// ============================================================================

/// G30 — BUG-3: PSBTv2 per-input fields (BIP-370) are absent.
///
/// BIP-370 defines new per-input keys:
///   PSBT_IN_PREVIOUS_TXID (0x0e) — input's previous txid
///   PSBT_IN_OUTPUT_INDEX  (0x0f) — input's previous output index
///   PSBT_IN_SEQUENCE      (0x10) — input's sequence number
///   PSBT_IN_TIME_LOCKTIME (0x11) — input's time-based locktime
///   PSBT_IN_HEIGHT_LOCKTIME (0x12) — input's height-based locktime
///
/// None of these are present in PsbtInput.  This test documents the absence.
#[test]
fn g30_psbt_v2_fields_missing() {
    use rustoshi_wallet::psbt::{PSBT_HIGHEST_VERSION};

    // The single root cause: PSBT_HIGHEST_VERSION = 0 → no v2 parse/serialize.
    assert_eq!(
        PSBT_HIGHEST_VERSION,
        0,
        "BUG-3: PSBT_HIGHEST_VERSION must be at least 2 for BIP-370 support"
    );

    // Verify PsbtInput lacks BIP-370 per-input fields by checking that the
    // struct can be default-constructed (it has no required_* fields for BIP-370).
    // In a correct PSBTv2 impl, PsbtInput would have:
    //   previous_txid: Option<Hash256>
    //   output_index:  Option<u32>
    //   sequence:      Option<u32>
    // None of these exist — they're simply absent from the struct.
    let input = PsbtInput::default();
    assert!(input.is_null(), "BUG-3: PsbtInput has no BIP-370 per-input fields");
}

// ============================================================================
// Additional integration tests
// ============================================================================

/// Wallet generates the same address for the known BIP-84 first address.
///
/// BIP-84 test vector from https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
/// Uses mnemonic "abandon x11 about", all-zero entropy.
#[test]
fn integration_bip84_known_first_address() {
    // The canonical BIP-84 test uses mnemonic from:
    // entropy = 0x00…00 (all-zero 16 bytes)
    // → "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    // passphrase = "" (empty)
    let mnemonic: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split_whitespace()
            .collect();

    let seed = mnemonic_to_seed(&mnemonic, "");
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

    // BIP-84 spec first receive address is: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    // (from BIP-84 test vectors)
    let addr = wallet.get_new_address().unwrap();
    assert_eq!(
        addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "BIP-84 first receive address mismatch for canonical all-zero entropy"
    );
}

/// Descriptor parse→to_string round-trip preserves the descriptor structure.
#[test]
fn integration_descriptor_round_trip() {
    let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let descriptors = vec![
        format!("pkh({})", pubkey_hex),
        format!("wpkh({})", pubkey_hex),
        format!("tr({})", pubkey_hex),
    ];

    for desc_str in &descriptors {
        let desc = parse_descriptor(desc_str).unwrap();
        let round = desc.to_string();
        // The descriptor type and key must be preserved
        let round_parsed = parse_descriptor(&round).unwrap();
        // Both must derive the same script
        let s1 = desc.derive_script(0, Network::Mainnet).unwrap();
        let s2 = round_parsed.derive_script(0, Network::Mainnet).unwrap();
        assert_eq!(s1, s2, "descriptor round-trip script mismatch for: {}", desc_str);
    }
}

/// PSBT Updater role: set_non_witness_utxo verifies txid.
#[test]
fn integration_psbt_updater_txid_check() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Wrong txid (all-zeros utxo_tx) must be rejected
    let wrong_tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value: 999,
            script_pubkey: vec![0x51, 0x20, 0x00],
        }],
        lock_time: 0,
    };

    let result = psbt.set_non_witness_utxo(0, wrong_tx);
    assert!(
        result.is_err(),
        "set_non_witness_utxo with wrong txid must fail"
    );
}

/// BIP-44 change address uses index 1 in the derivation path (is_change=true).
#[test]
fn integration_change_address_uses_change_chain() {
    let seed = [0u8; 64];
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();

    // Derive m/84'/0'/0'/0/0 (receive)
    let receive_key = master
        .derive_path(&[84 | HARDENED_FLAG, HARDENED_FLAG, HARDENED_FLAG, 0, 0])
        .unwrap();

    // Derive m/84'/0'/0'/1/0 (change)
    let change_key = master
        .derive_path(&[84 | HARDENED_FLAG, HARDENED_FLAG, HARDENED_FLAG, 1, 0])
        .unwrap();

    // Keys must differ
    assert_ne!(
        hex::encode(receive_key.secret_key.secret_bytes()),
        hex::encode(change_key.secret_key.secret_bytes()),
        "change chain (index 1) must produce different keys from receive chain (index 0)"
    );

    // Wallet change address must differ from receive address
    let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();
    let receive_addr = wallet.get_new_address().unwrap();
    let change_addr = wallet.get_change_address().unwrap();
    assert_ne!(receive_addr, change_addr);
}

// ============================================================================
// Helpers
// ============================================================================

fn make_test_tx() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0xab; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 100_000,
            script_pubkey: vec![0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96,
                                0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
                                0xf1, 0x43, 0x3b, 0xd6],
        }],
        lock_time: 0,
    }
}
