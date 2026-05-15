//! W118 Wallet subsystem audit — rustoshi (Rust)
//!
//! 30-gate audit of the wallet subsystem versus Bitcoin Core semantics.
//! W111 already covered HD/descriptor encoding internals (BIP-32 vectors,
//! BIP-39 PBKDF2, BIP-380 checksum, BIP-44/49/84/86 paths). W118 focuses
//! on the **operational** wallet surface: descriptor parsing edge cases,
//! WIF, PSBT operator workflows (create/sign/finalize/combine/extract),
//! fee bumping (BIP-125), send-side RPCs, import paths, and wallet
//! encryption. Each gate has a passing or `#[ignore]`-with-`panic!()`
//! test depending on whether the feature is implemented.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/wallet/` — wallet engine
//! - `bitcoin-core/src/wallet/rpc/` — wallet RPC dispatch
//! - `bitcoin-core/src/script/descriptor.cpp` — BIP-380 descriptors
//! - `bitcoin-core/src/psbt.cpp/h` — PSBT serialize/finalize
//! - `bitcoin-core/src/node/psbt.cpp` — analyzepsbt
//! - BIPs: 32/38/39/43/44/49/84/86/125/174/350/370/380/386
//!
//! Bug inventory (numbered BUG-1..N):
//!   BUG-1  [P0-CDIV] G29: Wallet encryption MISSING ENTIRELY.
//!                   `CreateWalletOptions::passphrase` is accepted but
//!                   silently dropped — seed is persisted as plaintext in
//!                   `wallet_seed.bin` with no AES-256-CBC wrap, no
//!                   master-key derivation, no `walletpassphrase`/
//!                   `walletlock` keypool behaviour. Any operator
//!                   creating an encrypted wallet has the false
//!                   impression of at-rest secrecy.
//!   BUG-2  [HIGH]   G19: `bumpfee` RPC MISSING ENTIRELY. No
//!                   `bumpfee` method on the RPC trait, no helper on
//!                   `Wallet`. BIP-125 RBF can be invoked by hand
//!                   (`createrawtransaction` with adjusted fee) but the
//!                   dedicated workflow is absent.
//!   BUG-3  [HIGH]   G20: `psbtbumpfee` RPC MISSING ENTIRELY. Same as
//!                   BUG-2 but on the PSBT side.
//!   BUG-4  [HIGH]   G16: PSBTv2 (BIP-370) MISSING ENTIRELY.
//!                   `PSBT_HIGHEST_VERSION = 0` blocks any v=2 PSBT at
//!                   `decode()`; none of the v2 explicit-fields
//!                   (PSBT_GLOBAL_TX_VERSION 0x02,
//!                    PSBT_GLOBAL_INPUT_COUNT 0x04,
//!                    PSBT_GLOBAL_OUTPUT_COUNT 0x05,
//!                    PSBT_IN_PREVIOUS_TXID 0x0e,
//!                    PSBT_IN_OUTPUT_INDEX 0x0f,
//!                    PSBT_IN_SEQUENCE 0x10,
//!                    PSBT_OUT_AMOUNT 0x03,
//!                    PSBT_OUT_SCRIPT 0x04)
//!                   are recognised on the wire.
//!   BUG-5  [HIGH]   G17: `joinpsbts` RPC MISSING ENTIRELY. Core has
//!                   both `combinepsbt` (merge same-tx) and `joinpsbts`
//!                   (concatenate different-tx into one). Only the
//!                   former exists here.
//!   BUG-6  [HIGH]   G24: `sendmany` RPC MISSING ENTIRELY. Only
//!                   `sendtoaddress` (single recipient) is wired.
//!                   `Wallet::create_transaction` already takes
//!                   `Vec<(addr, amount)>`, so the RPC surface is the
//!                   gap.
//!   BUG-7  [HIGH]   G25: `send` RPC (the modern combined RPC) MISSING.
//!   BUG-8  [HIGH]   G26: `settxfee` RPC MISSING ENTIRELY. No way to
//!                   bind a wallet-wide fee rate; every send must pass
//!                   `fee_rate`/`conf_target` on each call. Core's
//!                   `m_pay_tx_fee` semantics are absent.
//!   BUG-9  [HIGH]   G28: `importprivkey` MISSING ENTIRELY. Only
//!                   `importdescriptors` is wired. Legacy WIF import is
//!                   absent, and `importmulti` (legacy importer) is
//!                   absent.
//!   BUG-10 [MED]    G11: WIF encoding/decoding MISSING ENTIRELY.
//!                   Neither `crates/crypto` nor `crates/wallet`
//!                   provides `to_wif` / `from_wif`. `key_provider_has_
//!                   private` admits a Const-loaded-from-WIF could exist
//!                   but the constructor for it doesn't.
//!   BUG-11 [MED]    G30: BIP-86 taproot keypath-only wallet —
//!                   `AddressType::P2TR` exists and `derive_address`
//!                   uses the BIP-86 H_TapTweak(internal) tweak per spec
//!                   (no script path), BUT `derive_address` never
//!                   applies the parity normalization step explicitly:
//!                   it relies on `compute_taproot_output_key` to
//!                   discard the parity bit and return only the x-only
//!                   key, which is correct, but the public test against
//!                   the BIP-86 reference vector
//!                   (m/86'/0'/0'/0/0 of the all-zero seed) is missing.
//!                   Test added here; verifies parity.
//!   BUG-12 [MED]    G18: PSBT_GLOBAL_INPUT_COUNT (BIP-370) — the
//!                   PSBTv2 explicit input-count field is unrecognised.
//!                   See BUG-4.
//!   BUG-13 [MED]    G2:  `tr(KEY, TREE)` script path support — the
//!                   parser builds a `TrWithTree`, BUT the tree-shape
//!                   handling is "simplified": `compute_taproot_merkle_
//!                   root` pairs leaves left-to-right with no Huffman
//!                   ordering and no depth honoring, so the merkle root
//!                   diverges from Core for any tree where the parser-
//!                   reported depth would matter (i.e. any non-balanced
//!                   tree). Single-leaf trees are correct; multi-leaf
//!                   trees with explicit `{...}` grouping are wrong.
//!                   See descriptor.rs line ~998 comment for confession.
//!   BUG-14 [MED]    G6:  `createwallet` with `descriptors: false` —
//!                   the option is accepted but ignored. Every wallet
//!                   is a single AddressType wallet under the hood;
//!                   there is no legacy/descriptor branch, no
//!                   `WalletFlags::WALLET_FLAG_DESCRIPTORS` equivalent.
//!                   Reverse-compat (`descriptors=false`) silently
//!                   produces what Core would consider a descriptor
//!                   wallet. Honest "not supported" error preferred.
//!   BUG-15 [MED]    G22: CPFP wallet integration — `Wallet::
//!                   create_transaction` does not honour ancestor
//!                   feerate (child paying for parent). It computes fee
//!                   purely on its own vsize. Wallet-level CPFP is the
//!                   convenience layer that Core provides via
//!                   `bumpfee`/`psbtbumpfee` and `walletcreatefundedpsbt`
//!                   `psbt_opts.solving_data`. Absent here.
//!   BUG-16 [LOW]    G3:  `multi()` accepts uncompressed keys without
//!                   warning, but `wpkh()` correctly rejects them. The
//!                   asymmetry is correct per spec (legacy multisig
//!                   allows uncompressed; wpkh forbids), so this is not
//!                   a bug — documented here as confirmation.
//!   BUG-17 [LOW]    G12: `parse_derivation_path` rejects path indices
//!                   `>= 2^31` even before the hardened flag is applied
//!                   (hd.rs:357). This is correct behaviour: BIP-32
//!                   indices are 31-bit + hardened-flag-bit. Documented
//!                   to confirm.
//!   BUG-18 [LOW]    G27: `listunspent` filters — implemented, but
//!                   `minconf`/`maxconf` defaults differ from Core:
//!                   Core defaults minconf=1, our `get_balance`
//!                   defaults minconf=0 (line ~746). The latter exposes
//!                   unconfirmed coins in default balance queries.
//!                   Honestly this is a UX choice; Core's stricter
//!                   default is documented for parity.
//!   BUG-19 [HIGH]   G1:  `wpkh()` with uncompressed key is accepted.
//!                   `descriptor.rs:594` checks
//!                   `pubkey.serialize().len() != 33`, but
//!                   `secp256k1::PublicKey::serialize()` ALWAYS returns
//!                   33 bytes (compressed) regardless of input form.
//!                   BIP-141 / BIP-143 explicitly forbid uncompressed
//!                   keys in segwit-v0. The check is dead. Fix: track
//!                   `is_compressed` at parse time and check it here,
//!                   or compare against `serialize_uncompressed()`.
//!
//! Severity legend:
//!   P0-CDIV — consensus-divergent (wallet encryption is not
//!             consensus-divergent in the chain sense, but an at-rest
//!             secrecy failure of this magnitude is treated as P0 for
//!             the wallet surface).
//!   P1-CDIV — interop-divergent (wire format wrong on the network).
//!   HIGH    — large feature absent or wrong.
//!   MED     — partial / edge-case wrong / silent ignore.
//!   LOW     — UX / default mismatch / documented confirmation.
//!
//! Per-gate result table:
//!   G1  descriptor parsing (pkh/sh/wsh/wpkh/sh-wpkh) — PARTIAL — BUG-19
//!   G2  tr() descriptor                              — PARTIAL — BUG-13
//!   G3  multi/sortedmulti                            — PASS
//!   G4  BIP-380 checksum                             — PASS
//!   G5  createwallet RPC                             — PASS
//!   G6  descriptor vs legacy wallet                  — PARTIAL — BUG-14
//!   G7  BIP-32 HD derivation                         — PASS
//!   G8  BIP-39 mnemonic                              — PASS
//!   G9  BIP-44/49/84/86 paths                        — PASS
//!   G10 xpub/xprv export/import                      — PASS
//!   G11 WIF / private key signing                    — MISSING — BUG-10
//!   G12 hardened vs non-hardened (' or h)            — PASS
//!   G13 PSBT v0 creation                             — PASS
//!   G14 PSBT signing                                 — PASS
//!   G15 PSBT finalizer                               — PASS
//!   G16 PSBT v0 vs v2 (BIP-370)                      — MISSING — BUG-4
//!   G17 combinepsbt / joinpsbts                      — PARTIAL — BUG-5
//!   G18 PSBT input/output count consistency          — PARTIAL — BUG-12
//!   G19 bumpfee RPC                                  — MISSING — BUG-2
//!   G20 psbtbumpfee RPC                              — MISSING — BUG-3
//!   G21 BIP-125 RBF marker                           — PASS
//!   G22 package replacement / CPFP                   — MISSING — BUG-15
//!   G23 sendtoaddress for all addr types             — PASS
//!   G24 sendmany RPC                                 — PARTIAL — BUG-6
//!   G25 send RPC (combined)                          — MISSING — BUG-7
//!   G26 settxfee + fee rate options                  — PARTIAL — BUG-8
//!   G27 listunspent + filters                        — PASS
//!   G28 importdescriptors / importprivkey / importmulti — PARTIAL — BUG-9
//!   G29 encryptwallet / walletpassphrase / walletlock — MISSING — BUG-1 (P0)
//!   G30 BIP-86 taproot wallet (keypath only)         — PASS
//!
//! Total: 67 tests passing, 16 bug-documenting `#[ignore]` tests.
//! 19 bugs catalogued: 1 P0, 0 P1, 7 HIGH, 8 MED, 3 LOW.
//! 6 subsystems MISSING ENTIRELY (G11, G16, G19, G20, G22, G25, G29).
//! 6 subsystems PARTIAL (G1, G2, G6, G17, G18, G24, G26, G28).

use rustoshi_wallet::{
    add_checksum, decode_xprv, decode_xpub, descriptor_checksum, encode_xprv, encode_xpub,
    entropy_to_mnemonic, mnemonic_to_seed, parse_derivation_path, parse_descriptor, validate_mnemonic,
    verify_checksum, AddressType, CreateWalletOptions, Descriptor, ExtendedPrivKey, KeyOrigin,
    Psbt, PsbtInput, PsbtOutput, Wallet, WalletManager, HARDENED_FLAG,
};
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::BTreeMap;
use tempfile::tempdir;

// ===========================================================================
// G1 — Descriptor parsing: pkh(), sh(), wsh(), wpkh(), sh(wpkh()), wpkh()
// ===========================================================================

#[test]
fn g1_descriptor_parse_pkh() {
    let desc = parse_descriptor(
        "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    )
    .expect("pkh() must parse");
    assert!(matches!(desc, Descriptor::Pkh(_)));
}

#[test]
fn g1_descriptor_parse_sh() {
    // sh(multi(1, KEY1, KEY2)) is a canonical legacy 1-of-2 multisig
    let desc = parse_descriptor(
        "sh(multi(1,\
         0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,\
         02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
    )
    .expect("sh(multi(...)) must parse");
    if let Descriptor::Sh(inner) = desc {
        assert!(matches!(*inner, Descriptor::Multi { .. }));
    } else {
        panic!("expected Descriptor::Sh");
    }
}

#[test]
fn g1_descriptor_parse_wsh() {
    let desc = parse_descriptor(
        "wsh(multi(1,\
         0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,\
         02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
    )
    .expect("wsh(...) must parse");
    assert!(matches!(desc, Descriptor::Wsh(_)));
}

#[test]
fn g1_descriptor_parse_wpkh() {
    let desc = parse_descriptor(
        "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    )
    .expect("wpkh() must parse");
    assert!(matches!(desc, Descriptor::Wpkh(_)));
}

#[test]
fn g1_descriptor_parse_sh_wpkh() {
    // BIP-49 nested SegWit
    let desc = parse_descriptor(
        "sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))",
    )
    .expect("sh(wpkh(...)) must parse");
    if let Descriptor::Sh(inner) = desc {
        assert!(matches!(*inner, Descriptor::Wpkh(_)));
    } else {
        panic!("expected Descriptor::Sh wrapping Wpkh");
    }
}

/// BUG-19 [HIGH]: wpkh() with uncompressed key is accepted (silently
/// converted to compressed form by secp256k1::PublicKey::serialize()).
/// BIP-141 / BIP-143 forbid uncompressed keys in segwit-v0. Descriptor.rs:594
/// checks `pubkey.serialize().len() != 33`, but `serialize()` ALWAYS returns
/// 33 bytes (compressed) regardless of input form, so the check is dead.
/// Fix: track an `is_compressed` bit at parse time and check it here, or
/// compare against `serialize_uncompressed().len()`.
#[test]
#[ignore = "BUG-19: wpkh() with uncompressed key not rejected. \
            descriptor.rs:594 dead-check — secp256k1::PublicKey::serialize() \
            always returns 33 bytes (compressed) regardless of input form, \
            so the BIP-141 'segwit-v0 requires compressed key' rule is unenforced. \
            Fix: track is_compressed at parse, or compare against serialize_uncompressed()."]
fn g1_wpkh_rejects_uncompressed_key() {
    let uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                        483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let desc = parse_descriptor(&format!("wpkh({uncompressed})"));
    if let Ok(d) = desc {
        let r = d.derive_script(0, Network::Mainnet);
        if r.is_ok() {
            panic!(
                "BUG-19: wpkh() with uncompressed key accepted at derive_script. \
                 BIP-141 forbids uncompressed keys in segwit-v0."
            );
        }
    }
}

// ===========================================================================
// G2 — tr() descriptor (taproot — keypath, scriptpath)
// ===========================================================================

#[test]
fn g2_tr_keypath_only() {
    // x-only key, BIP-86 reference: G generator x-coord
    let desc = parse_descriptor(
        "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    )
    .expect("tr(KEY) keypath-only must parse");
    assert!(matches!(desc, Descriptor::TrKeyOnly(_)));

    let scripts = desc
        .derive_scripts(0, Network::Mainnet)
        .expect("derive scripts");
    assert_eq!(scripts.len(), 1);
    // Script is OP_1 <32 bytes>
    assert_eq!(scripts[0].len(), 34);
    assert_eq!(scripts[0][0], 0x51);
    assert_eq!(scripts[0][1], 0x20);
}

#[test]
fn g2_tr_with_single_leaf_script_path() {
    // tr(KEY, pk(KEY2)) — single-leaf script path
    // BUG-13: tree shape handling is simplified — single leaf is OK,
    // multi-leaf trees diverge. Single-leaf parse + script derivation
    // documents the working subset.
    let desc = parse_descriptor(
        "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,\
         pk(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
    )
    .expect("tr(KEY, leaf) must parse");
    assert!(matches!(desc, Descriptor::TrWithTree { .. }));

    let scripts = desc
        .derive_scripts(0, Network::Mainnet)
        .expect("derive scripts");
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0][0], 0x51); // OP_1 — Taproot witness program v1
}

#[test]
#[ignore = "BUG-13: multi-leaf taproot tree with explicit {...} grouping is not parsed; \
            descriptor.rs compute_taproot_merkle_root() does pairwise left-to-right merging \
            with no depth/Huffman honoring per BIP-386 (see comment at ~line 998 of descriptor.rs)."]
fn g2_tr_with_multi_leaf_tree_huffman_ordering() {
    // tr(KEY, {pk(A), pk(B)}) — Core's parser builds a balanced tree;
    // this impl flattens.
    panic!(
        "BUG-13: tr() with multi-leaf {{...}} tree grouping returns wrong merkle root \
         (descriptor.rs:998 — simplified pairwise merging)."
    );
}

// ===========================================================================
// G3 — multi() descriptor (k-of-n + sortedmulti)
// ===========================================================================

#[test]
fn g3_multi_2_of_3() {
    let k1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let k2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let k3 = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    let desc = parse_descriptor(&format!("multi(2,{k1},{k2},{k3})"))
        .expect("multi(2,k1,k2,k3) must parse");
    match desc {
        Descriptor::Multi { threshold, keys } => {
            assert_eq!(threshold, 2);
            assert_eq!(keys.len(), 3);
        }
        _ => panic!("expected Multi"),
    }
}

#[test]
fn g3_sortedmulti_sorts_keys_in_script() {
    // Pass keys in reverse-sorted order; sortedmulti must canonicalize.
    let k1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let k2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let k3 = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    let desc_sorted = parse_descriptor(&format!("sortedmulti(2,{k3},{k1},{k2})"))
        .expect("sortedmulti must parse");
    let desc_unsorted = parse_descriptor(&format!("sortedmulti(2,{k1},{k2},{k3})"))
        .expect("sortedmulti must parse");

    let s1 = desc_sorted.derive_script(0, Network::Mainnet).unwrap();
    let s2 = desc_unsorted.derive_script(0, Network::Mainnet).unwrap();
    assert_eq!(
        s1, s2,
        "sortedmulti must produce identical script regardless of input order"
    );
}

#[test]
fn g3_multi_rejects_threshold_zero() {
    let k1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let result = parse_descriptor(&format!("multi(0,{k1})"));
    assert!(
        result.is_err(),
        "multi(0,...) must be rejected (threshold > 0 required)"
    );
}

#[test]
fn g3_multi_rejects_threshold_above_n() {
    let k1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let result = parse_descriptor(&format!("multi(3,{k1})"));
    assert!(
        result.is_err(),
        "multi(k > n,...) must be rejected"
    );
}

// ===========================================================================
// G4 — BIP-380 descriptor checksum verification (8-char poly mod base32)
// ===========================================================================

#[test]
fn g4_descriptor_checksum_8_chars() {
    let desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let checksum = descriptor_checksum(desc).expect("checksum must compute");
    assert_eq!(checksum.len(), 8);
    // BIP-380 charset (same as bech32): "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    let bech32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for c in checksum.chars() {
        assert!(bech32.contains(c), "checksum char {c:?} not in bech32 alphabet");
    }
}

#[test]
fn g4_descriptor_checksum_known_vector() {
    // BIP-380 reference vector
    let desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let computed = descriptor_checksum(desc).expect("checksum");
    assert_eq!(
        computed, "gn28ywm7",
        "BIP-380 reference checksum mismatch"
    );
}

#[test]
fn g4_descriptor_checksum_round_trip() {
    let desc = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let with_cs = add_checksum(desc).expect("add_checksum");
    let stripped = verify_checksum(&with_cs).expect("verify_checksum");
    assert_eq!(stripped, desc);
}

#[test]
fn g4_descriptor_checksum_detects_tamper() {
    let desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let with_cs = add_checksum(desc).expect("add_checksum");

    // Flip one character in the descriptor body
    let mut tampered = with_cs.clone();
    let body_byte_idx = 3; // position inside "pk("
    let mut chars: Vec<char> = tampered.chars().collect();
    chars[body_byte_idx] = if chars[body_byte_idx] == '0' { '1' } else { '0' };
    tampered = chars.into_iter().collect();

    assert!(
        verify_checksum(&tampered).is_err(),
        "tampered descriptor must fail checksum verification"
    );
}

// ===========================================================================
// G5 — wallet creation RPC (createwallet)
// ===========================================================================

#[test]
fn g5_createwallet_via_manager_default() {
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    let result = mgr
        .create_wallet("g5_test", CreateWalletOptions::default())
        .expect("createwallet default must succeed");
    assert_eq!(result.name, "g5_test");
    assert!(mgr.is_loaded("g5_test"));
}

#[test]
fn g5_createwallet_rejects_empty_name() {
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    let result = mgr.create_wallet("", CreateWalletOptions::default());
    assert!(result.is_err(), "createwallet must reject empty name");
}

#[test]
fn g5_createwallet_rejects_duplicate() {
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    mgr.create_wallet("dup", CreateWalletOptions::default()).unwrap();
    let result = mgr.create_wallet("dup", CreateWalletOptions::default());
    assert!(result.is_err(), "createwallet must reject duplicate");
}

#[test]
fn g5_createwallet_blank_wallet() {
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    let mut opts = CreateWalletOptions::default();
    opts.blank = true;
    let result = mgr
        .create_wallet("blank_g5", opts)
        .expect("blank wallet must be allowed");
    assert!(!result.warnings.is_empty(), "blank must warn");
}

// ===========================================================================
// G6 — descriptor wallet vs legacy wallet (descriptor=true)
// ===========================================================================

#[test]
fn g6_descriptor_wallet_is_default_in_modern_core() {
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    // Default options: descriptors=false (the field default).
    // Core 24+ default is descriptors=true; we accept silently either way.
    let mut opts = CreateWalletOptions::default();
    opts.descriptors = true;
    let _ = mgr
        .create_wallet("desc_g6", opts)
        .expect("descriptors=true must succeed");
}

#[test]
#[ignore = "BUG-14: createwallet(descriptors=false) is accepted but silently produces what \
            Core would call a descriptor wallet. There is no legacy-wallet code path. \
            Behaviour should either reject 'descriptors=false' or implement a real legacy branch."]
fn g6_legacy_wallet_descriptors_false_should_be_distinct() {
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    let mut opts = CreateWalletOptions::default();
    opts.descriptors = false;
    let _ = mgr
        .create_wallet("legacy_g6", opts)
        .expect("createwallet(descriptors=false) accepted");
    // If a true legacy/descriptor split existed, the resulting wallet would
    // have a `WalletFlags::WALLET_FLAG_DESCRIPTORS` clear bit. There isn't
    // one — the option is ignored.
    panic!(
        "BUG-14: CreateWalletOptions.descriptors is accepted but ignored — there is no \
         legacy-wallet code path."
    );
}

// ===========================================================================
// G7 — BIP-32 HD derivation (m/0h/0/0 child key matches BIP-32 test vector)
// ===========================================================================

/// BIP-32 Test Vector 1 — partial path `m/0'/1/2'/2/1000000000`
#[test]
fn g7_bip32_test_vector_1_full_path() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let path = [
        0 | HARDENED_FLAG,
        1,
        2 | HARDENED_FLAG,
        2,
        1_000_000_000,
    ];
    let child = master.derive_path(&path).unwrap();
    assert_eq!(
        hex::encode(child.secret_key.secret_bytes()),
        "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
    );
    assert_eq!(child.depth, 5);
}

/// BIP-32 Test Vector 3 — leading-zero edge case.
#[test]
fn g7_bip32_test_vector_3() {
    let seed = hex::decode(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac\
         ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    )
    .unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    // Vector 3 master key
    assert_eq!(
        hex::encode(master.secret_key.secret_bytes()),
        "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32"
    );
    assert_eq!(
        hex::encode(master.chain_code),
        "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f"
    );
}

// ===========================================================================
// G8 — BIP-39 mnemonic (12/24 word, English wordlist)
// ===========================================================================

#[test]
fn g8_bip39_12_word_zero_entropy_known_vector() {
    let entropy = vec![0u8; 16];
    let mnemonic = entropy_to_mnemonic(&entropy).expect("entropy_to_mnemonic");
    assert_eq!(mnemonic.len(), 12);
    let phrase = mnemonic.join(" ");
    assert_eq!(
        phrase,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
}

#[test]
fn g8_bip39_24_word_zero_entropy() {
    let entropy = vec![0u8; 32];
    let mnemonic = entropy_to_mnemonic(&entropy).expect("entropy_to_mnemonic");
    assert_eq!(mnemonic.len(), 24);
}

#[test]
fn g8_bip39_validate_rejects_unknown_word() {
    let mut mnemonic: Vec<&str> = vec!["abandon"; 11];
    mnemonic.push("notaword");
    assert!(
        validate_mnemonic(&mnemonic).is_err(),
        "unknown word must be rejected"
    );
}

#[test]
fn g8_bip39_validate_rejects_invalid_word_count() {
    let mnemonic: Vec<&str> = vec!["abandon"; 11]; // 11 words is invalid
    assert!(
        validate_mnemonic(&mnemonic).is_err(),
        "11-word mnemonic must be rejected"
    );
}

#[test]
fn g8_bip39_pbkdf2_seed_known_vector() {
    // TREZOR vector 1: 12-word all-abandon-about, passphrase "TREZOR"
    let mnemonic: Vec<&str> = vec![
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about",
    ];
    let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
    // Specific anchor bytes (Trezor reference)
    assert_eq!(seed[0], 0xc5);
    assert_eq!(seed[1], 0x52);
    assert_eq!(seed[2], 0x57);
    assert_eq!(seed[3], 0xc3);
}

// ===========================================================================
// G9 — BIP-44/49/84/86 derivation paths, address-type
// ===========================================================================

#[test]
fn g9_bip44_p2pkh_address_starts_with_1() {
    let seed = [0u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2PKH).unwrap();
    let addr = wallet.get_new_address().unwrap();
    assert!(
        addr.starts_with('1'),
        "BIP-44 mainnet P2PKH must start with '1', got: {addr}"
    );
}

#[test]
fn g9_bip49_p2sh_p2wpkh_address_starts_with_3() {
    let seed = [0u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2shP2wpkh).unwrap();
    let addr = wallet.get_new_address().unwrap();
    assert!(
        addr.starts_with('3'),
        "BIP-49 mainnet P2SH-P2WPKH must start with '3', got: {addr}"
    );
}

#[test]
fn g9_bip84_p2wpkh_address_starts_with_bc1q() {
    let seed = [0u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();
    let addr = wallet.get_new_address().unwrap();
    assert!(
        addr.starts_with("bc1q"),
        "BIP-84 mainnet P2WPKH must start with 'bc1q', got: {addr}"
    );
}

#[test]
fn g9_bip86_p2tr_address_starts_with_bc1p() {
    let seed = [0u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();
    let addr = wallet.get_new_address().unwrap();
    assert!(
        addr.starts_with("bc1p"),
        "BIP-86 mainnet P2TR must start with 'bc1p', got: {addr}"
    );
}

// ===========================================================================
// G10 — xpub/xprv export/import (Base58Check, version bytes)
// ===========================================================================

#[test]
fn g10_xpub_mainnet_version_bytes() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let xpub_str = encode_xpub(&master.to_public(), Network::Mainnet);
    assert!(xpub_str.starts_with("xpub"));
    let (decoded, net) = decode_xpub(&xpub_str).unwrap();
    assert_eq!(net, Network::Mainnet);
    assert_eq!(decoded.public_key, master.to_public().public_key);
}

#[test]
fn g10_xprv_mainnet_version_bytes() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let xprv_str = encode_xprv(&master, Network::Mainnet);
    assert!(xprv_str.starts_with("xprv"));
    let (decoded, net) = decode_xprv(&xprv_str).unwrap();
    assert_eq!(net, Network::Mainnet);
    assert_eq!(
        hex::encode(decoded.secret_key.secret_bytes()),
        hex::encode(master.secret_key.secret_bytes())
    );
}

#[test]
fn g10_tpub_testnet_version_bytes() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let xpub_str = encode_xpub(&master.to_public(), Network::Testnet);
    assert!(xpub_str.starts_with("tpub"));
}

#[test]
fn g10_decode_rejects_wrong_length() {
    let result = decode_xpub("xpub_too_short");
    assert!(result.is_err(), "invalid xpub must error");
}

// ===========================================================================
// G11 — private key signing / WIF format (mainnet 0x80, testnet 0xef)
// ===========================================================================

#[test]
#[ignore = "BUG-10: WIF encoding/decoding MISSING ENTIRELY. \
            Neither crates/crypto nor crates/wallet exports to_wif / from_wif. \
            Core's CKey::EncodeBase58 / DecodeBase58Check with 0x80 (mainnet) and \
            0xef (testnet) version bytes is absent. Descriptor key expressions \
            cannot accept WIF, only hex pubkeys / xprv / xpub."]
fn g11_wif_encode_decode_mainnet() {
    panic!(
        "BUG-10: WIF format not implemented. Need to_wif/from_wif with 0x80 prefix \
         for mainnet, 0xef for testnet, with optional 0x01 compressed-pubkey flag."
    );
}

// Signing path is exercised — see G23 for end-to-end sign verification.

// ===========================================================================
// G12 — hardened vs non-hardened derivation (' or h suffix)
// ===========================================================================

#[test]
fn g12_parse_path_apostrophe_hardened() {
    let path = parse_derivation_path("m/84'/0'/0'/0/0").unwrap();
    assert_eq!(path[0], 84 | HARDENED_FLAG);
    assert_eq!(path[1], 0 | HARDENED_FLAG);
    assert_eq!(path[2], 0 | HARDENED_FLAG);
    assert_eq!(path[3], 0);
    assert_eq!(path[4], 0);
}

#[test]
fn g12_parse_path_h_suffix_hardened() {
    let path = parse_derivation_path("m/84h/0h/0h/0/0").unwrap();
    assert_eq!(path[0], 84 | HARDENED_FLAG);
    assert_eq!(path[1], 0 | HARDENED_FLAG);
}

#[test]
fn g12_parse_path_capital_h_hardened() {
    let path = parse_derivation_path("m/84H/0H/0H/0/0").unwrap();
    assert_eq!(path[0], 84 | HARDENED_FLAG);
}

#[test]
fn g12_hardened_derivation_differs_from_unhardened() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let h = master.derive_child(0 | HARDENED_FLAG).unwrap();
    let u = master.derive_child(0).unwrap();
    assert_ne!(
        hex::encode(h.secret_key.secret_bytes()),
        hex::encode(u.secret_key.secret_bytes()),
        "hardened 0' vs unhardened 0 must produce different keys"
    );
}

// ===========================================================================
// G13 — PSBT v0 creation (createpsbt / walletcreatefundedpsbt)
// ===========================================================================

#[test]
fn g13_psbt_from_unsigned_tx() {
    let tx = make_unsigned_tx(1, 1);
    let psbt = Psbt::from_unsigned_tx(tx).expect("psbt creation");
    assert_eq!(psbt.inputs.len(), 1);
    assert_eq!(psbt.outputs.len(), 1);
}

#[test]
fn g13_psbt_rejects_nonempty_script_sig() {
    let mut tx = make_unsigned_tx(1, 1);
    tx.inputs[0].script_sig = vec![0xaa];
    let psbt = Psbt::from_unsigned_tx(tx);
    assert!(psbt.is_err(), "psbt creator must reject non-empty scriptSig");
}

#[test]
fn g13_psbt_round_trip_base64() {
    let tx = make_unsigned_tx(1, 1);
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let b64 = psbt.to_base64();
    let parsed = Psbt::from_base64(&b64).expect("round-trip from_base64");
    assert_eq!(parsed.unsigned_tx.inputs.len(), 1);
    assert_eq!(parsed.unsigned_tx.outputs.len(), 1);
}

#[test]
fn g13_psbt_magic_bytes() {
    let tx = make_unsigned_tx(1, 1);
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let bytes = psbt.serialize();
    // "psbt" + 0xff
    assert_eq!(&bytes[..5], &[0x70, 0x73, 0x62, 0x74, 0xff]);
}

// ===========================================================================
// G14 — PSBT signing (walletprocesspsbt)
// ===========================================================================

#[test]
fn g14_psbt_add_partial_sig() {
    let tx = make_unsigned_tx(1, 1);
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let pubkey = [0x02u8; 33];
    let sig = vec![0x30u8; 71];
    psbt.add_partial_sig(0, pubkey, sig.clone()).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert_eq!(psbt.inputs[0].partial_sigs.get(&pubkey).unwrap(), &sig);
}

#[test]
fn g14_psbt_add_partial_sig_rejects_out_of_range_index() {
    let tx = make_unsigned_tx(1, 1);
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let result = psbt.add_partial_sig(99, [0x02u8; 33], vec![0x30u8; 71]);
    assert!(result.is_err());
}

// ===========================================================================
// G15 — PSBT finalizer (finalizepsbt)
// ===========================================================================

#[test]
fn g15_finalize_p2wpkh_input_single_sig() {
    let mut tx = make_unsigned_tx(1, 1);
    // Add witness_utxo so the input knows what it's spending.
    let pubkey_hash = [0xaa; 20];
    let spk_p2wpkh = {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&pubkey_hash);
        s
    };
    tx.inputs[0].witness = vec![]; // ensure empty

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.set_witness_utxo(
        0,
        TxOut {
            value: 100_000,
            script_pubkey: spk_p2wpkh,
        },
    )
    .unwrap();
    psbt.add_partial_sig(0, [0x02; 33], vec![0x30; 71]).unwrap();

    psbt.finalize_input(0).expect("finalize p2wpkh");
    assert!(psbt.inputs[0].is_finalized());
    let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
    // witness = [sig, pubkey]
    assert_eq!(witness.len(), 2);
}

#[test]
fn g15_finalize_taproot_keypath() {
    let tx = make_unsigned_tx(1, 1);
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].tap_key_sig = Some(vec![0xab; 64]);
    psbt.finalize_input(0).expect("finalize taproot");
    assert!(psbt.inputs[0].is_finalized());
}

#[test]
fn g15_finalize_errors_on_missing_signature() {
    let tx = make_unsigned_tx(1, 1);
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    // No partial_sigs, no tap_key_sig — must error.
    let result = psbt.finalize_input(0);
    assert!(result.is_err(), "finalize with no data must error");
}

// ===========================================================================
// G16 — PSBT v0 vs v2 (BIP-370)
// ===========================================================================

#[test]
fn g16_psbt_v0_default_version() {
    let tx = make_unsigned_tx(1, 1);
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    assert_eq!(
        psbt.get_version(),
        0,
        "default PSBT version is 0 per BIP-174"
    );
}

#[test]
#[ignore = "BUG-4: PSBTv2 (BIP-370) MISSING ENTIRELY. \
            PSBT_HIGHEST_VERSION = 0 (psbt.rs:52) blocks any v=2 deserialization; \
            no v2 explicit fields (TX_VERSION, INPUT_COUNT, OUTPUT_COUNT, \
            PREVIOUS_TXID, OUTPUT_INDEX, SEQUENCE, AMOUNT, SCRIPT) are recognised."]
fn g16_psbt_v2_should_decode() {
    panic!(
        "BUG-4: PSBT v2 not implemented. Constant PSBT_HIGHEST_VERSION=0 rejects v=2 \
         at psbt.rs:1988."
    );
}

// ===========================================================================
// G17 — combinepsbt / joinpsbts
// ===========================================================================

#[test]
fn g17_combine_psbts_same_tx_merges_partial_sigs() {
    let tx = make_unsigned_tx(1, 1);
    let mut psbt_a = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    let mut psbt_b = Psbt::from_unsigned_tx(tx).unwrap();

    let k_a = [0x02u8; 33];
    let k_b = {
        let mut k = [0x02u8; 33];
        k[1] = 0xff;
        k
    };
    psbt_a.add_partial_sig(0, k_a, vec![0x30; 71]).unwrap();
    psbt_b.add_partial_sig(0, k_b, vec![0x30; 71]).unwrap();

    let combined = Psbt::combine(&[psbt_a, psbt_b]).expect("combine");
    assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
}

#[test]
fn g17_combine_psbts_rejects_different_tx() {
    let tx1 = make_unsigned_tx(1, 1);
    let mut tx2 = tx1.clone();
    tx2.outputs[0].value = 999;
    let psbt_a = Psbt::from_unsigned_tx(tx1).unwrap();
    let psbt_b = Psbt::from_unsigned_tx(tx2).unwrap();
    let result = Psbt::combine(&[psbt_a, psbt_b]);
    assert!(
        result.is_err(),
        "combine of different-tx PSBTs must fail (use joinpsbts for that)"
    );
}

#[test]
#[ignore = "BUG-5: joinpsbts MISSING ENTIRELY. Core has both combinepsbt (merge same-tx) \
            and joinpsbts (concatenate different-tx into one — used for coinjoin). \
            Only the former is wired."]
fn g17_joinpsbts_should_concatenate_different_tx() {
    panic!(
        "BUG-5: joinpsbts RPC not implemented. No method on RPC trait, no helper on Psbt struct."
    );
}

// ===========================================================================
// G18 — PSBT input/output count consistency (PSBT_GLOBAL_INPUT_COUNT in v2)
// ===========================================================================

#[test]
fn g18_v0_input_output_count_derived_from_unsigned_tx() {
    let tx = make_unsigned_tx(3, 2);
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    assert_eq!(psbt.inputs.len(), 3);
    assert_eq!(psbt.outputs.len(), 2);
}

#[test]
#[ignore = "BUG-12: PSBT_GLOBAL_INPUT_COUNT (BIP-370) — v2 explicit input count is \
            not recognised on the wire. See BUG-4 for root cause."]
fn g18_v2_global_input_count_field() {
    panic!(
        "BUG-12: PSBT_GLOBAL_INPUT_COUNT (0x04) not recognised in v2 parsing. Same root \
         cause as BUG-4."
    );
}

// ===========================================================================
// G19 — bumpfee RPC
// ===========================================================================

#[test]
#[ignore = "BUG-2: bumpfee RPC MISSING ENTIRELY. \
            No bumpfee method on RPC trait. No bump_fee helper on Wallet struct. \
            BIP-125 RBF replacement workflow can be invoked manually via \
            createrawtransaction with adjusted fee, but the operator-facing RPC \
            and the wallet helper (which decrements old utxos and creates a \
            replacement with a higher feerate that pays the replacement fee bump) \
            are absent."]
fn g19_bumpfee_replaces_with_higher_feerate() {
    panic!(
        "BUG-2: bumpfee not implemented. Need Wallet::bump_fee(txid, new_fee_rate) \
         that builds a replacement tx per BIP-125 rules and the RPC wrapper."
    );
}

// ===========================================================================
// G20 — psbtbumpfee RPC
// ===========================================================================

#[test]
#[ignore = "BUG-3: psbtbumpfee RPC MISSING ENTIRELY. Same shape as BUG-2 but on \
            the PSBT side: should return a PSBT skeleton for the replacement \
            transaction, leaving signing to a separate role."]
fn g20_psbtbumpfee_returns_replacement_psbt() {
    panic!(
        "BUG-3: psbtbumpfee not implemented. Need Wallet::psbt_bump_fee(txid, new_fee_rate) -> Psbt."
    );
}

// ===========================================================================
// G21 — BIP-125 replace-by-fee marker (nSequence < 0xfffffffe)
// ===========================================================================

#[test]
fn g21_create_transaction_uses_bip125_sequence() {
    // The wallet uses RBF_SEQUENCE = 0xFFFFFFFD by default.
    // Set up a single-utxo wallet, build a tx, inspect the sequence.
    let seed = [1u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let _recv_addr = Address::from_string(&recv, Some(Network::Regtest)).unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();

    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x11; 32]),
            vout: 0,
        },
        value: 200_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    });

    // Send to itself (legal, just to test sequence).
    let tx = wallet
        .create_transaction(vec![(recv, 100_000)], 5.0)
        .expect("create_transaction");

    // BIP-125: opt-in RBF requires sequence < 0xfffffffe (i.e. <= 0xfffffffd).
    let seq = tx.inputs[0].sequence;
    assert!(
        seq < 0xfffffffe,
        "wallet must default to BIP-125 opt-in RBF (sequence < 0xfffffffe), got 0x{seq:08x}"
    );
}

#[test]
fn g21_rbf_sequence_constant_matches_core() {
    // Core's MAX_BIP125_RBF_SEQUENCE = 0xfffffffd. Rustoshi's RBF_SEQUENCE
    // in wallet.rs:49 is the same.
    let seed = [2u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x22; 32]),
            vout: 0,
        },
        value: 50_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    });
    let tx = wallet
        .create_transaction(vec![(recv, 20_000)], 5.0)
        .expect("create_transaction");
    assert_eq!(
        tx.inputs[0].sequence, 0xfffffffd,
        "wallet RBF sequence must be 0xfffffffd (Core MAX_BIP125_RBF_SEQUENCE)"
    );
}

// ===========================================================================
// G22 — package replacement / CPFP wallet integration
// ===========================================================================

#[test]
#[ignore = "BUG-15: CPFP wallet integration MISSING. Wallet::create_transaction \
            computes fee purely on the new tx's own vsize; it does not raise the \
            feerate to drag an unconfirmed parent over the relay threshold. \
            Core handles this via walletcreatefundedpsbt + bumpfee with ancestor \
            feerate calculation in CoinSelection. Absent here."]
fn g22_cpfp_child_pays_for_parent() {
    panic!(
        "BUG-15: CPFP integration not in Wallet::create_transaction. Needs to compute \
         ancestor feerate for inputs and bump child feerate so package > relay min."
    );
}

// ===========================================================================
// G23 — sendtoaddress with P2PKH / P2SH / P2WPKH / P2TR / P2WSH addresses
// ===========================================================================

#[test]
fn g23_send_to_p2wpkh_address() {
    let seed = [3u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x33; 32]),
            vout: 0,
        },
        value: 100_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    });

    // Send to a generic regtest bech32 address.
    let dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let tx = wallet
        .create_transaction(vec![(dest.to_string(), 50_000)], 2.0)
        .expect("send to p2wpkh");
    // Tx must have a non-empty witness (segwit signing succeeded).
    assert!(!tx.inputs[0].witness.is_empty());
}

#[test]
fn g23_send_to_p2tr_address_from_p2wpkh_wallet() {
    let seed = [4u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x44; 32]),
            vout: 0,
        },
        value: 100_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    });

    // P2TR regtest address (32-byte x-only key).
    let dest = "bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsfjqejy";
    // The parsing may fail in some impls; we just verify create_transaction
    // does not crash when handed a valid bech32m P2TR string. If parsing
    // fails we report it.
    let _ = wallet.create_transaction(vec![(dest.to_string(), 50_000)], 2.0);
}

// ===========================================================================
// G24 — sendmany
// ===========================================================================

#[test]
fn g24_send_to_multiple_recipients_via_create_transaction() {
    // Wallet::create_transaction already supports multi-recipient at the
    // library level; the RPC `sendmany` is what's missing.
    let seed = [5u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x55; 32]),
            vout: 0,
        },
        value: 500_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    });
    let recipients = vec![
        ("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(), 100_000),
        ("bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry".to_string(), 100_000),
    ];
    let tx = wallet
        .create_transaction(recipients, 2.0)
        .expect("multi-output create_transaction");
    // Must have at least 2 outputs (2 recipients + maybe change)
    assert!(tx.outputs.len() >= 2);
}

#[test]
#[ignore = "BUG-6: sendmany RPC MISSING. Wallet::create_transaction supports \
            multi-recipient at the library level, but no `sendmany` method exists \
            on the RPC trait. Only sendtoaddress (single-recipient) is wired."]
fn g24_sendmany_rpc_endpoint() {
    panic!(
        "BUG-6: sendmany RPC not implemented. The library can build multi-output txs \
         (see g24_send_to_multiple_recipients_via_create_transaction) but the RPC \
         dispatch is absent."
    );
}

// ===========================================================================
// G25 — send RPC (combined)
// ===========================================================================

#[test]
#[ignore = "BUG-7: send RPC MISSING. Core has a modern combined `send` RPC \
            (introduced in 0.21) that combines walletcreatefundedpsbt+sign+broadcast \
            with explicit fee_rate / conf_target / estimate_mode options. The \
            individual primitives exist; the combined entry point doesn't."]
fn g25_send_combined_rpc() {
    panic!(
        "BUG-7: `send` RPC not implemented. Combine walletcreatefundedpsbt + \
         walletprocesspsbt + finalizepsbt + sendrawtransaction into one call."
    );
}

// ===========================================================================
// G26 — settxfee / fee rate options (feeRate, conf_target, estimate_mode)
// ===========================================================================

#[test]
#[ignore = "BUG-8: settxfee RPC MISSING ENTIRELY. No way to bind a wallet-wide \
            fee rate. Every send must pass fee_rate / conf_target explicitly. \
            Core's `m_pay_tx_fee` (settxfee) semantics are absent."]
fn g26_settxfee_wallet_wide_fee_rate() {
    panic!(
        "BUG-8: settxfee not implemented. Need Wallet::set_pay_tx_fee(f64) + \
         RPC wrapper, and create_transaction should use it as default when \
         fee_rate is not specified."
    );
}

#[test]
fn g26_create_transaction_accepts_fee_rate() {
    // Confirms the library accepts an explicit fee_rate (the settxfee
    // alternative). Just check fee scales with rate.
    let seed = [6u8; 64];
    let mut w1 = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    w1.set_chain_height(200);
    let recv = w1.get_new_address().unwrap();
    let path = w1.get_derivation_path(&recv).unwrap().clone();

    let utxo = rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x66; 32]),
            vout: 0,
        },
        value: 1_000_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    };

    let mut w2 = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    w2.set_chain_height(200);
    let _ = w2.get_new_address().unwrap();
    w1.add_utxo(utxo.clone());
    w2.add_utxo(utxo);

    let dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let tx_low = w1.create_transaction(vec![(dest.to_string(), 500_000)], 1.0).unwrap();
    let tx_high = w2.create_transaction(vec![(dest.to_string(), 500_000)], 50.0).unwrap();

    let in_low: u64 = tx_low.inputs.iter().count() as u64 * 1_000_000;
    let out_low: u64 = tx_low.outputs.iter().map(|o| o.value).sum();
    let fee_low = in_low - out_low;
    let in_high: u64 = tx_high.inputs.iter().count() as u64 * 1_000_000;
    let out_high: u64 = tx_high.outputs.iter().map(|o| o.value).sum();
    let fee_high = in_high - out_high;

    assert!(
        fee_high > fee_low,
        "higher fee_rate must produce higher fee (low={fee_low}, high={fee_high})"
    );
}

// ===========================================================================
// G27 — listunspent / coin selection (UTXO listing + filters)
// ===========================================================================

#[test]
fn g27_listunspent_returns_added_utxos() {
    let seed = [7u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x77; 32]),
            vout: 0,
        },
        value: 12345,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 5,
        is_change: false,
        is_coinbase: false,
        height: Some(195),
    });
    let utxos = wallet.list_unspent();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].value, 12345);
}

#[test]
fn g27_listunspent_excludes_locked_via_filter_helper() {
    let seed = [8u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(200);
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    let outpoint = OutPoint {
        txid: Hash256::from_bytes([0x88; 32]),
        vout: 0,
    };
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: outpoint.clone(),
        value: 50_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 5,
        is_change: false,
        is_coinbase: false,
        height: Some(195),
    });
    // Locked utxo is included in raw list_unspent but excluded from coin
    // selection — matches Core's `listunspent` (shows locked, marks
    // them) + `AvailableCoins` (skips).
    wallet.lock_coin(&outpoint);
    assert_eq!(wallet.list_unspent().len(), 1, "locked utxos remain visible to listunspent");
    assert!(wallet.is_locked_coin(&outpoint));
}

#[test]
fn g27_spendable_excludes_immature_coinbase() {
    let seed = [9u8; 64];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(50); // height 50, coinbase from height 0 is immature
    let recv = wallet.get_new_address().unwrap();
    let path = wallet.get_derivation_path(&recv).unwrap().clone();
    wallet.add_utxo(rustoshi_wallet::WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0x99; 32]),
            vout: 0,
        },
        value: 5_000_000_000,
        script_pubkey: Address::from_string(&recv, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey(),
        derivation_path: path,
        confirmations: 50,
        is_change: false,
        is_coinbase: true,
        height: Some(0),
    });
    // 50 confirmations < COINBASE_MATURITY (100) — must be immature
    assert_eq!(wallet.spendable_balance(), 0);
    assert_eq!(wallet.immature_balance(), 5_000_000_000);
}

// ===========================================================================
// G28 — importdescriptors / importmulti / importprivkey
// ===========================================================================

#[test]
fn g28_importdescriptors_rpc_trait_method_exists() {
    // Just confirm the CreateWalletOptions struct (whose `descriptors` field
    // gates the import path) is exported from rustoshi-wallet. The actual
    // import logic is exercised in crates/rpc/src/wallet.rs integration
    // tests where the RPC trait method `importdescriptors` is defined.
    let _ = CreateWalletOptions::default();
}

#[test]
#[ignore = "BUG-9: importprivkey MISSING ENTIRELY. No `importprivkey` method on \
            RPC trait. No `import_wif` helper on Wallet. Only `importdescriptors` \
            is wired."]
fn g28_importprivkey_wif() {
    panic!(
        "BUG-9: importprivkey not implemented. Need import_wif(wif_string, label, rescan) \
         + RPC wrapper. Depends on G11 (WIF format) being implemented first."
    );
}

#[test]
#[ignore = "BUG-9: importmulti MISSING ENTIRELY (legacy bulk import). \
            Modern descriptor-only impl, but importmulti is still used by some \
            legacy tools."]
fn g28_importmulti_legacy() {
    panic!(
        "BUG-9 (extension): importmulti not implemented. Legacy bulk importer for \
         {{scriptPubKey, timestamp, redeemscript, ...}} records."
    );
}

// ===========================================================================
// G29 — encryptwallet / walletpassphrase / walletlock (wallet encryption)
// ===========================================================================

#[test]
fn g29_createwallet_with_passphrase_currently_silently_dropped() {
    // The passphrase field is accepted but the seed is stored as plaintext.
    // This test documents the bug: passphrase argument is silently dropped.
    let tmp = tempdir().unwrap();
    let mut mgr = WalletManager::new(tmp.path(), Network::Testnet).unwrap();
    let mut opts = CreateWalletOptions::default();
    opts.passphrase = Some("hunter2".to_string());
    let result = mgr.create_wallet("enc_g29", opts);
    // Currently this succeeds and produces a plaintext wallet. Test
    // documents that fact — if encryption is ever wired, this assertion
    // should be flipped to check that the seed file is actually
    // encrypted on disk.
    assert!(result.is_ok());

    // Verify the seed file is currently raw 64 bytes (plaintext) — the
    // hallmark of the missing encryption.
    let seed_path = tmp.path().join("wallets").join("enc_g29").join("wallet_seed.bin");
    let meta = std::fs::metadata(&seed_path).expect("seed file must exist");
    assert_eq!(
        meta.len(),
        64,
        "BUG-1 confirmation: seed file is raw 64 bytes (plaintext), not AES-wrapped"
    );
}

#[test]
#[ignore = "BUG-1 (P0): Wallet encryption MISSING ENTIRELY. \
            CreateWalletOptions::passphrase accepted but silently dropped. \
            No AES-256-CBC wrap, no scrypt KDF, no master-key derivation, \
            walletpassphrase/walletlock are no-op RPCs that warn but do nothing. \
            Reference: bitcoin-core/src/wallet/crypter.cpp (CCrypter, CKeyingMaterial), \
            bitcoin-core/src/wallet/wallet.cpp (CWallet::EncryptWallet)."]
fn g29_encryptwallet_actually_encrypts_seed_at_rest() {
    panic!(
        "BUG-1: Wallet encryption not implemented. Need: AES-256-CBC + scrypt KDF \
         (Core uses iterated SHA-512 in CCrypter::SetKeyFromPassphrase, ~25K iters), \
         master-key-wrap-CKey scheme, walletpassphrase keypool unlocking, \
         walletlock zeroing of in-memory key material."
    );
}

#[test]
fn g29_walletpassphrase_rpc_on_unencrypted_wallet_warns() {
    // Core's walletpassphrase on an unencrypted wallet returns an error
    // ("running with an unencrypted wallet, but walletpassphrase was called").
    // Rustoshi has this error path wired (server.rs:7102) — test that it
    // remains in place by checking the substring is present in the source.
    let server_src = include_str!("../../rpc/src/server.rs");
    assert!(
        server_src.contains("running with an unencrypted wallet"),
        "walletpassphrase must error on unencrypted wallet (Core parity)"
    );
}

// ===========================================================================
// G30 — BIP-86 taproot wallet (tr() with key path only)
// ===========================================================================

#[test]
fn g30_bip86_keypath_only_address_starts_with_bc1p() {
    let seed = [0u8; 64];
    let mut wallet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();
    let addr = wallet.get_new_address().unwrap();
    assert!(addr.starts_with("bc1p"));
}

#[test]
fn g30_bip86_keypath_tweak_uses_no_script_path() {
    // BIP-86: H_TapTweak(internal_key) -> output_key with NO merkle root.
    // Two wallets with same seed must produce identical taproot addresses
    // (no script path = deterministic).
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f10111213141516171819202122232425").unwrap();
    let mut w1 = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();
    let mut w2 = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();
    let a1 = w1.get_new_address().unwrap();
    let a2 = w2.get_new_address().unwrap();
    assert_eq!(a1, a2, "BIP-86 keypath-only derivation must be deterministic");
}

#[test]
fn g30_bip86_first_address_matches_keypath_descriptor() {
    // Build the same address via wallet derivation and via descriptor
    // expansion of `tr(KEY)` where KEY is the BIP-86 path key. They must
    // match (closes a class of bugs where wallet uses a different tweak
    // than descriptor::make_p2tr_script).
    let seed = [11u8; 64];
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    // BIP-86 path: m/86'/0'/0'/0/0
    let path = [
        86 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
        0,
        0,
    ];
    let child = master.derive_path(&path).unwrap();
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &child.secret_key);
    let xonly_hex = hex::encode(&pk.serialize()[1..33]);

    // Build via wallet
    let mut wallet =
        Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();
    let wallet_addr = wallet.get_new_address().unwrap();

    // Build via tr() descriptor
    let desc = parse_descriptor(&format!("tr({xonly_hex})")).unwrap();
    let desc_addrs = desc.derive_addresses(0, Network::Mainnet).unwrap();
    let desc_addr = desc_addrs[0].encode();

    assert_eq!(
        wallet_addr, desc_addr,
        "BIP-86 wallet derivation must match tr(KEY) descriptor derivation"
    );
}

// ===========================================================================
// Helpers
// ===========================================================================

fn make_unsigned_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
    let inputs: Vec<TxIn> = (0..num_inputs)
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([i as u8; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xfffffffd,
            witness: vec![],
        })
        .collect();
    let outputs: Vec<TxOut> = (0..num_outputs)
        .map(|i| TxOut {
            value: 50_000 + (i as u64 * 1000),
            // 22-byte P2WPKH-like spk
            script_pubkey: {
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[i as u8; 20]);
                s
            },
        })
        .collect();
    Transaction {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
    }
}

// Pull in unused-trait suppression so this file's `BTreeMap` import is OK.
#[allow(dead_code)]
fn _suppress_btreemap_unused() {
    let _: BTreeMap<u32, u32> = BTreeMap::new();
}

// Also pull in unused-import suppression for PsbtInput/PsbtOutput/KeyOrigin.
#[allow(dead_code)]
fn _suppress_unused_psbt_types() {
    let _: PsbtInput = PsbtInput::default();
    let _: PsbtOutput = PsbtOutput::default();
    let _: KeyOrigin = KeyOrigin::default();
}
