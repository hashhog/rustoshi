//! r3fix-rustoshi-p2pk-standard: bare pay-to-pubkey is a standard script type.
//!
//! Core v31.1:
//! - `script/solver.cpp` `MatchPayToPubkey` matches `<33 or 65-byte push>
//!   OP_CHECKSIG` when the key passes `CPubKey::ValidSize` (`pubkey.h`
//!   `GetLen`: header 0x02/0x03 for 33 bytes, 0x04/0x06/0x07 for 65 bytes), and
//!   `Solver` then returns `TxoutType::PUBKEY`.
//! - `policy/policy.cpp` `AreInputsStandard` refuses only `NONSTANDARD` and
//!   `WITNESS_UNKNOWN` prevouts, so a P2PK prevout passes the input gate and the
//!   spend goes on to `PolicyScriptChecks`.
//! - `policy/policy.cpp` `IsStandard` accepts a `PUBKEY` output.
//!
//! Before the fix rustoshi's classifier had no P2PK arm: every bare P2PK prevout
//! was refused `bad-txns-nonstandard-inputs` and every P2PK output `scriptpubkey`.
//!
//! The six `r3_*` cases are the stored examples of the R3 generating fuzzer's
//! rustoshi rows for this group (night 1, seed 739943, Core v31.1,
//! `tools/diff-fuzz/gen-baselines/rustoshi.json`). Each prevout is a 100,000-sat
//! bare script built from the row's case; `<pk>` there is the key of privkey 1.
//! The expected answer is Core v31.1's recorded `core_msg` for that row.

use rustoshi_consensus::mempool::{dust_threshold, Mempool, MempoolConfig, MempoolError};
use rustoshi_consensus::CoinEntry;
use rustoshi_crypto::legacy_sighash;
use rustoshi_primitives::{Decodable, OutPoint, Transaction, TxIn, TxOut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

const FUND_VALUE: u64 = 100_000;
const SIGHASH_ALL: u32 = 1;

/// Compressed key of privkey 1 (the generator point G).
const G_COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn p2pk(key_hex: &str) -> Vec<u8> {
    let key = hex::decode(key_hex).unwrap();
    let mut v = vec![key.len() as u8];
    v.extend_from_slice(&key);
    v.push(0xac);
    v
}

fn decode_tx(h: &str) -> Transaction {
    Transaction::deserialize(&hex::decode(h).unwrap()).unwrap()
}

fn production_pool() -> Mempool {
    let mut mp = Mempool::new(MempoolConfig::production());
    mp.notify_new_tip(1_000, 1_700_000_000);
    mp
}

/// Submit `tx` to a production mempool (standardness and script checks on)
/// with every input funded by a `FUND_VALUE` coin locked by `prevout_spk`.
fn submit(tx: Transaction, prevout_spk: Vec<u8>) -> Result<(), MempoolError> {
    let mut mp = production_pool();
    let lookup = move |_op: &OutPoint| {
        Some(CoinEntry {
            height: 500,
            is_coinbase: false,
            value: FUND_VALUE,
            script_pubkey: prevout_spk.clone(),
        })
    };
    mp.add_transaction(tx, &lookup).map(|_| ())
}

fn assert_core_script_reject(res: Result<(), MempoolError>, core_msg: &str) {
    match res {
        Err(MempoolError::PolicyScriptCheckFailed(0, msg)) => assert!(
            msg.starts_with(core_msg),
            "want Core's `{core_msg}`, got `{msg}`"
        ),
        other => panic!("want Core's `{core_msg}` (PolicyScriptChecks), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The six gen-fuzz rows of this group (stored examples, Core v31.1 answers)
// ---------------------------------------------------------------------------

/// R29 `mempool/verdict/accept|nonstandard`, the minimised case:
/// bare `<pk> CHECKSIG` spent with a valid low-S SIGHASH_ALL signature.
/// Core: `allowed`.
const R29_TX: &str = "0200000001977a612b8f69f25bc97da39964cc6ef5ff2f69220ea0af442c5e137b8dea920c0000000049483045022100d1c911ab77a52a9104dcf84d11161803ff1e0c92593d0ee1657f6f88f0c9a15f0220435a577e2d62ca84be8b09ba79548828bacc7df0481a6a587161927bf805dcb001feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";

#[test]
fn r3_r29_minimised_bare_p2pk_spend_is_accepted() {
    let res = submit(decode_tx(R29_TX), p2pk(G_COMPRESSED));
    assert!(
        res.is_ok(),
        "Core v31.1 accepts this spend; rustoshi said {res:?}"
    );
}

/// R9 `mempool/reason/script-policy/SIG_DER|nonstandard`: scriptSig `OP_1`.
#[test]
fn r3_r9_p2pk_non_der_sig_is_script_sig_der() {
    let tx = decode_tx("0200000001dca82a338215328e456af023e20b8196d67733d702777e369f58022257a4a8f9000000000151feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000");
    let spk = p2pk("038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508");
    assert_core_script_reject(
        submit(tx, spk),
        "mempool-script-verify-flag-failed (Non-canonical DER signature)",
    );
}

/// R11 `mempool/reason/script-policy/SIG_HASHTYPE|nonstandard`: hashtype 4.
#[test]
fn r3_r11_p2pk_undefined_hashtype_is_script_sig_hashtype() {
    let tx = decode_tx("0200000001fe971270b0c665e874af288a48217deb2aadbcb5a2ce1a4f2e329a96ff95d952000000004847304402206d0224f028a33927d75d2750aa869011b970d13ff99dfd42bccac5157c95d4f6022023b390dacc4700ea614715e2eefd52384c16dfbe582b9076f05b4843f765074d04feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000");
    assert_core_script_reject(
        submit(tx, p2pk(G_COMPRESSED)),
        "mempool-script-verify-flag-failed (Signature hash type missing or not understood)",
    );
}

/// R18 `mempool/reason/script-policy/SIG_NULLFAIL|nonstandard`: uncompressed key,
/// signature that does not verify.
#[test]
fn r3_r18_uncompressed_p2pk_failed_sig_is_script_sig_nullfail() {
    let tx = decode_tx("0200000001cd6ac72078e2883d728d28b74edea9ba478099a2709cc48566acb87e235492c1000000004847304402204710a85181663b32d25c70ec2bbd14adff5ddfff6cb50d09e155ef5f541fc86c0220056b0cc949be9386ecc5f6c2ac0493269031dbb185781db90171b54ac127790281feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000");
    let spk = p2pk("048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf");
    assert_core_script_reject(
        submit(tx, spk),
        "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)",
    );
}

/// R19 `mempool/reason/script-policy/EVAL_FALSE|nonstandard`: scriptSig `OP_0`.
#[test]
fn r3_r19_p2pk_empty_sig_is_script_eval_false() {
    let tx = decode_tx("020000000125f8698cbe16e6dc855efca70a8678d6091794a9194bd7c6355a51e8113e23f9000000000100feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000");
    let spk = p2pk("038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508");
    assert_core_script_reject(
        submit(tx, spk),
        "mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)",
    );
}

/// R20 `mempool/reason/script-policy/PUBKEYTYPE|nonstandard`: a hybrid (0x06)
/// key. `GetLen(0x06) == 65`, so Core's Solver says PUBKEY and the input gate
/// passes; STRICTENC then refuses the key in the script check.
#[test]
fn r3_r20_hybrid_p2pk_is_standard_input_then_script_pubkeytype() {
    let tx = decode_tx("0200000001aec736dd72dafbf5b6c639cb7e5b721aa4f1fc772b4487aa3a26de87bca997fc0000000048473044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000");
    let spk = p2pk("0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    assert_core_script_reject(
        submit(tx, spk),
        "mempool-script-verify-flag-failed (Public key is neither compressed or uncompressed)",
    );
}

// ---------------------------------------------------------------------------
// Own-signed controls
// ---------------------------------------------------------------------------

struct Signer {
    sk: SecretKey,
    compressed: [u8; 33],
    uncompressed: [u8; 65],
}

fn signer(seed: u8) -> Signer {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    Signer {
        sk,
        compressed: pk.serialize(),
        uncompressed: pk.serialize_uncompressed(),
    }
}

/// The 65-byte hybrid form of a key: header 0x06 (even y) or 0x07 (odd y).
fn hybrid(s: &Signer) -> Vec<u8> {
    let mut k = s.uncompressed.to_vec();
    k[0] = 0x06 | (k[64] & 1);
    k
}

fn p2pk_bytes(key: &[u8]) -> Vec<u8> {
    let mut v = vec![key.len() as u8];
    v.extend_from_slice(key);
    v.push(0xac);
    v
}

fn p2wpkh_dest() -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0x42; 20]);
    v
}

/// One input spending a bare P2PK coin locked by `prevout_spk`, signed by `s`
/// with SIGHASH_ALL. `corrupt` flips one bit of `r` so the DER encoding stays
/// strict but the signature no longer verifies.
fn p2pk_spend(s: &Signer, prevout_spk: &[u8], outputs: Vec<TxOut>, corrupt: bool) -> Transaction {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: rustoshi_primitives::Hash256::from([0xa7; 32]),
                vout: 3,
            },
            script_sig: vec![],
            sequence: 0xffff_fffe,
            witness: vec![],
        }],
        outputs,
        lock_time: 0,
    };
    let sighash = legacy_sighash(&tx, 0, prevout_spk, SIGHASH_ALL);
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(sighash.as_bytes()).unwrap();
    let mut der = secp.sign_ecdsa(&msg, &s.sk).serialize_der().to_vec();
    if corrupt {
        let rlen = der[3] as usize;
        der[4 + rlen - 1] ^= 0x01;
    }
    der.push(SIGHASH_ALL as u8);
    let mut script_sig = vec![der.len() as u8];
    script_sig.extend_from_slice(&der);
    tx.inputs[0].script_sig = script_sig;
    tx
}

fn pay(script_pubkey: Vec<u8>, value: u64) -> TxOut {
    TxOut {
        value,
        script_pubkey,
    }
}

#[test]
fn compressed_p2pk_spend_is_accepted() {
    let s = signer(0x31);
    let spk = p2pk_bytes(&s.compressed);
    let tx = p2pk_spend(
        &s,
        &spk,
        vec![pay(p2wpkh_dest(), FUND_VALUE - 2_000)],
        false,
    );
    let res = submit(tx, spk);
    assert!(res.is_ok(), "compressed P2PK spend: {res:?}");
}

#[test]
fn uncompressed_p2pk_spend_is_accepted() {
    let s = signer(0x32);
    let spk = p2pk_bytes(&s.uncompressed);
    let tx = p2pk_spend(
        &s,
        &spk,
        vec![pay(p2wpkh_dest(), FUND_VALUE - 2_000)],
        false,
    );
    let res = submit(tx, spk);
    assert!(res.is_ok(), "uncompressed P2PK spend: {res:?}");
}

/// Invalid stays invalid: passing the input gate must not let a P2PK spend
/// whose signature fails into the mempool.
#[test]
fn p2pk_spend_with_failing_signature_is_still_refused_by_script_check() {
    let s = signer(0x33);
    let spk = p2pk_bytes(&s.compressed);
    let tx = p2pk_spend(&s, &spk, vec![pay(p2wpkh_dest(), FUND_VALUE - 2_000)], true);
    assert_core_script_reject(
        submit(tx, spk),
        "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)",
    );
}

/// Shapes Core's `MatchPayToPubkey` does NOT match stay NONSTANDARD prevouts:
/// a key whose header byte does not give `GetLen == size`, a wrong-size push,
/// and the right push followed by an opcode other than OP_CHECKSIG.
#[test]
fn near_p2pk_shapes_stay_nonstandard_inputs() {
    let k33 = |h: u8| {
        let mut k = vec![h];
        k.extend_from_slice(&[0x11; 32]);
        k
    };
    let k65 = |h: u8| {
        let mut k = vec![h];
        k.extend_from_slice(&[0x11; 64]);
        k
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("33-byte key, header 0x04", p2pk_bytes(&k33(0x04))),
        ("33-byte key, header 0x06", p2pk_bytes(&k33(0x06))),
        ("33-byte key, header 0x00", p2pk_bytes(&k33(0x00))),
        ("33-byte key, header 0x05", p2pk_bytes(&k33(0x05))),
        ("65-byte key, header 0x02", p2pk_bytes(&k65(0x02))),
        ("65-byte key, header 0x03", p2pk_bytes(&k65(0x03))),
        ("65-byte key, header 0x05", p2pk_bytes(&k65(0x05))),
        ("65-byte key, header 0x00", p2pk_bytes(&k65(0x00))),
    ];
    // 34-byte push of a 0x02 key + OP_CHECKSIG.
    let mut k34 = vec![0x02];
    k34.extend_from_slice(&[0x11; 33]);
    cases.push(("34-byte push", p2pk_bytes(&k34)));
    // Compressed key followed by OP_CHECKSIGVERIFY / OP_CHECKMULTISIG.
    let mut csv = p2pk_bytes(&k33(0x02));
    *csv.last_mut().unwrap() = 0xad;
    cases.push(("33-byte key + OP_CHECKSIGVERIFY", csv));
    // Compressed key pushed with OP_PUSHDATA1 (Core matches script[0] == 33 only).
    let mut pd1 = vec![0x4c, 0x21];
    pd1.extend_from_slice(&k33(0x02));
    pd1.push(0xac);
    cases.push(("OP_PUSHDATA1 33-byte key + OP_CHECKSIG", pd1));
    // Trailing byte after OP_CHECKSIG.
    let mut trailing = p2pk_bytes(&k33(0x03));
    trailing.push(0x51);
    cases.push(("p2pk + trailing OP_1", trailing));

    for (name, spk) in cases {
        let res = submit(decode_tx(R29_TX), spk);
        assert!(
            matches!(res, Err(MempoolError::InputsNonStandard(0))),
            "{name}: Core's Solver says NONSTANDARD, so bad-txns-nonstandard-inputs; got {res:?}"
        );
    }
}

/// Core `IsStandard` accepts PUBKEY outputs: compressed, uncompressed and hybrid
/// (`ValidSize` accepts 0x06/0x07 headers).
#[test]
fn p2pk_outputs_are_standard() {
    let s = signer(0x34);
    let spk_in = p2pk_bytes(&s.compressed);
    let other = signer(0x35);
    let outputs = vec![
        pay(p2pk_bytes(&other.compressed), 30_000),
        pay(p2pk_bytes(&other.uncompressed), 30_000),
        pay(p2pk_bytes(&hybrid(&other)), 30_000),
    ];
    let tx = p2pk_spend(&s, &spk_in, outputs, false);
    let res = submit(tx, spk_in);
    assert!(res.is_ok(), "tx creating P2PK outputs: {res:?}");
}

/// A P2PK-looking output whose key header fails `ValidSize` is still NONSTANDARD:
/// `scriptpubkey`.
#[test]
fn p2pk_output_with_bad_key_header_is_nonstandard_scriptpubkey() {
    let s = signer(0x36);
    let spk_in = p2pk_bytes(&s.compressed);
    let mut bad = vec![0x04];
    bad.extend_from_slice(&[0x22; 32]);
    let tx = p2pk_spend(&s, &spk_in, vec![pay(p2pk_bytes(&bad), 90_000)], false);
    match submit(tx, spk_in) {
        Err(MempoolError::NonStandard(r)) => {
            assert!(r.starts_with("scriptpubkey"), "want scriptpubkey, got {r}")
        }
        other => panic!("want NonStandard(scriptpubkey), got {other:?}"),
    }
}

/// Core `GetDustThreshold` for a non-witness output: (8 + 1 + len + 148) bytes at
/// 3000 sat/kvB. 35-byte P2PK → 576 sat, 67-byte P2PK → 672 sat.
#[test]
fn p2pk_dust_thresholds_match_core() {
    let s = signer(0x37);
    assert_eq!(
        dust_threshold(&pay(p2pk_bytes(&s.compressed), 0), 3_000),
        576
    );
    assert_eq!(
        dust_threshold(&pay(p2pk_bytes(&s.uncompressed), 0), 3_000),
        672
    );
}
