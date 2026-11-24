//! Neon audit (2026-11-24) script findings 1-4, checked against Bitcoin Core
//! v31.1 `src/script/interpreter.cpp` and `src/pubkey.cpp`.
//!
//! Every non-control test here fails on rustoshi master 93365362 and passes
//! with the fix. Controls pin the behaviour that must NOT change.
//!
//! * F1 (consensus): Core `VerifyScript` evaluates a P2SH redeemScript and
//!   requires a true top element (interpreter.cpp:2070-2076) BEFORE it looks
//!   for a P2SH witness program (:2078). rustoshi took the witness branch
//!   first, so a redeemScript `OP_1 <0x0000>` (an upgradable witness program
//!   whose program bytes cast to false) with an empty witness was spendable
//!   under block flags. Core rejects it (EVAL_FALSE).
//! * F2 (policy): Core's CHECKMULTISIG loop (:1153-1180) runs
//!   CheckPubKeyEncoding on every key it reaches even when the signature is
//!   empty. rustoshi broke out of the loop on an empty signature and skipped
//!   STRICTENC / WITNESS_PUBKEYTYPE.
//! * F3 (interpreter flags): with CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY
//!   not enabled, Core treats the opcodes as NOP2 / NOP3 and never consults
//!   DISCOURAGE_UPGRADABLE_NOPS (:522-526, :561-565, :596-600).
//! * F4 (LOW_S without NULLFAIL): Core's CheckLowS (pubkey.cpp:424-430) uses
//!   ecdsa_signature_parse_der_lax, which zeroes a signature whose R or S is
//!   >= the curve order (pubkey.cpp:155-181); the zeroed signature counts as
//!   low-S.

use rustoshi_consensus::script::{verify_script, DummyChecker, ScriptError, ScriptFlags};
use rustoshi_crypto::hashes::{hash160, sha256};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_NOT: u8 = 0x91;
const OP_EQUAL: u8 = 0x87;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_CLTV: u8 = 0xb1;
const OP_CSV: u8 = 0xb2;
const OP_NOP4: u8 = 0xb3;

/// Block-consensus flags (Core GetBlockScriptFlags after taproot):
/// P2SH | DERSIG | CLTV | CSV | WITNESS | NULLDUMMY | TAPROOT.
fn block_flags() -> ScriptFlags {
    ScriptFlags {
        verify_p2sh: true,
        verify_dersig: true,
        verify_checklocktimeverify: true,
        verify_checksequenceverify: true,
        verify_witness: true,
        verify_nulldummy: true,
        verify_taproot: true,
        ..Default::default()
    }
}

fn push(data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 0x4c);
    let mut v = vec![data.len() as u8];
    v.extend_from_slice(data);
    v
}

fn p2sh_spk(redeem: &[u8]) -> Vec<u8> {
    let mut spk = vec![OP_HASH160, 0x14];
    spk.extend_from_slice(hash160(redeem).as_bytes());
    spk.push(OP_EQUAL);
    spk
}

fn p2wsh_spk(witness_script: &[u8]) -> Vec<u8> {
    let mut spk = vec![OP_0, 0x20];
    spk.extend_from_slice(&sha256(witness_script));
    spk
}

/// secp256k1 generator G, uncompressed (valid, but not allowed in witness v0
/// under WITNESS_PUBKEYTYPE).
fn uncompressed_g() -> Vec<u8> {
    hex::decode(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
         483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    )
    .unwrap()
}

/// The same point in hybrid encoding (0x06/0x07 prefix): refused by STRICTENC.
fn hybrid_g() -> Vec<u8> {
    let mut k = uncompressed_g();
    k[0] = 0x06;
    k
}

fn compressed_g() -> Vec<u8> {
    hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
}

fn run(script_sig: &[u8], spk: &[u8], witness: &[Vec<u8>], flags: &ScriptFlags) -> Result<(), ScriptError> {
    verify_script(script_sig, spk, witness, flags, &DummyChecker)
}

// ---------------------------------------------------------------------------
// F1: P2SH-wrapped witness program whose program casts to false
// ---------------------------------------------------------------------------

fn p2sh_witness_case(redeem: &[u8]) -> Result<(), ScriptError> {
    // scriptSig is exactly the canonical single push of the redeemScript, so
    // the WITNESS_MALLEATED_P2SH check cannot be what refuses it.
    let script_sig = push(redeem);
    run(&script_sig, &p2sh_spk(redeem), &[], &block_flags())
}

#[test]
fn neon_f1_p2sh_witness_program_zero_program_is_eval_false_under_block_flags() {
    // OP_1 PUSHBYTES_2 0x0000: Core EvalScript leaves [0x01, 0x0000];
    // CastToBool(0x0000) == false -> EVAL_FALSE.
    let r = p2sh_witness_case(&[OP_1, 0x02, 0x00, 0x00]);
    assert!(r.is_err(), "Core rejects (EVAL_FALSE); rustoshi returned {r:?}");
}

#[test]
fn neon_f1_p2sh_witness_program_negative_zero_program_is_eval_false() {
    // 0x0080 is negative zero: CastToBool == false.
    let r = p2sh_witness_case(&[OP_1, 0x02, 0x00, 0x80]);
    assert!(r.is_err(), "Core rejects (EVAL_FALSE); rustoshi returned {r:?}");
}

#[test]
fn neon_f1_p2sh_witness_v1_32_zero_bytes_is_eval_false() {
    // OP_1 <32 zero bytes>: inside P2SH this is not taproot (BIP-341), so the
    // witness branch would accept it as upgradable; Core never gets there.
    let mut redeem = vec![OP_1, 0x20];
    redeem.extend_from_slice(&[0u8; 32]);
    let r = p2sh_witness_case(&redeem);
    assert!(r.is_err(), "Core rejects (EVAL_FALSE); rustoshi returned {r:?}");
}

#[test]
fn neon_f1_control_p2sh_witness_program_true_program_still_accepted() {
    // Control: a non-zero upgradable P2SH witness program stays spendable
    // under block flags, as in Core (VerifyWitnessProgram returns true).
    assert_eq!(p2sh_witness_case(&[OP_1, 0x02, 0x00, 0x01]), Ok(()));
    assert_eq!(p2sh_witness_case(&[OP_2, 0x02, 0x4e, 0x73]), Ok(()));
}

#[test]
fn neon_f1_control_malleated_p2sh_witness_still_refused() {
    // Control: a non-canonical scriptSig for a true P2SH witness program is
    // still WITNESS_MALLEATED_P2SH (the check now runs after the eval, as in
    // Core).
    let redeem = [OP_1, 0x02, 0x00, 0x01];
    let mut script_sig = vec![0x4c, redeem.len() as u8]; // OP_PUSHDATA1
    script_sig.extend_from_slice(&redeem);
    assert_eq!(
        run(&script_sig, &p2sh_spk(&redeem), &[], &block_flags()),
        Err(ScriptError::WitnessMalleatedP2SH)
    );
}

// ---------------------------------------------------------------------------
// F2: CHECKMULTISIG with an empty signature still checks pubkey encoding
// ---------------------------------------------------------------------------

#[test]
fn neon_f2_checkmultisig_empty_sig_p2wsh_uncompressed_key_is_witness_pubkeytype() {
    // witnessScript: 1 <uncompressed G> 1 CHECKMULTISIG NOT; witness: "", "".
    let mut ws = vec![OP_1];
    ws.extend(push_long(&uncompressed_g()));
    ws.extend([OP_1, OP_CHECKMULTISIG, OP_NOT]);
    let witness = vec![vec![], vec![], ws.clone()];
    assert_eq!(
        run(&[], &p2wsh_spk(&ws), &witness, &ScriptFlags::standard_flags()),
        Err(ScriptError::WitnessPubkeyType)
    );
}

// Legacy cases put the dummy and the empty signature in the scriptSig, not
// the scriptPubKey: an empty signature push-encodes to 0x00, so an OP_0 in
// the scriptCode would be FindAndDelete'd and CONST_SCRIPTCODE (a standard
// flag) would refuse first, in Core as here.
const EMPTY_SIG_SCRIPTSIG: [u8; 2] = [OP_0, OP_0];

#[test]
fn neon_f2_checkmultisig_empty_sig_hybrid_key_is_pubkeytype_under_strictenc() {
    // scriptSig 0 0; scriptPubKey 1 <hybrid G> 1 CHECKMULTISIG NOT (legacy).
    let mut spk = vec![OP_1];
    spk.extend(push_long(&hybrid_g()));
    spk.extend([OP_1, OP_CHECKMULTISIG, OP_NOT]);
    assert_eq!(
        run(&EMPTY_SIG_SCRIPTSIG, &spk, &[], &ScriptFlags::standard_flags()),
        Err(ScriptError::PubKeyType)
    );
}

#[test]
fn neon_f2_checkmultisig_empty_sig_reaches_second_key() {
    // 1-of-2, keys pushed <hybrid> <compressed>: Core pairs the empty sig
    // with the top key (compressed, fine), fails it, then still has
    // nSigs(1) <= nKeys(1) so pairs it with the hybrid key -> PUBKEYTYPE.
    let mut spk = vec![OP_1];
    spk.extend(push_long(&hybrid_g()));
    spk.extend(push(&compressed_g()));
    spk.extend([OP_2, OP_CHECKMULTISIG, OP_NOT]);
    assert_eq!(
        run(&EMPTY_SIG_SCRIPTSIG, &spk, &[], &ScriptFlags::standard_flags()),
        Err(ScriptError::PubKeyType)
    );
}

#[test]
fn neon_f2_checkmultisigverify_empty_sig_hybrid_key_is_pubkeytype() {
    // CHECKMULTISIGVERIFY fails either way; Core's error is PUBKEYTYPE.
    let mut spk = vec![OP_1];
    spk.extend(push_long(&hybrid_g()));
    spk.extend([OP_1, OP_CHECKMULTISIGVERIFY, OP_1]);
    assert_eq!(
        run(&EMPTY_SIG_SCRIPTSIG, &spk, &[], &ScriptFlags::standard_flags()),
        Err(ScriptError::PubKeyType)
    );
}

#[test]
fn neon_f2_control_empty_sig_valid_key_and_block_flags() {
    // Control: a valid compressed key with an empty sig is a plain failed
    // CHECKMULTISIG (NOT makes it true) under standard flags, and the hybrid
    // key is fine under block flags (no STRICTENC there).
    let mut ok = vec![OP_1];
    ok.extend(push(&compressed_g()));
    ok.extend([OP_1, OP_CHECKMULTISIG, OP_NOT]);
    assert_eq!(
        run(&EMPTY_SIG_SCRIPTSIG, &ok, &[], &ScriptFlags::standard_flags()),
        Ok(())
    );

    let mut hybrid = vec![OP_1];
    hybrid.extend(push_long(&hybrid_g()));
    hybrid.extend([OP_1, OP_CHECKMULTISIG, OP_NOT]);
    assert_eq!(run(&EMPTY_SIG_SCRIPTSIG, &hybrid, &[], &block_flags()), Ok(()));
}

#[test]
fn neon_f2_control_empty_sig_with_op0_in_scriptcode_is_findanddelete() {
    // Control: with the OP_0s inside the scriptPubKey, Core's FindAndDelete
    // of the empty signature (0x00) hits them and CONST_SCRIPTCODE refuses
    // before any pubkey is looked at (interpreter.cpp:1141-1150).
    let mut spk = vec![OP_0, OP_0, OP_1];
    spk.extend(push(&compressed_g()));
    spk.extend([OP_1, OP_CHECKMULTISIG, OP_NOT]);
    assert_eq!(
        run(&[], &spk, &[], &ScriptFlags::standard_flags()),
        Err(ScriptError::SigFindAndDelete)
    );
}

fn push_long(data: &[u8]) -> Vec<u8> {
    // 65-byte keys still fit a direct push (< 0x4c).
    push(data)
}

// ---------------------------------------------------------------------------
// F3: CLTV / CSV not enabled are NOP2 / NOP3, not discouraged NOPs
// ---------------------------------------------------------------------------

fn nops_flags() -> ScriptFlags {
    ScriptFlags {
        verify_discourage_upgradable_nops: true,
        ..Default::default()
    }
}

#[test]
fn neon_f3_cltv_disabled_is_nop2_not_discouraged() {
    assert_eq!(run(&[], &[OP_1, OP_CLTV], &[], &nops_flags()), Ok(()));
}

#[test]
fn neon_f3_csv_disabled_is_nop3_not_discouraged() {
    assert_eq!(run(&[], &[OP_1, OP_CSV], &[], &nops_flags()), Ok(()));
}

#[test]
fn neon_f3_control_nop4_still_discouraged() {
    assert_eq!(
        run(&[], &[OP_1, OP_NOP4], &[], &nops_flags()),
        Err(ScriptError::DiscourageUpgradableNops)
    );
}

// ---------------------------------------------------------------------------
// F4: LOW_S with an R or S that overflows the curve order
// ---------------------------------------------------------------------------

fn der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = vec![0x02, r.len() as u8];
    body.extend_from_slice(r);
    body.push(0x02);
    body.push(s.len() as u8);
    body.extend_from_slice(s);
    let mut sig = vec![0x30, body.len() as u8];
    sig.extend(body);
    sig.push(0x01); // SIGHASH_ALL
    sig
}

fn low_s_flags() -> ScriptFlags {
    // LOW_S without NULLFAIL, so a failing signature is not an error by itself.
    ScriptFlags {
        verify_dersig: true,
        verify_low_s: true,
        ..Default::default()
    }
}

fn checksig_not(sig: &[u8]) -> Result<(), ScriptError> {
    let script_sig = push(sig);
    let mut spk = push(&compressed_g());
    spk.extend([OP_CHECKSIG, OP_NOT]);
    run(&script_sig, &spk, &[], &low_s_flags())
}

fn order_plus(delta: u8) -> Vec<u8> {
    // 0x00 || N + delta (33 bytes, DER-positive). delta < 0xbf, no carry.
    let mut n = hex::decode("00fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    n[32] += delta;
    n
}

#[test]
fn neon_f4_low_s_accepts_s_at_or_above_order() {
    // S = N: parse_der_lax overflows -> (0,0) -> CheckLowS true.
    let r = checksig_not(&der_sig(&[0x01], &order_plus(0)));
    assert_eq!(r, Ok(()), "Core: LOW_S passes, sig fails, NOT -> true");
    let mut all_ff = vec![0x00];
    all_ff.extend([0xffu8; 32]);
    assert_eq!(checksig_not(&der_sig(&[0x01], &all_ff)), Ok(()));
}

#[test]
fn neon_f4_low_s_accepts_high_s_when_r_overflows() {
    // R = 0x00||ff*32 (>= N), S = 2^255 (between N/2 and N).
    let mut r = vec![0x00];
    r.extend([0xffu8; 32]);
    let mut s = vec![0x00, 0x80];
    s.extend([0u8; 31]);
    assert_eq!(checksig_not(&der_sig(&r, &s)), Ok(()));
}

#[test]
fn neon_f4_control_high_s_below_order_still_refused() {
    // S = N - 1 (high, valid scalar), R small: SIG_HIGH_S in Core and here.
    let mut s = order_plus(0);
    s[32] -= 1;
    assert_eq!(checksig_not(&der_sig(&[0x01], &s)), Err(ScriptError::SigHighS));
    // S = 2^255 with a valid R: still high.
    let mut s2 = vec![0x00, 0x80];
    s2.extend([0u8; 31]);
    assert_eq!(checksig_not(&der_sig(&[0x01], &s2)), Err(ScriptError::SigHighS));
}

#[test]
fn neon_f4_control_low_s_accepted() {
    assert_eq!(checksig_not(&der_sig(&[0x01], &[0x01])), Ok(()));
}
