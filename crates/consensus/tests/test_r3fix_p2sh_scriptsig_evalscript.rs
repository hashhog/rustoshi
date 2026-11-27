//! r3fix-rustoshi-p2sh-scriptsig-evalscript: the P2SH redeemScript is the top of
//! the stack that `EvalScript(scriptSig, SCRIPT_VERIFY_NONE)` leaves, in both
//! `AreInputsStandard` and `IsWitnessStandard`.
//!
//! Core v31.1 `src/policy/policy.cpp`:
//! - `AreInputsStandard` (SCRIPTHASH arm): `EvalScript(stack, scriptSig,
//!   SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE)` must succeed
//!   and leave a non-empty stack, else the input is nonstandard
//!   (`bad-txns-nonstandard-inputs`); then `GetSigOpCount(true)` of
//!   `stack.back()` must be `<= MAX_P2SH_SIGOPS` (15).
//! - `IsWitnessStandard`: the same unwrap for a P2SH prevout; failure or an
//!   empty stack is nonstandard (`bad-witness-nonstandard`).
//!
//! Before the fix rustoshi took the redeemScript from a hand-rolled push walker
//! that (a) ignored the 520-byte `MAX_SCRIPT_ELEMENT_SIZE` push limit and
//! (b) returned `None` on `OP_1NEGATE` and `OP_1..OP_16`, which `IsPushOnly`
//! accepts and EvalScript pushes. The sigop gate treated `None` (and an empty
//! scriptSig) as "leave the check unenforced", so `OP_1 <redeem with 16
//! sigops>` got into the mempool.
//!
//! The `r3_*` cases are the stored examples of the R3 generating fuzzer's
//! rustoshi rows for this group (night 1, seed 739943, Core v31.1,
//! `tools/diff-fuzz/gen-baselines/rustoshi.json`). Each prevout is a
//! 100,000-sat coin; the expected answer is Core v31.1's recorded `core_msg`.

use rustoshi_consensus::mempool::{Mempool, MempoolConfig, MempoolError};
use rustoshi_consensus::CoinEntry;
use rustoshi_crypto::hashes::{hash160, sha256};
use rustoshi_primitives::{Decodable, Hash256, OutPoint, Transaction, TxIn, TxOut};

const FUND_VALUE: u64 = 100_000;

const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;

fn decode_tx(h: &str) -> Transaction {
    Transaction::deserialize(&hex::decode(h).unwrap()).unwrap()
}

fn p2sh_spk(redeem: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa9, 0x14];
    v.extend_from_slice(&hash160(redeem).0);
    v.push(0x87);
    v
}

/// Minimal direct push (`redeem.len() <= 75`).
fn push(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 75);
    let mut v = vec![data.len() as u8];
    v.extend_from_slice(data);
    v
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

/// One-input, one-output spend of a P2SH coin with the given scriptSig and an
/// empty witness. The output is the gen-fuzz P2WSH output (97,000 sat).
fn p2sh_spend(script_sig: Vec<u8>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_hex(
                    "5e06412f90048245b4024a7c1db5e32b1f700d14c5d3441a58570404828042ee",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig,
            sequence: 0xffff_fffe,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 97_000,
            script_pubkey: hex::decode(
                "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
            )
            .unwrap(),
        }],
        lock_time: 0,
    }
}

/// `OP_0 OP_IF OP_CHECKSIG x n OP_ENDIF` (+ `OP_1` when `trailing_true`).
/// The CHECKSIGs are never executed, but `GetSigOpCount(true)` counts all `n`.
fn dead_checksig_redeem(n: usize, trailing_true: bool) -> Vec<u8> {
    let mut v = vec![OP_0, OP_IF];
    v.extend(std::iter::repeat(OP_CHECKSIG).take(n));
    v.push(OP_ENDIF);
    if trailing_true {
        v.push(OP_1);
    }
    v
}

fn assert_inputs_nonstandard(res: Result<(), MempoolError>, what: &str) {
    match res {
        Err(MempoolError::InputsNonStandard(0)) => {}
        other => panic!(
            "{what}: Core v31.1 refuses `bad-txns-nonstandard-inputs` \
             (AreInputsStandard), rustoshi said {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// The two gen-fuzz rows of this group (stored examples, Core v31.1 answers)
// ---------------------------------------------------------------------------

/// R13 `mempool/reason/script-policy/WITNESS_MALLEATED_P2SH|nonstandard`, the
/// minimised case: p2sh-p2wsh, scriptSig `OP_1 <0020 sha256("")>`, witness
/// `[<empty script>]`. Core unwraps the redeemScript (OP_1 is a push), passes
/// IsWitnessStandard, and fails the script check with WITNESS_MALLEATED_P2SH.
const R13_TX: &str = "0200000000010182ba839b6731f1d1b2c75d8a1b01acc82276691c0db49a0fabf66ff416500ed9000000002451220020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260010000000000";

#[test]
fn r3_r13_op1_prefixed_p2sh_p2wsh_is_witness_malleated_p2sh() {
    let mut program = vec![0x00, 0x20];
    program.extend_from_slice(&sha256(&[]));
    let spk = p2sh_spk(&program);
    const CORE: &str =
        "mempool-script-verify-flag-failed (Witness requires only-redeemscript scriptSig)";
    match submit(decode_tx(R13_TX), spk) {
        Err(MempoolError::PolicyScriptCheckFailed(0, msg)) => {
            assert!(msg.starts_with(CORE), "want Core's `{CORE}`, got `{msg}`")
        }
        other => panic!("want Core's `{CORE}` (PolicyScriptChecks), got {other:?}"),
    }
}

/// R7 `mempool/reason/nonstandard|script-policy/PUSH_SIZE`: a P2SH scriptSig
/// that is one PUSHDATA2 of a 521-byte redeemScript. Core's EvalScript fails
/// PUSH_SIZE inside AreInputsStandard, so the input is nonstandard; rustoshi went
/// on to the script check and reported PUSH_SIZE.
const R7_TX: &str = "02000000019e4d8082040457581a44d3c5140d701f2be3b51d7c4a02b4458204902f41065e00000000fd0c024d0902ab5b5b5b5b5b5b52572929292987878787878787878730878787000000000000000000000000000000000000000000a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a904f2a1abfc610000585858585858585858585858585858587a7a7a7a7a7a7a7a7a7a4c4c4c4c4c4c4cb44c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c0000000000000000010000a3a6a6a6a6a6a6a6a6a6a6a6ffffffffffffffffffffffffffffffffffffffffffffa6a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000292929292929292929292929292929292929292929298787877f01000000000000878787878787308787a9a9a9a9a95ba904f2a1abfc610000585858585858585858585858585858587a7a7a7a7a7a7a7a7a7a4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c010000a3a6a6a6a6ffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaa7fff00b3aaaaaaaaa7a7a7a7a7a7a7a7a7a7a7a708000000005d5d009ca7a7a7a7a7000000a7000000a7a7a7a7a7a7a7a7a7595358585858582929292929292929292929292929282929222222222222222222222222222222222222222222222222a9a9a9a9a9a9a9a9a9005200524fa1a9a9a9a9a9ffffffffffffffffa5ffffffffffffffa9a9a9a9a9a9a9a9a9a9a9a9a9a956feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";

#[test]
fn r3_r7_p2sh_scriptsig_push_over_520_is_inputs_nonstandard() {
    let tx = decode_tx(R7_TX);
    let ss = &tx.inputs[0].script_sig;
    // scriptSig = OP_PUSHDATA2 <0x0209 = 521> <redeemScript>.
    assert_eq!(&ss[..3], &[0x4d, 0x09, 0x02]);
    let redeem = ss[3..].to_vec();
    assert_eq!(redeem.len(), 521);
    assert_inputs_nonstandard(submit(tx, p2sh_spk(&redeem)), "R7 521-byte push");
}

// ---------------------------------------------------------------------------
// The accept hole the triage predicted from the code, plus controls
// ---------------------------------------------------------------------------

/// `<small-int push> <0 IF CHECKSIG x16 ENDIF>`: consensus-valid (the redeem
/// leaves the pushed number, true, as the single stack item), but the redeem
/// has 16 > MAX_P2SH_SIGOPS sigops, so Core refuses it as nonstandard. Before
/// the fix rustoshi's walker returned None on the small-int opcode and the
/// sigop gate was skipped: the tx was ACCEPTED into the mempool.
#[test]
fn hole_op1_prefixed_p2sh_with_16_sigops_is_inputs_nonstandard() {
    for (name, prefix) in [("OP_1", OP_1), ("OP_16", OP_16), ("OP_1NEGATE", OP_1NEGATE)] {
        let redeem = dead_checksig_redeem(16, false);
        let mut ss = vec![prefix];
        ss.extend(push(&redeem));
        assert_inputs_nonstandard(
            submit(p2sh_spend(ss), p2sh_spk(&redeem)),
            &format!("{name} <16-sigop redeem>"),
        );
    }
}

/// Control: the same 15-sigop redeem behind `OP_1` is at the limit, not over
/// it. Core accepts; the fix must not over-refuse.
#[test]
fn control_op1_prefixed_p2sh_with_15_sigops_is_accepted() {
    let redeem = dead_checksig_redeem(15, false);
    let mut ss = vec![OP_1];
    ss.extend(push(&redeem));
    let res = submit(p2sh_spend(ss), p2sh_spk(&redeem));
    assert!(res.is_ok(), "Core v31.1 accepts this spend; rustoshi said {res:?}");
}

/// Control: a 16-sigop redeem in a data-push-only scriptSig was already refused
/// before the fix (the walker handled this shape). Pins that the gate still
/// fires on the shape it always covered.
#[test]
fn control_plain_push_p2sh_with_16_sigops_is_inputs_nonstandard() {
    let redeem = dead_checksig_redeem(16, true);
    assert_inputs_nonstandard(
        submit(p2sh_spend(push(&redeem)), p2sh_spk(&redeem)),
        "<16-sigop redeem>",
    );
}

/// An empty scriptSig on a P2SH coin. Core: EvalScript succeeds with an empty
/// stack -> `bad-txns-nonstandard-inputs` ("P2SH redeemscript missing"). Before
/// the fix the sigop gate skipped it and the script check refused it instead
/// (INVALID_STACK_OPERATION).
#[test]
fn empty_p2sh_scriptsig_is_inputs_nonstandard() {
    let redeem = dead_checksig_redeem(0, true);
    assert_inputs_nonstandard(
        submit(p2sh_spend(vec![]), p2sh_spk(&redeem)),
        "empty scriptSig",
    );
}
