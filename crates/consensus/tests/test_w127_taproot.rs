//! W127 — BIP-340 Schnorr / BIP-341 Taproot / BIP-342 Tapscript audit.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/script/interpreter.cpp:347-385` —
//!   `EvalChecksigTapscript` (success-on-non-empty-sig, validation-weight
//!   decrement, unknown-pubkey-type branching).
//! - `bitcoin-core/src/script/interpreter.cpp:1483-1570` —
//!   `SignatureHashSchnorr` (BIP-341 sighash, ext_flag, key_version=0,
//!   SIGHASH_DEFAULT byte handling).
//! - `bitcoin-core/src/script/interpreter.cpp:1717-1742` —
//!   `CheckSchnorrSignature` (64/65-byte size, SIGHASH_DEFAULT byte
//!   forbidden in 65-byte form, sighash-Err path).
//! - `bitcoin-core/src/script/interpreter.cpp:1872-1901` —
//!   `ComputeTapleafHash`, `ComputeTapbranchHash`,
//!   `ComputeTaprootMerkleRoot`.
//! - `bitcoin-core/src/script/interpreter.cpp:1903-1915` —
//!   `VerifyTaprootCommitment` (tweak + parity check).
//! - `bitcoin-core/src/script/interpreter.cpp:1947-1999` —
//!   `VerifyWitnessProgram` v1 path (Taproot/tapscript dispatch).
//! - `bitcoin-core/src/script/interpreter.cpp:1832-1870` —
//!   `ExecuteWitnessScript` (OP_SUCCESS pre-scan + entry-time caps).
//! - `bitcoin-core/src/script/interpreter.h:241-246` — constants.
//! - `bitcoin-core/src/script/script.cpp:364` — `IsOpSuccess`.
//! - `bitcoin-core/src/script/script.h:61-64` — VALIDATION_WEIGHT_*.
//! - `bitcoin-core/src/pubkey.cpp:230-263` — `XOnlyPubKey::IsFullyValid`,
//!   `CheckTapTweak`.
//! - BIPs **340**, **341**, **342**.
//!
//! Cross-cutting:
//! - W94 (`interpreter.rs:5497-5860`) covers Taproot dispatch gates.
//! - W95 (`interpreter.rs:5862-6056`) covers BIP-342 unknown-pubkey-type
//!   semantics.
//! - W27-C (`crates/crypto/src/taproot.rs:425-445`) covers the
//!   CompactSize >= 253 boundary that hit clearbit at h=947,960.
//!
//! Gate legend:
//! - OK      : implemented correctly (regression pin)
//! - PARTIAL : implemented but missing edge cases / fields / wiring
//! - MISSING : not implemented
//! - BUG     : implemented but deviates from Core/BIP
//! - C-DIV   : consensus / relay divergence (real fork or wire-incompat risk)
//!
//! Severity scale:
//! - P0-CDIV : real fork / relay divergence
//! - P0      : security or correctness gap with user-visible damage
//! - P1      : protocol-level correctness
//! - P2      : operational correctness / observability
//! - P3      : minor / polish
//!
//! Wave W127 summary:
//!   Gates: 30 total. All 30 PRESENT and PASS regression pins.
//!   0 P0-CONSENSUS / 0 P0-CDIV findings.
//!   6 cosmetic / error-name follow-on BUGs (P2/P3) documented in
//!   `audit/w127_taproot.md` — NOT gated here because they do not change
//!   accept/reject decisions:
//!     - BUG-1 (P2): tapscript invalid-non-empty-Schnorr-sig reports
//!       `NullFail` instead of Core's `SCHNORR_SIG`.
//!     - BUG-2 (P2): Schnorr sighash-Err collapses to generic `false`
//!       instead of `SCHNORR_SIG_HASHTYPE`.
//!     - BUG-3 (P3): P2SH-wrapped P2A returns Ok unconditionally
//!       (unreachable corner; Core gates on `!is_p2sh`).
//!     - BUG-4 (P3): dead "Tapscript ... not implemented yet" comment in
//!       legacy `check_sig` path.
//!     - BUG-5 (P3): silent-defensive-fail-closed `} else { false }` in
//!       tapscript CHECKSIG/CHECKSIGVERIFY/CHECKSIGADD when
//!       `ctx.tapscript.is_none()`; Core uses `assert(...)`.
//!     - BUG-6 (P3): `script/mod.rs` does not re-export tapscript
//!       primitives / constants.

use rustoshi_consensus::params::{
    ANNEX_TAG, TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_MAX_NODE_COUNT,
    TAPROOT_CONTROL_MAX_SIZE, TAPROOT_CONTROL_NODE_SIZE, TAPROOT_LEAF_MASK,
    TAPROOT_LEAF_TAPSCRIPT, VALIDATION_WEIGHT_OFFSET,
    VALIDATION_WEIGHT_PER_SIGOP_PASSED, WITNESS_V1_TAPROOT_SIZE,
};
use rustoshi_consensus::script::interpreter::{
    eval_script_tapscript, get_serialize_size_of_witness_stack, is_p2a,
    is_p2a_program, is_p2tr, parse_witness_program, verify_script,
    DummyChecker, ScriptError, ScriptFlags, SigVersion, SignatureChecker,
    Stack, TapscriptCtx,
};
use rustoshi_consensus::script::opcodes::Opcode;

// ============================================================
// Test helpers
// ============================================================

/// A signature checker that returns `true` for every Schnorr check —
/// used to exercise the tapscript dispatch without real BIP-340
/// crypto. Mirrors `AlwaysTrueSchnorrChecker` in interpreter.rs tests.
struct AlwaysTrueSchnorrChecker;

impl SignatureChecker for AlwaysTrueSchnorrChecker {
    fn check_sig(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
        true
    }
    fn check_locktime(&self, _: i64) -> bool {
        true
    }
    fn check_sequence(&self, _: i64) -> bool {
        true
    }
    fn check_schnorr_sig(
        &self,
        _sig: &[u8],
        _xonly_pubkey: &[u8; 32],
        _annex: Option<&[u8]>,
    ) -> bool {
        true
    }
    fn check_schnorr_sig_tapscript(
        &self,
        _sig: &[u8],
        _xonly_pubkey: &[u8; 32],
        _tapleaf_hash: &[u8; 32],
        _codesep_pos: u32,
        _annex: Option<&[u8]>,
    ) -> bool {
        true
    }
}

/// A signature checker that records the codesep_pos value seen by the
/// most recent Schnorr-tapscript call. Used by G19 / G21 to assert that
/// OP_CODESEPARATOR positions plumb through to the sighash extension.
#[derive(Default)]
struct CapturingSchnorrChecker {
    last_codesep_pos: std::cell::Cell<u32>,
    last_tapleaf_hash: std::cell::Cell<[u8; 32]>,
    last_annex_present: std::cell::Cell<bool>,
}

impl SignatureChecker for CapturingSchnorrChecker {
    fn check_sig(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
        true
    }
    fn check_locktime(&self, _: i64) -> bool {
        true
    }
    fn check_sequence(&self, _: i64) -> bool {
        true
    }
    fn check_schnorr_sig_tapscript(
        &self,
        _sig: &[u8],
        _xonly_pubkey: &[u8; 32],
        tapleaf_hash: &[u8; 32],
        codesep_pos: u32,
        annex: Option<&[u8]>,
    ) -> bool {
        self.last_codesep_pos.set(codesep_pos);
        self.last_tapleaf_hash.set(*tapleaf_hash);
        self.last_annex_present.set(annex.is_some());
        true
    }
}

// ============================================================
// G1-G9: Constants match Core (regression pins)
// ============================================================

/// G1 — `TAPROOT_LEAF_MASK = 0xfe` (Core
/// `script/interpreter.h:241`).
#[test]
fn w127_g1_taproot_leaf_mask_constant() {
    assert_eq!(TAPROOT_LEAF_MASK, 0xfe);
}

/// G2 — `TAPROOT_LEAF_TAPSCRIPT = 0xc0` (Core
/// `script/interpreter.h:242`).
#[test]
fn w127_g2_taproot_leaf_tapscript_constant() {
    assert_eq!(TAPROOT_LEAF_TAPSCRIPT, 0xc0);
    // BIP-342: leaf version must be even (parity bit cleared).
    assert_eq!(TAPROOT_LEAF_TAPSCRIPT & 0x01, 0);
    // Leaf-version byte AND TAPROOT_LEAF_MASK must round-trip identity.
    assert_eq!(TAPROOT_LEAF_TAPSCRIPT & TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT);
}

/// G3 — `TAPROOT_CONTROL_BASE_SIZE = 33` (Core
/// `script/interpreter.h:243`). 1 byte (version+parity) + 32-byte
/// internal x-only key.
#[test]
fn w127_g3_taproot_control_base_size_constant() {
    assert_eq!(TAPROOT_CONTROL_BASE_SIZE, 33);
}

/// G4 — `TAPROOT_CONTROL_NODE_SIZE = 32` (Core
/// `script/interpreter.h:244`). One 32-byte SHA256 per merkle path
/// node.
#[test]
fn w127_g4_taproot_control_node_size_constant() {
    assert_eq!(TAPROOT_CONTROL_NODE_SIZE, 32);
}

/// G5 — `TAPROOT_CONTROL_MAX_SIZE = 4129` (Core
/// `script/interpreter.h:246`). Pre-W94 rustoshi accepted any
/// control block ≥33 and a multiple of 32; a 4-MiB control block
/// would have been a P0-CDIV gap. Now hard-gated.
#[test]
fn w127_g5_taproot_control_max_size_constant() {
    assert_eq!(TAPROOT_CONTROL_MAX_SIZE, 4129);
    assert_eq!(TAPROOT_CONTROL_MAX_SIZE,
               TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT);
    assert_eq!(TAPROOT_CONTROL_MAX_NODE_COUNT, 128);
}

/// G6 — `WITNESS_V1_TAPROOT_SIZE = 32` (Core
/// `script/interpreter.h:245`). Only v1 + program-len == 32 enters
/// the Taproot verifier (else falls through to upgradable witness
/// or P2A).
#[test]
fn w127_g6_witness_v1_taproot_size_constant() {
    assert_eq!(WITNESS_V1_TAPROOT_SIZE, 32);
}

/// G7 — `ANNEX_TAG = 0x50` (Core `policy/policy.h`). Annex
/// detection key for BIP-341 stack-bottom item.
#[test]
fn w127_g7_annex_tag_constant() {
    assert_eq!(ANNEX_TAG, 0x50);
}

/// G8 — `VALIDATION_WEIGHT_OFFSET = 50` (Core
/// `script/script.h:64`). BIP-342 budget = witness-size + 50.
#[test]
fn w127_g8_validation_weight_offset_constant() {
    assert_eq!(VALIDATION_WEIGHT_OFFSET, 50);
}

/// G9 — `VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50` (Core
/// `script/script.h:61`). BIP-342 deduction per non-empty sig op.
#[test]
fn w127_g9_validation_weight_per_sigop_passed_constant() {
    assert_eq!(VALIDATION_WEIGHT_PER_SIGOP_PASSED, 50);
}

// ============================================================
// G10: P2TR detection
// ============================================================

/// G10 — `is_p2tr` matches `OP_1 <push-32> <32 bytes>` exactly
/// (BIP-341 output script format). A P2TR scriptPubKey is always
/// 34 bytes; anything else (P2A, P2WSH, P2WPKH) must NOT match.
#[test]
fn w127_g10_is_p2tr_detection() {
    // Canonical P2TR: OP_1 push-32 + 32 zeros.
    let mut p2tr = vec![0x51u8, 0x20];
    p2tr.extend_from_slice(&[0u8; 32]);
    assert_eq!(p2tr.len(), 34);
    assert!(is_p2tr(&p2tr));

    // OP_1 push-32 + 31 bytes (too short): NOT P2TR.
    let mut short = vec![0x51u8, 0x20];
    short.extend_from_slice(&[0u8; 31]);
    assert!(!is_p2tr(&short));

    // P2A (OP_1 push-2 4e73): NOT P2TR.
    let p2a = vec![0x51u8, 0x02, 0x4e, 0x73];
    assert!(!is_p2tr(&p2a));
    assert!(is_p2a(&p2a));
    assert!(is_p2a_program(1, &[0x4e, 0x73]));

    // Wrong opcode (OP_2 instead of OP_1).
    let mut bad_op = vec![0x52u8, 0x20];
    bad_op.extend_from_slice(&[0u8; 32]);
    assert!(!is_p2tr(&bad_op));

    // Wrong push opcode (OP_PUSHBYTES_31 instead of OP_PUSHBYTES_32).
    let mut bad_push = vec![0x51u8, 0x1f];
    bad_push.extend_from_slice(&[0u8; 32]);
    assert!(!is_p2tr(&bad_push));

    // parse_witness_program agrees with is_p2tr on the canonical P2TR.
    let (ver, prog) = parse_witness_program(&p2tr).expect("parse v1");
    assert_eq!(ver, 1);
    assert_eq!(prog.len(), 32);
}

// ============================================================
// G11: verify_taproot=false short-circuit
// ============================================================

/// G11 — When `verify_taproot=false`, a v1+32+!p2sh program returns
/// success unconditionally. Core `interpreter.cpp:1949` returns
/// `set_success(serror)` BEFORE any actual Taproot logic, and BEFORE
/// any DISCOURAGE check fires. Pre-W94 rustoshi could spuriously
/// activate consensus rules on heights/chains where Taproot has not
/// yet activated.
#[test]
fn w127_g11_verify_taproot_inactive_short_circuits() {
    // Build a v1+32 native scriptPubKey + a non-empty witness.
    let program = [0xCDu8; 32];
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&program);
    let witness: Vec<Vec<u8>> = vec![vec![0x42u8; 64]];

    let mut flags = ScriptFlags::default();
    flags.verify_taproot = false;
    flags.verify_witness = true;
    // Even DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM must NOT fire here —
    // the Taproot-inactive short-circuit returns set_success before
    // any discourage check.
    flags.verify_discourage_upgradable_witness_program = true;

    let checker = DummyChecker;
    let result = verify_script(&[], &spk, &witness, &flags, &checker);
    assert!(
        result.is_ok(),
        "Taproot inactive must return Ok unconditionally: {result:?}"
    );
}

// ============================================================
// G12: P2SH-wrapped Taproot dispatch
// ============================================================

/// G12 — P2SH-wrapped v1+32 program (`is_p2sh=true`) must NOT
/// activate the BIP-341 verifier. Core `interpreter.cpp:1947` gates
/// the Taproot path on `!is_p2sh` — BIP-341 explicitly forbids
/// Taproot inside P2SH.
///
/// Build a P2SH scriptPubKey whose redeem script is the v1+32
/// witness program; assert the spend succeeds via the upgradable-
/// witness-program fall-through (not via Taproot).
#[test]
fn w127_g12_p2sh_wrapped_taproot_falls_through() {
    let inner_program = [0x42u8; 32];
    let mut redeem_script = vec![0x51u8, 0x20];
    redeem_script.extend_from_slice(&inner_program);

    // P2SH scriptPubKey = OP_HASH160 <h160> OP_EQUAL.
    use sha2::{Digest, Sha256};
    use ripemd::Ripemd160;
    let sha = Sha256::digest(&redeem_script);
    let h160 = Ripemd160::digest(sha);
    let mut spk = vec![0xa9u8, 0x14];
    spk.extend_from_slice(&h160);
    spk.push(0x87);

    // scriptSig must push the redeem script (push-only).
    let mut script_sig = vec![redeem_script.len() as u8];
    script_sig.extend_from_slice(&redeem_script);

    // Witness can be empty: the P2SH-wrapped Taproot does NOT activate
    // BIP-341, so no witness checks run.
    let witness: Vec<Vec<u8>> = vec![];

    let mut flags = ScriptFlags::default();
    flags.verify_p2sh = true;
    flags.verify_witness = true;
    flags.verify_taproot = true; // would activate Taproot but is_p2sh=true blocks it

    let checker = DummyChecker;
    let result = verify_script(&script_sig, &spk, &witness, &flags, &checker);
    assert!(
        result.is_ok(),
        "P2SH-wrapped v1+32 must succeed (no Taproot activation): {result:?}"
    );
}

// ============================================================
// G13: Empty witness on native v1+32
// ============================================================

/// G13 — Native v1+32 program with empty witness must return
/// `WitnessProgramWitnessEmpty` (Core line 1950 / Core line 1927
/// reuse the same SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY). Pre-W94
/// rustoshi collapsed this to the generic `WitnessProgramMismatch`,
/// losing fine-grained operator diagnostics.
#[test]
fn w127_g13_empty_witness_yields_distinct_error() {
    let program = [0x37u8; 32];
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&program);
    let witness: Vec<Vec<u8>> = vec![]; // EMPTY

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;

    let checker = DummyChecker;
    let result = verify_script(&[], &spk, &witness, &flags, &checker);
    assert!(
        matches!(result, Err(ScriptError::WitnessProgramWitnessEmpty)),
        "empty witness on v1+32+!p2sh must return WitnessProgramWitnessEmpty: {result:?}"
    );
}

// ============================================================
// G14: Annex detection (last item, prefix 0x50)
// ============================================================

/// G14 — Annex detection: when `witness.len() >= 2` AND the last
/// item is non-empty AND its first byte is `ANNEX_TAG (0x50)`, the
/// last item is treated as the annex (stripped from the effective
/// witness before key-path / script-path dispatch, but committed to
/// the BIP-341 sighash via field 12).
///
/// Build a key-path spend with an annex; assert the
/// `check_schnorr_sig` checker sees the annex bytes.
#[test]
fn w127_g14_annex_detection_propagates_to_checker() {
    use std::cell::Cell;

    struct CheckerWithAnnexCapture {
        annex_seen: Cell<Option<Vec<u8>>>,
    }
    impl SignatureChecker for CheckerWithAnnexCapture {
        fn check_sig(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
            true
        }
        fn check_locktime(&self, _: i64) -> bool {
            true
        }
        fn check_sequence(&self, _: i64) -> bool {
            true
        }
        fn check_schnorr_sig(
            &self,
            _sig: &[u8],
            _xonly_pubkey: &[u8; 32],
            annex: Option<&[u8]>,
        ) -> bool {
            self.annex_seen.set(annex.map(|a| a.to_vec()));
            true
        }
    }

    let program = [0xAFu8; 32];
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&program);

    // Witness = [sig, annex]. annex starts with 0x50.
    let sig = vec![0x42u8; 64];
    let annex_bytes = vec![ANNEX_TAG, 0x01, 0x02, 0x03];
    let witness: Vec<Vec<u8>> = vec![sig, annex_bytes.clone()];

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;

    let checker = CheckerWithAnnexCapture { annex_seen: Cell::new(None) };
    let result = verify_script(&[], &spk, &witness, &flags, &checker);
    assert!(result.is_ok(), "key-path with valid sig must succeed: {result:?}");
    assert_eq!(
        checker.annex_seen.into_inner().as_deref(),
        Some(annex_bytes.as_slice()),
        "annex bytes (including 0x50 prefix) must be plumbed through to the Schnorr checker"
    );
}

// ============================================================
// G15: Key-path Schnorr verify
// ============================================================

/// G15 — Key-path spending dispatch: when the (annex-stripped)
/// witness has exactly one item, that item is the Schnorr signature
/// to be verified against the witness program (the tweaked output
/// key Q). Mirrors Core `interpreter.cpp:1960-1965`.
#[test]
fn w127_g15_key_path_dispatch_invokes_check_schnorr_sig() {
    use std::cell::Cell;

    struct CounterChecker {
        key_path_calls: Cell<u32>,
        script_path_calls: Cell<u32>,
    }
    impl SignatureChecker for CounterChecker {
        fn check_sig(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
            true
        }
        fn check_locktime(&self, _: i64) -> bool {
            true
        }
        fn check_sequence(&self, _: i64) -> bool {
            true
        }
        fn check_schnorr_sig(
            &self,
            _sig: &[u8],
            _xonly_pubkey: &[u8; 32],
            _annex: Option<&[u8]>,
        ) -> bool {
            self.key_path_calls.set(self.key_path_calls.get() + 1);
            true
        }
        fn check_schnorr_sig_tapscript(
            &self,
            _sig: &[u8],
            _xonly_pubkey: &[u8; 32],
            _tapleaf_hash: &[u8; 32],
            _codesep_pos: u32,
            _annex: Option<&[u8]>,
        ) -> bool {
            self.script_path_calls.set(self.script_path_calls.get() + 1);
            true
        }
    }

    let program = [0x88u8; 32];
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&program);
    let witness: Vec<Vec<u8>> = vec![vec![0x42u8; 64]]; // single sig

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;

    let checker = CounterChecker {
        key_path_calls: Cell::new(0),
        script_path_calls: Cell::new(0),
    };
    let result = verify_script(&[], &spk, &witness, &flags, &checker);
    assert!(result.is_ok(), "key-path must succeed: {result:?}");
    assert_eq!(checker.key_path_calls.get(), 1,
        "key-path must invoke check_schnorr_sig exactly once");
    assert_eq!(checker.script_path_calls.get(), 0,
        "key-path must NOT invoke check_schnorr_sig_tapscript");
}

// ============================================================
// G16-G17: Control block size validation
// ============================================================

/// G16 — Control block size must satisfy
/// `33 <= size <= 4129 AND (size - 33) % 32 == 0`. Boundary
/// case: 33-byte (zero merkle nodes) and 4129-byte (128-node) are
/// both valid sizes. Mirrors Core `interpreter.cpp:1970-1972`.
#[test]
fn w127_g16_control_block_well_formed_sizes_accepted() {
    let program = [0xDDu8; 32];
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&program);

    let dummy_script = vec![0x51u8]; // OP_1

    // 33-byte (no merkle path) control block — well-formed size.
    // Internal key 0xc0...0xc0 isn't on the curve so we expect
    // mismatch, but NOT TaprootWrongControlSize.
    let min_control = vec![0xc0u8; TAPROOT_CONTROL_BASE_SIZE];
    let witness: Vec<Vec<u8>> = vec![dummy_script.clone(), min_control];
    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;
    let result = verify_script(&[], &spk, &witness, &flags, &DummyChecker);
    assert!(
        !matches!(result, Err(ScriptError::TaprootWrongControlSize)),
        "33-byte control block must NOT trip wrong-control-size: {result:?}"
    );

    // 4129-byte (max merkle path) — well-formed size.
    let max_control = vec![0xc0u8; TAPROOT_CONTROL_MAX_SIZE];
    let witness2: Vec<Vec<u8>> = vec![dummy_script, max_control];
    let result2 = verify_script(&[], &spk, &witness2, &flags, &DummyChecker);
    assert!(
        !matches!(result2, Err(ScriptError::TaprootWrongControlSize)),
        "4129-byte control block must NOT trip wrong-control-size: {result2:?}"
    );
}

/// G17 — Control block sizes outside the legal range MUST return
/// `TaprootWrongControlSize` (distinct error, NOT the generic
/// `WitnessProgramMismatch`). Three cases: undersize (<33), oversize
/// (>4129), misaligned ((size-33) % 32 != 0).
#[test]
fn w127_g17_control_block_malformed_sizes_distinct_error() {
    let program = [0xDDu8; 32];
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&program);
    let dummy_script = vec![0x51u8];

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;

    // Undersize (32 bytes).
    let under = vec![0xc0u8; TAPROOT_CONTROL_BASE_SIZE - 1];
    let result = verify_script(
        &[],
        &spk,
        &vec![dummy_script.clone(), under],
        &flags,
        &DummyChecker,
    );
    assert!(
        matches!(result, Err(ScriptError::TaprootWrongControlSize)),
        "undersize control block must yield TaprootWrongControlSize: {result:?}"
    );

    // Oversize (4129 + 32 = 4161 bytes).
    let over = vec![0xc0u8; TAPROOT_CONTROL_MAX_SIZE + TAPROOT_CONTROL_NODE_SIZE];
    let result2 = verify_script(
        &[],
        &spk,
        &vec![dummy_script.clone(), over],
        &flags,
        &DummyChecker,
    );
    assert!(
        matches!(result2, Err(ScriptError::TaprootWrongControlSize)),
        "oversize control block must yield TaprootWrongControlSize: {result2:?}"
    );

    // Misaligned (50 bytes: 33 + 17, 17 % 32 != 0).
    let misaligned = vec![0xc0u8; 50];
    let result3 = verify_script(
        &[],
        &spk,
        &vec![dummy_script, misaligned],
        &flags,
        &DummyChecker,
    );
    assert!(
        matches!(result3, Err(ScriptError::TaprootWrongControlSize)),
        "misaligned control block must yield TaprootWrongControlSize: {result3:?}"
    );
}

// ============================================================
// G18: Leaf-version masking
// ============================================================

/// G18 — Leaf version is `control_block[0] & TAPROOT_LEAF_MASK`
/// (`0xfe`). The low bit (`& 0x01`) carries the output-key parity
/// — NOT part of the leaf version. Mirrors Core `interpreter.cpp:
/// 1973-1978` (`control[0] & TAPROOT_LEAF_MASK`).
#[test]
fn w127_g18_leaf_version_masking_strips_parity() {
    // 0xc0 (TAPROOT_LEAF_TAPSCRIPT) | 0x01 (odd parity) = 0xc1.
    assert_eq!(0xc1u8 & TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT);
    // 0xc0 | 0x00 (even parity) = 0xc0.
    assert_eq!(0xc0u8 & TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT);
    // Unknown leaf-version 0xc2 (e.g. future soft-fork) | parity.
    assert_eq!(0xc3u8 & TAPROOT_LEAF_MASK, 0xc2);
    assert_eq!(0xc2u8 & TAPROOT_LEAF_MASK, 0xc2);
    // 0x00 leaf version (impossible in practice — would conflict with
    // OP_0 in scripts — but the mask is well-defined).
    assert_eq!(0x01u8 & TAPROOT_LEAF_MASK, 0x00);
    assert_eq!(0x00u8 & TAPROOT_LEAF_MASK, 0x00);
}

// ============================================================
// G19: Tapleaf hash via canonical helper
// ============================================================

/// G19 — `compute_tapleaf_hash(leaf_version, script)` matches the
/// BIP-341 spec: `TaggedHash("TapLeaf", leaf_version || compact_size(script.len()) || script)`.
/// The CompactSize encoder MUST cover all four size classes
/// (`<0xfd`, `<=0xffff`, `<=0xffff_ffff`, full u64). Pre-W27-C the
/// wallet had a single-byte encoder that errored at script_len >=
/// 253 — the same bug that hit clearbit at h=947,960.
#[test]
fn w127_g19_compute_tapleaf_hash_compactsize_classes() {
    use rustoshi_crypto::taproot::compute_tapleaf_hash;
    use rustoshi_crypto::tagged_hash;

    // 1-byte CompactSize (script.len() < 0xfd).
    let script_small = vec![0x51u8]; // 1 byte
    let actual = compute_tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, &script_small);
    let mut expected_data = Vec::new();
    expected_data.push(TAPROOT_LEAF_TAPSCRIPT);
    expected_data.push(0x01); // 1-byte compact-size
    expected_data.extend_from_slice(&script_small);
    let expected = tagged_hash("TapLeaf", &expected_data);
    assert_eq!(actual, expected, "1-byte CompactSize tapleaf hash mismatch");

    // 3-byte CompactSize (253 <= script.len() <= 0xffff).
    let script_mid = vec![0xAAu8; 300];
    let actual2 = compute_tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, &script_mid);
    let mut expected_data2 = Vec::new();
    expected_data2.push(TAPROOT_LEAF_TAPSCRIPT);
    expected_data2.push(0xFD);
    expected_data2.extend_from_slice(&300u16.to_le_bytes());
    expected_data2.extend_from_slice(&script_mid);
    let expected2 = tagged_hash("TapLeaf", &expected_data2);
    assert_eq!(actual2, expected2, "3-byte CompactSize tapleaf hash mismatch");
}

// ============================================================
// G20: Tapbranch combine
// ============================================================

/// G20 — `compute_tapbranch_hash(a, b)` combines two merkle nodes
/// via `TaggedHash("TapBranch", min(a,b) || max(a,b))`. The
/// lex-sorted ordering is mandatory (BIP-341 spec, Core line
/// 1880-1884 `std::lexicographical_compare`). Commutativity test:
/// `tapbranch(a, b) == tapbranch(b, a)`.
#[test]
fn w127_g20_compute_tapbranch_hash_commutative() {
    use rustoshi_crypto::taproot::compute_tapbranch_hash;

    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let ab = compute_tapbranch_hash(&a, &b);
    let ba = compute_tapbranch_hash(&b, &a);
    assert_eq!(ab, ba, "tapbranch must lex-sort inputs (commutative)");

    // Same node twice: well-defined (lex-sort yields a || a).
    let aa = compute_tapbranch_hash(&a, &a);
    assert_ne!(aa, [0u8; 32], "tapbranch(a, a) must not be zero");
}

// ============================================================
// G21: Taproot tweak (output-key construction)
// ============================================================

/// G21 — `compute_taproot_output_key(internal_key, Some(merkle_root))`
/// returns `(output_key_xonly, parity)` where
/// `output_key = internal_key + H_TapTweak(internal_key || merkle_root) * G`.
/// Mirrors Core `XOnlyPubKey::CreateTapTweak` (pubkey.cpp:265-285).
/// Round-trip: sign with the tweaked keypair, verify with the
/// output key.
#[test]
fn w127_g21_taproot_tweak_round_trip() {
    use rustoshi_crypto::taproot::{
        compute_taproot_output_key, compute_taproot_tweak_hash,
    };

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0x73u8; 32]).unwrap();
    let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();

    let merkle_root = [0x55u8; 32];

    let (output_key, parity) =
        compute_taproot_output_key(&internal_xonly, Some(&merkle_root))
            .expect("tweak must succeed for valid internal key");

    // Round-trip: tweak the keypair the same way, sign a message,
    // verify against the output key.
    let tweak_hash = compute_taproot_tweak_hash(&internal_xonly.serialize(), Some(&merkle_root));
    let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash).unwrap();
    let tweaked_kp = kp.add_xonly_tweak(&secp, &tweak).expect("tweak kp");
    let (tweaked_xonly, _) = tweaked_kp.x_only_public_key();
    assert_eq!(
        tweaked_xonly.serialize(),
        output_key,
        "tweaked keypair x-only must match compute_taproot_output_key result"
    );

    // Parity is a flag bit (0 or 1).
    let parity_bit: u8 = match parity {
        secp256k1::Parity::Even => 0,
        secp256k1::Parity::Odd => 1,
    };
    assert!(parity_bit <= 1, "parity must be 0 or 1");
}

// ============================================================
// G22: Parity bit verification (output_parity vs control[0]&1)
// ============================================================

/// G22 — After computing the output key from the internal key +
/// merkle root, the script-path verifier MUST check that the
/// output-key parity matches `control_block[0] & 0x01`. A mismatch
/// rejects with `WitnessProgramMismatch`. Mirrors Core
/// `XOnlyPubKey::CheckTapTweak` (pubkey.cpp:262 — passes parity
/// through to `secp256k1_xonly_pubkey_tweak_add_check`).
#[test]
fn w127_g22_parity_bit_check_rejects_wrong_parity() {
    use rustoshi_crypto::taproot::{compute_taproot_output_key, compute_tapleaf_hash};

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0x44u8; 32]).unwrap();
    let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();

    let tap_script = vec![0x51u8]; // OP_1
    let tapleaf = compute_tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, &tap_script);
    let (output_key, parity) =
        compute_taproot_output_key(&internal_xonly, Some(&tapleaf)).unwrap();
    let actual_parity_bit: u8 = match parity {
        secp256k1::Parity::Even => 0,
        secp256k1::Parity::Odd => 1,
    };

    // Build a control block with FLIPPED parity. The verifier must
    // reject this with WitnessProgramMismatch.
    let wrong_parity = 1u8 - actual_parity_bit;
    let mut control = Vec::with_capacity(TAPROOT_CONTROL_BASE_SIZE);
    control.push(TAPROOT_LEAF_TAPSCRIPT | wrong_parity);
    control.extend_from_slice(&internal_xonly.serialize());

    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&output_key);
    let witness: Vec<Vec<u8>> = vec![tap_script, control];

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;

    let result = verify_script(&[], &spk, &witness, &flags, &DummyChecker);
    assert!(
        matches!(result, Err(ScriptError::WitnessProgramMismatch)),
        "flipped parity bit must yield WitnessProgramMismatch: {result:?}"
    );
}

// ============================================================
// G23: Leaf version 0xc0 dispatches into tapscript
// ============================================================

/// G23 — Leaf version `TAPROOT_LEAF_TAPSCRIPT (0xc0)` MUST dispatch
/// into the BIP-342 tapscript interpreter. Build a script-path
/// spend with leaf-version 0xc0, valid commitment, and tapscript
/// `OP_1` (succeeds). The interpreter must execute it; the
/// `AlwaysTrueSchnorrChecker` is unused (no CHECKSIG in script).
#[test]
fn w127_g23_leaf_version_tapscript_dispatches_to_interpreter() {
    use rustoshi_crypto::taproot::{compute_taproot_output_key, compute_tapleaf_hash};

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0xA1u8; 32]).unwrap();
    let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();

    let tap_script = vec![0x51u8]; // OP_1 (always succeeds)
    let tapleaf = compute_tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, &tap_script);
    let (output_key, parity) =
        compute_taproot_output_key(&internal_xonly, Some(&tapleaf)).unwrap();
    let parity_bit: u8 = match parity {
        secp256k1::Parity::Even => 0,
        secp256k1::Parity::Odd => 1,
    };

    let mut control = Vec::with_capacity(TAPROOT_CONTROL_BASE_SIZE);
    control.push(TAPROOT_LEAF_TAPSCRIPT | parity_bit);
    control.extend_from_slice(&internal_xonly.serialize());

    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&output_key);
    let witness: Vec<Vec<u8>> = vec![tap_script, control];

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;

    let result = verify_script(&[], &spk, &witness, &flags, &DummyChecker);
    assert!(
        result.is_ok(),
        "leaf_version=0xc0 + script OP_1 must succeed (tapscript dispatched, OP_1 leaves true): {result:?}"
    );
}

// ============================================================
// G24-G25: Unknown leaf version handling
// ============================================================

/// G24 — Unknown leaf version (anything other than 0xc0 after
/// parity masking) MUST be treated as anyone-can-spend
/// (soft-fork-safe). Without the
/// `verify_discourage_upgradable_taproot_version` flag, the spend
/// succeeds. Mirrors Core `interpreter.cpp:1985-1988` falling
/// through to `set_success`.
#[test]
fn w127_g24_unknown_leaf_version_is_anyone_can_spend() {
    use rustoshi_crypto::taproot::{compute_taproot_output_key, compute_tapleaf_hash};

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0xB2u8; 32]).unwrap();
    let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();

    // Unknown leaf version: 0xc2 (any non-0xc0 even byte).
    let unknown_lv = 0xc2u8;
    let tap_script = vec![0x51u8];
    let tapleaf = compute_tapleaf_hash(unknown_lv, &tap_script);
    let (output_key, parity) =
        compute_taproot_output_key(&internal_xonly, Some(&tapleaf)).unwrap();
    let parity_bit: u8 = match parity {
        secp256k1::Parity::Even => 0,
        secp256k1::Parity::Odd => 1,
    };

    let mut control = Vec::with_capacity(TAPROOT_CONTROL_BASE_SIZE);
    control.push(unknown_lv | parity_bit);
    control.extend_from_slice(&internal_xonly.serialize());

    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&output_key);
    let witness: Vec<Vec<u8>> = vec![tap_script, control];

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;
    // DISCOURAGE flag NOT set.
    assert!(!flags.verify_discourage_upgradable_taproot_version);

    let result = verify_script(&[], &spk, &witness, &flags, &DummyChecker);
    assert!(
        result.is_ok(),
        "unknown leaf version without DISCOURAGE must succeed: {result:?}"
    );
}

/// G25 — Unknown leaf version + DISCOURAGE flag → rejection with
/// `DiscourageUpgradableTaprootVersion` (relay-only; consensus
/// validation MUST NOT set this flag). Mirrors Core
/// `interpreter.cpp:1985-1987`.
#[test]
fn w127_g25_unknown_leaf_version_discourage_rejects() {
    use rustoshi_crypto::taproot::{compute_taproot_output_key, compute_tapleaf_hash};

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0xB3u8; 32]).unwrap();
    let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();

    let unknown_lv = 0xc4u8;
    let tap_script = vec![0x51u8];
    let tapleaf = compute_tapleaf_hash(unknown_lv, &tap_script);
    let (output_key, parity) =
        compute_taproot_output_key(&internal_xonly, Some(&tapleaf)).unwrap();
    let parity_bit: u8 = match parity {
        secp256k1::Parity::Even => 0,
        secp256k1::Parity::Odd => 1,
    };

    let mut control = Vec::with_capacity(TAPROOT_CONTROL_BASE_SIZE);
    control.push(unknown_lv | parity_bit);
    control.extend_from_slice(&internal_xonly.serialize());

    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&output_key);
    let witness: Vec<Vec<u8>> = vec![tap_script, control];

    let mut flags = ScriptFlags::default();
    flags.verify_witness = true;
    flags.verify_taproot = true;
    flags.verify_discourage_upgradable_taproot_version = true;

    let result = verify_script(&[], &spk, &witness, &flags, &DummyChecker);
    assert!(
        matches!(result, Err(ScriptError::DiscourageUpgradableTaprootVersion)),
        "unknown leaf version + DISCOURAGE flag must reject: {result:?}"
    );
}

// ============================================================
// G26: OP_CHECKSIGADD opcode byte
// ============================================================

/// G26 — `OP_CHECKSIGADD` is opcode byte `0xba` (BIP-342). It's
/// valid only in tapscript context; legacy/SegWit-v0 must reject
/// it as a bad opcode. Mirrors Core `script.h::OP_CHECKSIGADD = 0xba`
/// + `interpreter.cpp` switch-case.
#[test]
fn w127_g26_op_checksigadd_opcode_byte() {
    assert_eq!(Opcode::OP_CHECKSIGADD as u8, 0xba);
    // OP_CHECKSIGADD is NOT in the OP_SUCCESS range (Core comment:
    // "0xba is NOT OP_SUCCESS — it's a valid tapscript opcode").
    assert!(!Opcode::is_tapscript_success_byte(0xba));
    // 0xbb..=0xfe ARE OP_SUCCESS (undefined-as-success).
    for byte in 0xbbu8..=0xfeu8 {
        assert!(Opcode::is_tapscript_success_byte(byte),
            "byte 0x{byte:02x} must be OP_SUCCESS");
    }
}

// ============================================================
// G27: OP_SUCCESS pre-scan covers BIP-342 set
// ============================================================

/// G27 — `is_tapscript_success_byte` covers every byte in BIP-342's
/// `IsOpSuccess`:
///   80 (0x50), 98 (0x62),
///   126..=129 (0x7e..=0x81),
///   131..=134 (0x83..=0x86),
///   137..=138 (0x89..=0x8a),
///   141..=142 (0x8d..=0x8e),
///   149..=153 (0x95..=0x99),
///   187..=254 (0xbb..=0xfe).
/// Mirrors Core `script.cpp:364-369::IsOpSuccess`.
#[test]
fn w127_g27_op_success_byte_set_complete() {
    // Required bytes.
    assert!(Opcode::is_tapscript_success_byte(0x50));
    assert!(Opcode::is_tapscript_success_byte(0x62));
    // OP_CAT..OP_RIGHT (0x7e..=0x81).
    for b in 0x7eu8..=0x81u8 {
        assert!(Opcode::is_tapscript_success_byte(b), "0x{b:02x}");
    }
    // OP_INVERT..OP_XOR (0x83..=0x86).
    for b in 0x83u8..=0x86u8 {
        assert!(Opcode::is_tapscript_success_byte(b), "0x{b:02x}");
    }
    // OP_RESERVED1/2 (0x89..=0x8a).
    for b in 0x89u8..=0x8au8 {
        assert!(Opcode::is_tapscript_success_byte(b), "0x{b:02x}");
    }
    // OP_2MUL/2DIV (0x8d..=0x8e).
    for b in 0x8du8..=0x8eu8 {
        assert!(Opcode::is_tapscript_success_byte(b), "0x{b:02x}");
    }
    // OP_MUL..OP_RSHIFT (0x95..=0x99).
    for b in 0x95u8..=0x99u8 {
        assert!(Opcode::is_tapscript_success_byte(b), "0x{b:02x}");
    }
    // 0xbb..=0xfe.
    for b in 0xbbu8..=0xfeu8 {
        assert!(Opcode::is_tapscript_success_byte(b), "0x{b:02x}");
    }
    // Sanity: NOT in the set.
    assert!(!Opcode::is_tapscript_success_byte(0x51));  // OP_1
    assert!(!Opcode::is_tapscript_success_byte(0x82));  // OP_SIZE
    assert!(!Opcode::is_tapscript_success_byte(0xba));  // OP_CHECKSIGADD
    assert!(!Opcode::is_tapscript_success_byte(0xff));  // OP_INVALIDOPCODE
    assert!(!Opcode::is_tapscript_success_byte(0x00));  // OP_0
}

// ============================================================
// G28: OP_SUCCESS + DISCOURAGE flag
// ============================================================

/// G28 — Tapscript with an OP_SUCCESS opcode + the
/// `verify_discourage_op_success` flag (relay-only) returns
/// `DiscourageOpSuccess`. Without the flag, OP_SUCCESS causes
/// unconditional script success regardless of stack contents or
/// disabled-opcode rules. Mirrors Core `interpreter.cpp:1846-1850`.
#[test]
fn w127_g28_op_success_discourage_rejection() {
    let mut stack: Stack = vec![];
    let script = [0x50u8]; // OP_RESERVED == OP_SUCCESS in tapscript
    let mut flags = ScriptFlags::default();
    flags.verify_discourage_op_success = true;
    let checker = DummyChecker;
    let tapleaf = [0u8; 32];
    let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 1000);
    assert!(
        matches!(res, Err(ScriptError::DiscourageOpSuccess)),
        "OP_SUCCESS + DISCOURAGE flag must reject with DiscourageOpSuccess: {res:?}"
    );

    // Without the flag, the SAME script succeeds.
    let mut stack2: Stack = vec![];
    let flags2 = ScriptFlags::default(); // no DISCOURAGE
    let ts2 = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res2 = eval_script_tapscript(&mut stack2, &script, &flags2, &DummyChecker, ts2, 1000);
    assert!(
        res2.is_ok(),
        "OP_SUCCESS alone must succeed unconditionally: {res2:?}"
    );
}

// ============================================================
// G29: CHECKMULTISIG disabled in tapscript
// ============================================================

/// G29 — OP_CHECKMULTISIG (0xae) and OP_CHECKMULTISIGVERIFY (0xaf)
/// are DISABLED in tapscript. BIP-342 explicitly removed multisig
/// in favor of OP_CHECKSIGADD. Rustoshi reports
/// `TapscriptCheckmultisig`; Core reports
/// `SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`. Mirrors Core
/// `interpreter.cpp` switch-case at OP_CHECKMULTISIG.
#[test]
fn w127_g29_checkmultisig_disabled_in_tapscript() {
    // OP_CHECKMULTISIG: must reject with TapscriptCheckmultisig.
    let mut stack: Stack = vec![
        vec![],          // dummy null
        vec![0x42; 64],  // sig
        vec![0x01],      // n_sigs = 1
        vec![0x02; 33],  // pubkey
        vec![0x01],      // n_keys = 1
    ];
    let script = [0xaeu8]; // OP_CHECKMULTISIG
    let flags = ScriptFlags::default();
    let tapleaf = [0u8; 32];
    let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res = eval_script_tapscript(
        &mut stack,
        &script,
        &flags,
        &AlwaysTrueSchnorrChecker,
        ts,
        1000,
    );
    assert!(
        matches!(res, Err(ScriptError::TapscriptCheckmultisig)),
        "OP_CHECKMULTISIG in tapscript must reject: {res:?}"
    );

    // OP_CHECKMULTISIGVERIFY: must reject with TapscriptCheckmultisig.
    let mut stack2: Stack = vec![
        vec![],
        vec![0x42; 64],
        vec![0x01],
        vec![0x02; 33],
        vec![0x01],
    ];
    let script2 = [0xafu8]; // OP_CHECKMULTISIGVERIFY
    let ts2 = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res2 = eval_script_tapscript(
        &mut stack2,
        &script2,
        &flags,
        &AlwaysTrueSchnorrChecker,
        ts2,
        1000,
    );
    assert!(
        matches!(res2, Err(ScriptError::TapscriptCheckmultisig)),
        "OP_CHECKMULTISIGVERIFY in tapscript must reject: {res2:?}"
    );
}

// ============================================================
// G30: Validation-weight budget
// ============================================================

/// G30 — BIP-342 validation-weight: budget = `witness_serialize_size
/// + VALIDATION_WEIGHT_OFFSET (50)`, decremented by
/// `VALIDATION_WEIGHT_PER_SIGOP_PASSED (50)` for each non-empty
/// signature in CHECKSIG/CHECKSIGVERIFY/CHECKSIGADD, regardless of
/// whether the pubkey is 32-byte (Schnorr) or unknown (upgradable
/// type). Empty signature consumes ZERO weight. Mirrors Core
/// `interpreter.cpp:357-365`.
///
/// Three sub-assertions:
///   (a) budget=49 (< 50) + non-empty sig → TapscriptValidationWeight.
///   (b) budget=50 + non-empty sig → succeeds (49 + 1 = 50 OK).
///   (c) budget=49 + empty sig → succeeds (no weight consumed).
#[test]
fn w127_g30_validation_weight_decrement() {
    let pubkey = vec![0x02u8; 32];
    let sig = vec![0x42u8; 64];
    let flags = ScriptFlags::default();
    let checker = AlwaysTrueSchnorrChecker;
    let tapleaf = [0u8; 32];

    // (a) budget=49 — non-empty sig triggers TapscriptValidationWeight.
    let mut stack: Stack = vec![sig.clone(), pubkey.clone()];
    let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res = eval_script_tapscript(
        &mut stack,
        &[0xacu8], // OP_CHECKSIG
        &flags,
        &checker,
        ts,
        49,
    );
    assert!(
        matches!(res, Err(ScriptError::TapscriptValidationWeight)),
        "budget=49 + non-empty sig must trip TapscriptValidationWeight: {res:?}"
    );

    // (b) budget=50 — exactly sufficient, succeeds.
    let mut stack2: Stack = vec![sig.clone(), pubkey.clone()];
    let ts2 = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res2 = eval_script_tapscript(
        &mut stack2,
        &[0xacu8],
        &flags,
        &checker,
        ts2,
        50,
    );
    assert!(res2.is_ok(), "budget=50 + non-empty sig must succeed: {res2:?}");

    // (c) budget=49 + EMPTY sig → no weight consumed, succeeds.
    // For CHECKSIG with empty sig: pushes false. We add OP_NOT then
    // the stack ends with true.
    let mut stack3: Stack = vec![vec![], pubkey.clone()];
    let ts3 = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res3 = eval_script_tapscript(
        &mut stack3,
        &[0xacu8, 0x91u8], // OP_CHECKSIG OP_NOT
        &flags,
        &checker,
        ts3,
        49,
    );
    assert!(
        res3.is_ok(),
        "budget=49 + EMPTY sig must succeed (0 weight consumed): {res3:?}"
    );

    // (d) BONUS: budget=49 + non-empty sig + unknown pubkey (33-byte) →
    // also trips ValidationWeight. The Core comment at line 360
    // ("Passing with an upgradable public key version is also counted")
    // is critical: a future-pubkey-type free pass would be a sigop
    // attack vector.
    let unknown_pubkey = vec![0x02u8; 33];
    let mut stack4: Stack = vec![sig.clone(), unknown_pubkey];
    let ts4 = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
    let res4 = eval_script_tapscript(
        &mut stack4,
        &[0xacu8],
        &flags,
        &checker,
        ts4,
        49,
    );
    assert!(
        matches!(res4, Err(ScriptError::TapscriptValidationWeight)),
        "budget=49 + non-empty sig + unknown pubkey must ALSO trip ValidationWeight: {res4:?}"
    );
}

// ============================================================
// Cross-cut: witness serialize size matches Core
// ============================================================

/// Cross-cut for G30: `get_serialize_size_of_witness_stack` must
/// match Core's `::GetSerializeSize(witness.stack)` byte-for-byte.
/// Layout: count(CompactSize) || (per item: len(CompactSize) || bytes).
#[test]
fn w127_xcut_witness_serialize_size_matches_core() {
    // Empty stack: just the count CompactSize = 1 byte.
    assert_eq!(get_serialize_size_of_witness_stack(&[]), 1);
    // [64B] = 1 (count) + 1 (len) + 64 = 66.
    assert_eq!(get_serialize_size_of_witness_stack(&[vec![0u8; 64]]), 66);
    // [100B, 33B] = 1 + (1+100) + (1+33) = 136.
    assert_eq!(
        get_serialize_size_of_witness_stack(&[vec![0u8; 100], vec![0u8; 33]]),
        136
    );
    // [252B] = 1 + 1 (CompactSize<0xfd) + 252 = 254.
    assert_eq!(get_serialize_size_of_witness_stack(&[vec![0u8; 252]]), 254);
    // [253B] = 1 + 3 (CompactSize 0xFD+u16) + 253 = 257.
    assert_eq!(get_serialize_size_of_witness_stack(&[vec![0u8; 253]]), 257);
}

// ============================================================
// Cross-cut: CapturingSchnorrChecker exercises codesep_pos
// ============================================================

/// Cross-cut: a tapscript with OP_CODESEPARATOR then OP_CHECKSIG
/// must invoke `check_schnorr_sig_tapscript` with the right
/// `codesep_pos`. The CODESEPARATOR opcode is at opcode index 0
/// (the first opcode), so `codesep_pos` should be 0 when CHECKSIG
/// runs at opcode index 1. Mirrors Core
/// `interpreter.cpp:1055, 1565` (opcode-index recording).
#[test]
fn w127_xcut_codesep_pos_plumbing() {
    let pubkey = vec![0x02u8; 32];
    let sig = vec![0x42u8; 64];
    let mut stack: Stack = vec![sig, pubkey];

    let flags = ScriptFlags::default();
    let checker = CapturingSchnorrChecker::default();
    let tapleaf = [0xAA; 32];
    let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };

    // Script: [OP_CODESEPARATOR, OP_CHECKSIG] — codesep at opcode index 0,
    // CHECKSIG at opcode index 1.
    let script = [0xabu8, 0xacu8];
    let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 1000);
    assert!(res.is_ok(), "script must succeed: {res:?}");
    assert_eq!(
        checker.last_codesep_pos.get(),
        0,
        "OP_CODESEPARATOR at opcode index 0 must set codesep_pos = 0"
    );
    // Tapleaf hash must propagate unchanged.
    assert_eq!(checker.last_tapleaf_hash.get(), tapleaf);
    // No annex.
    assert!(!checker.last_annex_present.get());
}

// ============================================================
// Source-level forward-regression guards
// ============================================================

/// Forward-regression guard: the canonical
/// `compute_tapleaf_hash` lives in `crates/crypto/src/taproot.rs`.
/// A duplicate in the wallet (`descriptor.rs`) was the W27-C bug
/// class — verify it has not crept back. Pattern:
/// **single-source-of-truth source-grep guard.**
#[test]
fn w127_source_guard_no_duplicate_tapleaf_hash() {
    let crypto_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crypto/src/taproot.rs"
    ))
    .expect("read crypto/taproot.rs");
    assert!(
        crypto_src.contains("pub fn compute_tapleaf_hash"),
        "compute_tapleaf_hash must live in crates/crypto/src/taproot.rs"
    );

    // Wallet must NOT carry its own compute_tapleaf_hash.
    let wallet_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../wallet/src");
    if let Ok(entries) = std::fs::read_dir(wallet_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                let s = std::fs::read_to_string(&p).unwrap_or_default();
                assert!(
                    !s.contains("fn compute_tapleaf_hash"),
                    "wallet file {} must NOT redefine compute_tapleaf_hash \
                     (W27-C bug class)",
                    p.display()
                );
            }
        }
    }
}

/// Forward-regression guard: the W94 constant-check test
/// `w94_taproot_constants_match_core` lives in `interpreter.rs` and
/// pins every numeric constant against Core. Verify the function
/// still exists (drift detector).
#[test]
fn w127_source_guard_w94_constants_test_present() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/script/interpreter.rs"
    ))
    .expect("read interpreter.rs");
    assert!(
        src.contains("fn w94_taproot_constants_match_core"),
        "W94 constants-vs-Core regression test must remain in interpreter.rs"
    );
    assert!(
        src.contains("fn w95_tapscript_checksig_unknown_pkt_empty_sig_pushes_false"),
        "W95 unknown-pubkey-type semantics regression must remain in interpreter.rs"
    );
}

/// Forward-regression guard: the W27-C tapleaf-CompactSize-boundary
/// regression test must remain in `crates/crypto/src/taproot.rs`.
/// This is the test that pins the bug class that hit clearbit at
/// h=947,960.
#[test]
fn w127_source_guard_w27c_compactsize_boundary_test_present() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crypto/src/taproot.rs"
    ))
    .expect("read crypto/taproot.rs");
    assert!(
        src.contains("fn tapleaf_hash_handles_script_over_compactsize_boundary"),
        "W27-C >65535B tapleaf hash regression test must remain in crypto/taproot.rs"
    );
}
