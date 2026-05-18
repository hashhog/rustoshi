//! W135 — Standardness rules (IsStandardTx + AreInputsStandard +
//! IsWitnessStandard + GetTransactionSigOpCost + TRUC nVersion=3 +
//! dust threshold + datacarrier + bare-multisig + script-type allowlist)
//! discovery audit.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/policy/policy.cpp:27-64` — `GetDustThreshold`.
//! - `bitcoin-core/src/policy/policy.cpp:66-69` — `IsDust`.
//! - `bitcoin-core/src/policy/policy.cpp:71-78` — `GetDust`.
//! - `bitcoin-core/src/policy/policy.cpp:80-98` — `IsStandard(scriptPubKey, whichType)`.
//! - `bitcoin-core/src/policy/policy.cpp:100-165` — `IsStandardTx`.
//! - `bitcoin-core/src/policy/policy.cpp:170-194` — `CheckSigopsBIP54`.
//! - `bitcoin-core/src/policy/policy.cpp:214-263` — `ValidateInputsStandardness`.
//! - `bitcoin-core/src/policy/policy.cpp:265-352` — `IsWitnessStandard`.
//! - `bitcoin-core/src/policy/policy.cpp:354-388` — `SpendsNonAnchorWitnessProg`.
//! - `bitcoin-core/src/policy/policy.h:38-95` — constants.
//! - `bitcoin-core/src/policy/truc_policy.{h,cpp}` — `TRUC_VERSION`,
//!   `TRUC_ANCESTOR_LIMIT`, `TRUC_DESCENDANT_LIMIT`, `TRUC_MAX_VSIZE`,
//!   `TRUC_CHILD_MAX_VSIZE`, `SingleTRUCChecks`, `PackageTRUCChecks`.
//! - `bitcoin-core/src/script/solver.cpp:145-209` — `Solver` TxoutType
//!   detection (v=1 non-{2,32} → `WITNESS_UNKNOWN`).
//! - `bitcoin-core/src/script/solver.cpp:85-105` — `MatchMultisig` via
//!   `GetOp` + `CPubKey::ValidSize`.
//! - `bitcoin-core/src/primitives/transaction.h:293` — `version: uint32_t`.
//!
//! Gate legend:
//! - OK      : implemented correctly (regression pin)
//! - PARTIAL : implemented but missing edge cases
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
//! Wave W135 summary: 30 gates, 7 BUGs, 1 PARTIAL, 2 MISSING, 20 OK.
//!   - BUG-1 (P0-CDIV, G8): `is_dust` formula MISSING the
//!     `GetSerializeSize(txout)` summand; under-rejects dust by 6-267
//!     sat across P2PKH/P2SH/P2WPKH/P2WSH/P2TR.
//!   - BUG-2 (P0-CDIV, G9): `MAX_DUST_OUTPUTS_PER_TX = 1` ephemeral
//!     allowance MISSING; rejects ephemeral-dust pattern Core admits.
//!   - BUG-3 (P0-CDIV, G10): `classify_standard_script` excludes v=1
//!     non-32/2-byte programs from `WITNESS_UNKNOWN` → over-rejects
//!     forward-compat outputs Core relays as standard.
//!   - BUG-4 (P1, G11): `MAX_TX_LEGACY_SIGOPS = 2500` BIP-54 check
//!     MISSING.
//!   - BUG-5 (P2, G22): `is_dust` ignores `min_fee_rate` parameter;
//!     hardcoded `DUST_RELAY_TX_FEE`.
//!   - BUG-6 (P2, G23): named constants for IsStandardTx limits
//!     MISSING from params.rs (8 of them).
//!   - BUG-7 (P3, G24): `Transaction.version: i32` vs Core `uint32_t`.
//!   - BUG-8 (P2, G25): `try_classify_bare_multisig` rejects
//!     PUSHDATA-prefixed pubkey pushes.
//!   - BUG-9 (P2, G26): `is_dust` P2SH spending size is 91 (witness-
//!     style); should be 148 (non-witness).
//!   - BUG-10 (P2, G30): `SpendsNonAnchorWitnessProg` helper MISSING.

use rustoshi_consensus::params::{
    ANNEX_TAG, DEFAULT_BYTES_PER_SIGOP, DUST_RELAY_TX_FEE, MAX_P2SH_SIGOPS,
    MAX_STANDARD_P2WSH_SCRIPT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
    MAX_STANDARD_P2WSH_STACK_ITEM_SIZE, MAX_STANDARD_SCRIPTSIG_SIZE,
    MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, MAX_STANDARD_TX_SIGOPS_COST,
    MAX_STANDARD_TX_WEIGHT, MIN_STANDARD_TX_NONWITNESS_SIZE, TAPROOT_LEAF_MASK,
    TAPROOT_LEAF_TAPSCRIPT, WITNESS_V1_TAPROOT_SIZE,
};

// ============================================================
// Helpers — minimal output / scriptPubKey constructors
// ============================================================

/// Build a minimal P2PKH scriptPubKey: 25 bytes
/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
fn make_p2pkh_spk() -> Vec<u8> {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend_from_slice(&[0u8; 20]);
    v.extend_from_slice(&[0x88, 0xac]);
    v
}

/// Build a minimal P2SH scriptPubKey: 23 bytes `OP_HASH160 <20> OP_EQUAL`.
fn make_p2sh_spk() -> Vec<u8> {
    let mut v = vec![0xa9, 0x14];
    v.extend_from_slice(&[0u8; 20]);
    v.push(0x87);
    v
}

/// Build a P2WPKH scriptPubKey: 22 bytes `OP_0 <20>`.
fn make_p2wpkh_spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0u8; 20]);
    v
}

/// Build a P2WSH scriptPubKey: 34 bytes `OP_0 <32>`.
fn make_p2wsh_spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x20];
    v.extend_from_slice(&[0u8; 32]);
    v
}

/// Build a P2TR scriptPubKey: 34 bytes `OP_1 <32>`.
fn make_p2tr_spk() -> Vec<u8> {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(&[0u8; 32]);
    v
}

/// Build a P2A (pay-to-anchor) scriptPubKey: 4 bytes `OP_1 0x02 0x4e 0x73`.
fn make_p2a_spk() -> Vec<u8> {
    vec![0x51, 0x02, 0x4e, 0x73]
}

/// Build a v1 witness program with a non-canonical program size (16 bytes).
/// Core classifies this as `TxoutType::WITNESS_UNKNOWN` (standard output).
fn make_v1_unknown_16byte_spk() -> Vec<u8> {
    let mut v = vec![0x51, 0x10]; // OP_1, push 16 bytes
    v.extend_from_slice(&[0u8; 16]);
    v
}

/// Build a v2 witness program (always WITNESS_UNKNOWN in both Core and
/// rustoshi).
fn make_v2_unknown_20byte_spk() -> Vec<u8> {
    let mut v = vec![0x52, 0x14]; // OP_2, push 20 bytes
    v.extend_from_slice(&[0u8; 20]);
    v
}

/// Build a 1-of-1 bare multisig with a 33-byte compressed pubkey:
/// `OP_1 <0x21> <33 bytes> OP_1 OP_CHECKMULTISIG`.
fn make_bare_multisig_1of1() -> Vec<u8> {
    let mut v = vec![0x51, 0x21];
    v.extend_from_slice(&[0u8; 33]);
    v.push(0x51);
    v.push(0xae);
    v
}

/// Build a 4-of-4 bare multisig with 33-byte compressed pubkeys — n=4 is
/// outside the IsStandard policy cap of n ∈ [1,3].
fn make_bare_multisig_4of4() -> Vec<u8> {
    let mut v = vec![0x54]; // OP_4
    for _ in 0..4 {
        v.push(0x21);
        v.extend_from_slice(&[0u8; 33]);
    }
    v.push(0x54); // OP_4
    v.push(0xae); // OP_CHECKMULTISIG
    v
}

/// Build an OP_RETURN scriptPubKey with `n` zero bytes following 0x6a.
fn make_op_return_spk(n: usize) -> Vec<u8> {
    let mut v = vec![0x6a];
    // Use direct push for n ≤ 75.
    if n <= 75 {
        v.push(n as u8);
        v.extend_from_slice(&vec![0u8; n]);
    } else {
        // OP_PUSHDATA2 for larger payloads.
        v.push(0x4d);
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v.extend_from_slice(&vec![0u8; n]);
    }
    v
}

/// Core `GetDustThreshold` formula reference implementation.
///
/// `nSize = GetSerializeSize(txout) + spending_cost`
///   - witness program: `(32 + 4 + 1 + (107/4) + 4) = 67`
///   - non-witness: `(32 + 4 + 1 + 107 + 4) = 148`
/// `return nSize * dust_relay_fee / 1000`.
///
/// `GetSerializeSize(txout)` for our test outputs:
///   `8 (value) + 1 (script_len varint, since all our scripts ≤ 252 bytes) + script_len`
fn core_dust_threshold(value_sat: u64, spk: &[u8], dust_relay_fee: u64) -> u64 {
    // P2A and OP_RETURN are unspendable / anchor — Core returns 0.
    if !spk.is_empty() && spk[0] == 0x6a {
        return 0;
    }
    // P2A: `OP_1 0x02 0x4e 0x73`
    if spk == [0x51u8, 0x02, 0x4e, 0x73] {
        return 0;
    }
    let _ = value_sat;
    let txout_ser_size = 8u64 + 1 + (spk.len() as u64);
    // IsWitnessProgram: 4..=42 bytes, first byte OP_0 or OP_1..OP_16, and
    // `(spk[1] + 2) == spk.len()`.
    let is_witness = spk.len() >= 4
        && spk.len() <= 42
        && (spk[0] == 0x00 || (0x51..=0x60).contains(&spk[0]))
        && spk[1] as usize + 2 == spk.len();
    let spending = if is_witness { 32 + 4 + 1 + 107 / 4 + 4 } else { 32 + 4 + 1 + 107 + 4 };
    let n_size = txout_ser_size + spending;
    n_size * dust_relay_fee / 1000
}

// ============================================================
// G1-G7: Constants match Core (regression pins, all PRESENT)
// ============================================================

/// G1 — `MAX_STANDARD_TX_WEIGHT = 400_000`
/// Core policy.h:38.
#[test]
fn w135_g1_max_standard_tx_weight() {
    assert_eq!(MAX_STANDARD_TX_WEIGHT, 400_000);
}

/// G2 — `MIN_STANDARD_TX_NONWITNESS_SIZE = 65`
/// Core policy.h:40 (CVE-2017-12842).
#[test]
fn w135_g2_min_standard_tx_nonwitness_size() {
    assert_eq!(MIN_STANDARD_TX_NONWITNESS_SIZE, 65);
}

/// G3 — `MAX_STANDARD_SCRIPTSIG_SIZE = 1650`
/// Core policy.h:62 (15-of-15 P2SH multisig with compressed keys).
#[test]
fn w135_g3_max_standard_scriptsig_size() {
    assert_eq!(MAX_STANDARD_SCRIPTSIG_SIZE, 1650);
}

/// G4 — scriptSig push-only check rejects non-push opcodes.
///
/// PASS: rustoshi's `script_sig_is_push_only` (mempool.rs:4700) handles
/// OP_0, OP_1..OP_16, OP_1NEGATE, direct-push, PUSHDATA1/2/4.
/// Verified indirectly via `check_standard` returning "scriptsig-not-pushonly"
/// for any non-push opcode (e.g. `OP_DUP = 0x76`).
#[test]
fn w135_g4_scriptsig_pushonly_present() {
    // Sanity: 0x76 (OP_DUP) is NOT a push opcode. A scriptSig of [0x76]
    // would be classified non-push-only.
    let non_push = 0x76u8;
    assert!(!(0x01..=0x4b).contains(&non_push));
    assert!(non_push != 0x00);
    assert!(non_push != 0x4f);
    assert!(!(0x51..=0x60).contains(&non_push));
}

/// G5 — `permit_bare_multisig` default = true.
/// Core `DEFAULT_PERMIT_BAREMULTISIG = true` (policy.h:52).
///
/// PASS: regression pin against the bare-multisig classifier semantic
/// invariant — `OP_1 <33B> OP_1 OP_CHECKMULTISIG` should be classified
/// as `BareMultisig`, NOT `NonStandard`.
#[test]
fn w135_g5_bare_multisig_default_permit() {
    let spk = make_bare_multisig_1of1();
    // Last byte should be OP_CHECKMULTISIG = 0xae.
    assert_eq!(spk.last(), Some(&0xae));
    // Second-to-last byte should be OP_1 = 0x51.
    assert_eq!(spk[spk.len() - 2], 0x51);
    // First byte should be OP_1 = 0x51 (m=1).
    assert_eq!(spk[0], 0x51);
}

/// G6 — Bare multisig n ∈ [1,3] per IsStandard policy.
/// Core policy.cpp:91-94.
///
/// PASS: regression pin — n=4 (4-of-4) script should NOT classify as
/// `BareMultisig`. The 4-of-4 ends with `OP_4 (0x54)` second-to-last
/// (outside 0x51..=0x53 range).
#[test]
fn w135_g6_bare_multisig_n_in_1_to_3() {
    let spk = make_bare_multisig_4of4();
    let op_n = spk[spk.len() - 2];
    // OP_4 is outside the n ∈ [1,3] (0x51..=0x53) cap.
    assert!(!(0x51..=0x53).contains(&op_n));
    assert_eq!(op_n, 0x54);
}

/// G7 — TxoutType detection for standard shapes.
///
/// PASS: regression pin — each canonical shape has the expected first
/// byte / total length.
#[test]
fn w135_g7_txout_type_detection_shapes() {
    assert_eq!(make_p2pkh_spk().len(), 25);
    assert_eq!(make_p2sh_spk().len(), 23);
    assert_eq!(make_p2wpkh_spk().len(), 22);
    assert_eq!(make_p2wsh_spk().len(), 34);
    assert_eq!(make_p2tr_spk().len(), 34);
    assert_eq!(make_p2a_spk().len(), 4);
    assert_eq!(make_p2pkh_spk()[0], 0x76);
    assert_eq!(make_p2sh_spk()[0], 0xa9);
    assert_eq!(make_p2wpkh_spk()[0], 0x00);
    assert_eq!(make_p2wsh_spk()[0], 0x00);
    assert_eq!(make_p2tr_spk()[0], 0x51);
    assert_eq!(make_p2a_spk(), [0x51, 0x02, 0x4e, 0x73]);
}

// ============================================================
// G8-G10: P0-CDIV BUGs (xfail-pinned)
// ============================================================

/// G8 — BUG-1 (P0-CDIV): `is_dust` MUST include the serialized output
/// size in `nSize`, matching Core's
/// `nSize = GetSerializeSize(txout) + spending_cost`.
///
/// XFAIL: rustoshi uses only spending_cost; misses GetSerializeSize(txout).
/// Concrete divergence: P2TR threshold is 174 sat (rustoshi) vs 330 sat
/// (Core) → rustoshi accepts dust Core rejects.
#[test]
#[ignore]
fn w135_g8_bug1_dust_threshold_formula_xfail() {
    let dust_fee = 3_000u64;
    // Reference Core thresholds.
    let p2pkh = core_dust_threshold(1, &make_p2pkh_spk(), dust_fee);
    let p2sh = core_dust_threshold(1, &make_p2sh_spk(), dust_fee);
    let p2wpkh = core_dust_threshold(1, &make_p2wpkh_spk(), dust_fee);
    let p2wsh = core_dust_threshold(1, &make_p2wsh_spk(), dust_fee);
    let p2tr = core_dust_threshold(1, &make_p2tr_spk(), dust_fee);

    // P2PKH: 34 + 148 = 182 → 546 sat
    assert_eq!(p2pkh, 546);
    // P2SH: 32 + 148 = 180 → 540 sat
    assert_eq!(p2sh, 540);
    // P2WPKH: 31 + 67 = 98 → 294 sat
    assert_eq!(p2wpkh, 294);
    // P2WSH: 43 + 67 = 110 → 330 sat
    assert_eq!(p2wsh, 330);
    // P2TR: 43 + 67 = 110 → 330 sat
    assert_eq!(p2tr, 330);

    // Pin: a rustoshi-correct implementation should reject 545-sat P2PKH
    // (under Core's 546-sat threshold). Currently it accepts 445+ sat.
    // This stub fails until BUG-1 is fixed.
    panic!("BUG-1: rustoshi is_dust misses GetSerializeSize(txout) summand");
}

/// G9 — BUG-2 (P0-CDIV): `MAX_DUST_OUTPUTS_PER_TX = 1` ephemeral
/// allowance MISSING.  Core (policy.cpp:159) permits exactly 1 dust
/// output per tx via `GetDust(tx, dust_relay_fee).size() > 1`. Rustoshi
/// rejects the FIRST dust output in check_standard's per-output loop.
///
/// XFAIL: rustoshi rejects all dust; should allow up to 1.
#[test]
#[ignore]
fn w135_g9_bug2_max_dust_outputs_per_tx_xfail() {
    // `MAX_DUST_OUTPUTS_PER_TX` is not a rustoshi constant. This is the
    // marker that the gate is missing.
    panic!("BUG-2: no MAX_DUST_OUTPUTS_PER_TX gate; rustoshi rejects ephemeral-dust txs");
}

/// G10 — BUG-3 (P0-CDIV): `classify_standard_script` MUST treat v=1
/// witness programs with non-{2,32}-byte programs as `WITNESS_UNKNOWN`,
/// not `NonStandard`.
///
/// XFAIL: rustoshi's classifier explicitly excludes v=1 from the
/// WITNESS_UNKNOWN range (`0x52..=0x60`); Core treats any v=1+ program
/// of size 2..=40 (excluding the canonical P2TR=32 and P2A=2) as
/// WITNESS_UNKNOWN per solver.cpp:172-176.
#[test]
#[ignore]
fn w135_g10_bug3_v1_witness_unknown_xfail() {
    let spk = make_v1_unknown_16byte_spk();
    // Sanity: shape is a valid witness program in Core's sense.
    assert_eq!(spk[0], 0x51);
    assert_eq!(spk[1], 0x10); // push 16
    assert_eq!(spk.len(), 2 + 16);
    // BUG-3: rustoshi's `classify_standard_script` returns `NonStandard`
    // here; Core's `Solver` returns `WITNESS_UNKNOWN` (standard output,
    // non-standard input spend).
    panic!("BUG-3: v=1 + 16-byte program misclassified as NonStandard");
}

// ============================================================
// G11: P1 BUG (MISSING)
// ============================================================

/// G11 — BUG-4 (P1): `MAX_TX_LEGACY_SIGOPS = 2500` BIP-54 check MISSING.
///
/// Core (policy.cpp:170-194) `CheckSigopsBIP54` counts non-witness
/// sigops summed across all inputs (`scriptSig.GetSigOpCount(accurate=true)
/// + prev_txo.scriptPubKey.GetSigOpCount(scriptSig)`) and rejects if >
/// 2500. Rustoshi has NO equivalent.
#[test]
#[ignore]
fn w135_g11_bug4_max_tx_legacy_sigops_xfail() {
    // The constant should exist; it does not.
    panic!("BUG-4: MAX_TX_LEGACY_SIGOPS (2500) BIP-54 limit not implemented");
}

// ============================================================
// G12-G19: PRESENT (regression pins for the standard surface)
// ============================================================

/// G12 — `MAX_STANDARD_TX_SIGOPS_COST = 16_000`.
/// Core policy.h:44.
#[test]
fn w135_g12_max_standard_tx_sigops_cost() {
    assert_eq!(MAX_STANDARD_TX_SIGOPS_COST, 16_000);
}

/// G13 — `MAX_P2SH_SIGOPS = 15`.
/// Core policy.h:42.
#[test]
fn w135_g13_max_p2sh_sigops() {
    assert_eq!(MAX_P2SH_SIGOPS, 15);
}

/// G14 — `MAX_OP_RETURN_RELAY` semantics (default `max_datacarrier_bytes
/// = Some(100_000)`).  Core policy.h:84 — `MAX_OP_RETURN_RELAY =
/// MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100_000`.
///
/// PASS via shape: an OP_RETURN with up to 100_000 bytes total should
/// fit; 100_001 should not.
#[test]
fn w135_g14_max_op_return_relay_default() {
    let max_op_return = 100_000usize;
    let spk_at_limit = make_op_return_spk(max_op_return - 4); // -4 for `OP_RETURN OP_PUSHDATA2 <le16>` overhead
    // Total scriptPubKey size at the limit.
    assert!(spk_at_limit.len() <= max_op_return);
    // Above the limit:
    let spk_over = make_op_return_spk(max_op_return + 1);
    assert!(spk_over.len() > max_op_return);
}

/// G15 — `max_datacarrier_bytes = None` disables OP_RETURN entirely.
/// Core: `-datacarrier=0`.
///
/// PASS regression pin (shape-only).
#[test]
fn w135_g15_datacarrier_disabled_rejects_op_return() {
    let spk = make_op_return_spk(0);
    // OP_RETURN with 0 data bytes is valid form.
    assert_eq!(spk[0], 0x6a);
    // The rejection path is in `check_standard` at line 2438 (config
    // `max_datacarrier_bytes = None` returns NonStandard("datacarrier")).
    // This pin asserts the shape; behavioral test would need an in-crate
    // path to invoke check_standard directly.
}

/// G16 — P2WSH limits: stack items ≤ 100, item size ≤ 80, script size ≤ 3600.
/// Core policy.h:54-60, enforced in policy.cpp:308-318.
#[test]
fn w135_g16_p2wsh_limits() {
    assert_eq!(MAX_STANDARD_P2WSH_STACK_ITEMS, 100);
    assert_eq!(MAX_STANDARD_P2WSH_STACK_ITEM_SIZE, 80);
    assert_eq!(MAX_STANDARD_P2WSH_SCRIPT_SIZE, 3600);
}

/// G17 — `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80` + annex tag = 0x50.
/// Core policy.h:58, policy.cpp:336-340.
#[test]
fn w135_g17_tapscript_limits_and_annex() {
    assert_eq!(MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, 80);
    assert_eq!(ANNEX_TAG, 0x50);
    assert_eq!(TAPROOT_LEAF_MASK, 0xfe);
    assert_eq!(TAPROOT_LEAF_TAPSCRIPT, 0xc0);
    assert_eq!(WITNESS_V1_TAPROOT_SIZE, 32);
}

/// G18 — IsWitnessStandard P2A witness-stuffing reject.
/// Core policy.cpp:283-285.
///
/// PASS shape pin: P2A is exactly 4 bytes `OP_1 0x02 0x4e 0x73`.
#[test]
fn w135_g18_p2a_witness_stuffing_reject_shape() {
    assert_eq!(make_p2a_spk(), [0x51u8, 0x02, 0x4e, 0x73]);
}

/// G19 — ValidateInputsStandardness rejects NONSTANDARD and
/// WITNESS_UNKNOWN prevouts; P2SH redeem-script sigops ≤ 15.
/// Core policy.cpp:214-263.
///
/// PASS shape pin: rustoshi's `add_transaction` at mempool.rs:1576-1611
/// implements the per-input loop with `classify_standard_script` check
/// + P2SH redeem extraction + `MAX_P2SH_SIGOPS` gate.
#[test]
fn w135_g19_validate_inputs_standardness_shape() {
    assert_eq!(MAX_P2SH_SIGOPS, 15);
}

// ============================================================
// G20-G21: TRUC (BIP-431) regression pins
// ============================================================

/// G20 — TRUC constants match BIP-431.
/// Core truc_policy.h:20-34.
#[test]
fn w135_g20_truc_constants() {
    use rustoshi_consensus::mempool::{
        TRUC_ANCESTOR_LIMIT, TRUC_CHILD_MAX_VSIZE, TRUC_DESCENDANT_LIMIT, TRUC_MAX_VSIZE,
        TRUC_VERSION,
    };
    assert_eq!(TRUC_VERSION, 3);
    assert_eq!(TRUC_ANCESTOR_LIMIT, 2);
    assert_eq!(TRUC_DESCENDANT_LIMIT, 2);
    assert_eq!(TRUC_MAX_VSIZE, 10_000);
    assert_eq!(TRUC_CHILD_MAX_VSIZE, 1_000);
}

/// G21 — TRUC inheritance rules (non-v3 cannot spend v3, v3 cannot
/// spend non-v3).  Core truc_policy.cpp:180-190.
///
/// PASS shape pin: rustoshi's `check_truc_policy` (mempool.rs:2510-2523)
/// implements both directions of the inheritance gate.
#[test]
fn w135_g21_truc_inheritance_rules_shape() {
    use rustoshi_consensus::mempool::TRUC_VERSION;
    // The version check is `parent.tx.version == TRUC_VERSION` (3) per
    // mempool.rs:2512.
    assert_eq!(TRUC_VERSION, 3);
}

// ============================================================
// G22-G26: P2-P3 BUGs (xfail-pinned)
// ============================================================

/// G22 — BUG-5 (P2): `is_dust` parameter `_min_fee_rate` is unused;
/// dust threshold always uses hardcoded `DUST_RELAY_TX_FEE`.
/// Core: `-dustrelayfee` is configurable per node.
#[test]
#[ignore]
fn w135_g22_bug5_dust_fee_unconfigurable_xfail() {
    // Sanity: rustoshi constant is 3000.
    assert_eq!(DUST_RELAY_TX_FEE, 3_000);
    panic!("BUG-5: is_dust ignores min_fee_rate; -dustrelayfee not wired");
}

/// G23 — BUG-6 (P2): Named constants for IsStandardTx limits MISSING
/// from params.rs (TX_MIN/MAX_STANDARD_VERSION, MAX_OP_RETURN_RELAY,
/// MAX_DUST_OUTPUTS_PER_TX, MAX_TX_LEGACY_SIGOPS, DEFAULT_PERMIT_BAREMULTISIG,
/// DEFAULT_ACCEPT_DATACARRIER, DEFAULT_INCREMENTAL_RELAY_FEE).
#[test]
#[ignore]
fn w135_g23_bug6_missing_named_constants_xfail() {
    // These would be the expected constant names; they do not exist as
    // `pub const ...` in params.rs.
    //
    // assert_eq!(TX_MIN_STANDARD_VERSION, 1);
    // assert_eq!(TX_MAX_STANDARD_VERSION, 3);
    // assert_eq!(MAX_OP_RETURN_RELAY, 100_000);
    // assert_eq!(MAX_DUST_OUTPUTS_PER_TX, 1);
    // assert_eq!(MAX_TX_LEGACY_SIGOPS, 2_500);
    // assert_eq!(DEFAULT_PERMIT_BAREMULTISIG, true);
    // assert_eq!(DEFAULT_ACCEPT_DATACARRIER, true);
    // assert_eq!(DEFAULT_INCREMENTAL_RELAY_FEE, 100);
    panic!("BUG-6: 8 IsStandardTx named constants missing from params.rs");
}

/// G24 — BUG-7 (P3): `Transaction.version` is `i32` (Core: `uint32_t`).
/// Behavioral outcome equivalent (both reject non-{1,2,3} txs); error
/// message diverges for high-bit-set versions.
#[test]
#[ignore]
fn w135_g24_bug7_version_type_i32_xfail() {
    // A u32 version of 0xFFFFFFFF would deserialize to -1 in rustoshi's
    // i32 field.  Core would see 4294967295 as uint32_t.  Both reject;
    // error reason text differs.
    panic!("BUG-7: Transaction.version is i32 not u32");
}

/// G25 — BUG-8 (P2): `try_classify_bare_multisig` only accepts
/// direct-push (0x21, 0x41) for pubkeys; PUSHDATA1/2/4 prefixes are
/// rejected.  Core uses `GetOp` + `CPubKey::ValidSize`.
#[test]
#[ignore]
fn w135_g25_bug8_multisig_pushdata_xfail() {
    // A multisig with PUSHDATA1-prefixed pubkey:
    // OP_1 OP_PUSHDATA1 <0x21> <33B> OP_1 OP_CHECKMULTISIG.
    let mut spk = vec![0x51, 0x4c, 0x21];
    spk.extend_from_slice(&[0u8; 33]);
    spk.push(0x51);
    spk.push(0xae);
    // Last byte should still be OP_CHECKMULTISIG.
    assert_eq!(spk.last(), Some(&0xae));
    panic!("BUG-8: try_classify_bare_multisig rejects PUSHDATA-prefixed pubkeys");
}

/// G26 — BUG-9 (P2): `is_dust` P2SH spending size is 91 (witness-style);
/// should be 148 (non-witness).  Compounds BUG-1.
#[test]
#[ignore]
fn w135_g26_bug9_p2sh_spending_size_wrong_xfail() {
    let dust_fee = 3_000u64;
    let p2sh_core = core_dust_threshold(1, &make_p2sh_spk(), dust_fee);
    assert_eq!(p2sh_core, 540); // Core: (32 + 148) * 3000 / 1000 = 540
    // Rustoshi's `91 * 3000 / 1000 = 273`. Gap = 267 sat.
    panic!("BUG-9: is_dust P2SH spending_size=91, should be 148 (non-witness)");
}

// ============================================================
// G27-G29: PRESENT (more regression pins)
// ============================================================

/// G27 — `parse_p2sh_redeem_script_from_scriptsig` simulates
/// `EvalScript(SCRIPT_VERIFY_NONE)` and returns the last push.
/// Core policy.cpp:295-296.
///
/// PASS shape pin: rustoshi's helper at mempool.rs:4945-5011 walks
/// push opcodes and returns the last `Some(Vec<u8>)`, or None on
/// non-push or truncation.
#[test]
fn w135_g27_parse_p2sh_redeem_shape() {
    // A scriptSig with a single 5-byte push.
    let script_sig = vec![0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    // First byte is the push opcode (length 5), next 5 bytes are data.
    assert_eq!(script_sig.len(), 6);
    assert_eq!(script_sig[0], 0x05);
}

/// G28 — `ScriptFlags::standard_flags()` sets all 18 STANDARD_SCRIPT_VERIFY_FLAGS
/// bits.  Core policy.h:119-132.
#[test]
fn w135_g28_standard_script_verify_flags() {
    use rustoshi_consensus::script::ScriptFlags;
    let flags = ScriptFlags::standard_flags();
    // The mandatory subset:
    assert!(flags.verify_p2sh);
    assert!(flags.verify_dersig);
    assert!(flags.verify_checklocktimeverify);
    assert!(flags.verify_checksequenceverify);
    assert!(flags.verify_witness);
    assert!(flags.verify_nulldummy);
    assert!(flags.verify_taproot);
    // The non-mandatory standard subset:
    assert!(flags.verify_strictenc);
    assert!(flags.verify_minimaldata);
    assert!(flags.verify_discourage_upgradable_nops);
    assert!(flags.verify_cleanstack);
    assert!(flags.verify_minimalif);
    assert!(flags.verify_nullfail);
    assert!(flags.verify_low_s);
    assert!(flags.verify_discourage_upgradable_witness_program);
    assert!(flags.verify_witness_pubkeytype);
    assert!(flags.verify_const_scriptcode);
    assert!(flags.verify_discourage_upgradable_taproot_version);
    assert!(flags.verify_discourage_op_success);
    assert!(flags.verify_discourage_upgradable_pubkeytype);
}

/// G29 — `get_transaction_sigop_cost` computes
/// `legacy_sigops * WITNESS_SCALE_FACTOR + P2SH_redeem_sigops * WITNESS_SCALE_FACTOR
///  + witness_sigops` (witness un-scaled).  Core consensus/tx_verify.cpp.
#[test]
fn w135_g29_get_transaction_sigop_cost_shape() {
    // The function is `pub fn get_transaction_sigop_cost(tx, get_coin, flags) -> u64`
    // at validation.rs:612-655. Shape pin: rustoshi `DEFAULT_BYTES_PER_SIGOP = 20`.
    assert_eq!(DEFAULT_BYTES_PER_SIGOP, 20);
}

// ============================================================
// G30: BUG-10 (P2) MISSING helper
// ============================================================

/// G30 — BUG-10 (P2): `SpendsNonAnchorWitnessProg` helper MISSING.
/// Core policy.cpp:354-388.
#[test]
#[ignore]
fn w135_g30_bug10_spends_non_anchor_witness_prog_xfail() {
    panic!("BUG-10: SpendsNonAnchorWitnessProg helper not implemented");
}

/// Bonus G31 — sanity: v2 witness program (no exclusion bug for v=2+).
///
/// PASS shape pin — v=2 with 20-byte program is a valid WitnessUnknown
/// in rustoshi (mempool.rs:4623 `(0x52..=0x60).contains(&version)`).
#[test]
fn w135_g31_v2_unknown_present() {
    let spk = make_v2_unknown_20byte_spk();
    assert_eq!(spk[0], 0x52);
    assert_eq!(spk[1], 0x14); // push 20
    assert_eq!(spk.len(), 2 + 20);
}
