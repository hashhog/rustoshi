//! Fuzz target: script interpreter.
//!
//! Input layout:
//!   [0..3]  flag-selection bytes (24 bits -> the 21 ScriptFlags bools)
//!   [3]     sig_version selector + verify_script/eval_script mode bit
//!   [4..5]  split point for script_sig vs script_pubkey (verify mode)
//!   rest    script bytes
//!
//! Uses `DummyChecker` so no real signatures are needed; the interpreter's
//! parsing, stack handling, numeric ops, and control flow are all exercised.
//! Must never panic or hang (interpreter enforces MAX_OPS/MAX_STACK/etc).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustoshi_consensus::{eval_script, verify_script, DummyChecker, ScriptFlags, SigVersion};

fn flags_from(bits: u32) -> ScriptFlags {
    let b = |n: u32| bits & (1 << n) != 0;
    ScriptFlags {
        verify_p2sh: b(0),
        verify_dersig: b(1),
        verify_checklocktimeverify: b(2),
        verify_checksequenceverify: b(3),
        verify_witness: b(4),
        verify_nulldummy: b(5),
        verify_nullfail: b(6),
        verify_witness_pubkeytype: b(7),
        verify_taproot: b(8),
        verify_strictenc: b(9),
        verify_low_s: b(10),
        verify_sigpushonly: b(11),
        verify_minimaldata: b(12),
        verify_cleanstack: b(13),
        verify_discourage_upgradable_nops: b(14),
        verify_discourage_upgradable_witness_program: b(15),
        verify_minimalif: b(16),
        verify_discourage_upgradable_taproot_version: b(17),
        verify_discourage_op_success: b(18),
        verify_discourage_upgradable_pubkeytype: b(19),
        verify_const_scriptcode: b(20),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let bits = u32::from_le_bytes([data[0], data[1], data[2], 0]);
    let flags = flags_from(bits);
    let sel = data[3];
    let split_hint = u16::from_le_bytes([data[4], data[5]]) as usize;
    let script = &data[6..];
    let checker = DummyChecker;

    if sel & 0x80 != 0 {
        // verify_script mode: split input into scriptSig | scriptPubkey,
        // witness items derived from the tail.
        let split = if script.is_empty() { 0 } else { split_hint % (script.len() + 1) };
        let (sig, pubkey) = script.split_at(split);
        let witness: Vec<Vec<u8>> = pubkey
            .chunks(17)
            .take(4)
            .map(|c| c.to_vec())
            .collect();
        let _ = verify_script(sig, pubkey, &witness, &flags, &checker);
    } else {
        // NOTE: only Base / WitnessV0 are valid for the direct `eval_script`
        // entry point. `SigVersion::Tapscript` execution is seeded with a
        // BIP-342 validation-weight budget and MUST go through
        // `eval_script_tapscript` / `with_stack_tapscript`; feeding Tapscript
        // here trips a debug-only `debug_assert!(validation_weight_init)` that
        // is compiled out in the production fleet build (release, no
        // debug-assertions) and is therefore a harness misuse, not a decoder
        // bug. Restricting the selector keeps the target exercising only real
        // production code paths.
        let sig_version = if sel & 0x01 == 0 {
            SigVersion::Base
        } else {
            SigVersion::WitnessV0
        };
        let mut stack = Vec::new();
        let _ = eval_script(&mut stack, script, &flags, &checker, sig_version);
    }
});
