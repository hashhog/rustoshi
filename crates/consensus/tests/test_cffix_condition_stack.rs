//! cffix-rustoshi-tapscript-condition-stack: tapscript condition handling
//! must be O(1) per opcode.
//!
//! Tapscript is exempt from the 10,000-byte script-size limit and the
//! 201 op-count limit (BIP-342), so IF/NOTIF nesting depth is bounded only
//! by the block size. If "am I in an executing branch?" is answered by
//! scanning the whole condition stack, a script of the shape
//!
//! ```text
//! (OP_1 OP_IF) x K   OP_NOP x M   OP_ENDIF x K   OP_1
//! ```
//!
//! costs O(K * (K + M)) reads: with K = 16000 and M = 20 * K (~370 KB) that
//! is ~6e9 reads, run twice per mempool acceptance and again per block.
//!
//! Core avoids this with `class ConditionStack` (src/script/interpreter.cpp)
//! which keeps only the stack size and the position of the first false
//! entry. This test scales K by 8 (with M proportional to K): a linear
//! interpreter grows ~8x, a quadratic one ~64x. The bound of 16 allows
//! linear plus timing noise.

use rustoshi_consensus::script::interpreter::{
    eval_script_tapscript, DummyChecker, ScriptFlags, Stack, TapscriptCtx,
};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Serializes the CPU-heavy tests in this binary so the timing test is not
/// measured while the 200k-script differential runs on another thread.
static SERIAL: Mutex<()> = Mutex::new(());

const OP_1: u8 = 0x51;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_NOP: u8 = 0x61;

fn deep_if_script(k: usize, m: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(4 * k + m + 1);
    for _ in 0..k {
        s.push(OP_1);
        s.push(OP_IF);
    }
    s.extend(std::iter::repeat(OP_NOP).take(m));
    s.extend(std::iter::repeat(OP_ENDIF).take(k));
    s.push(OP_1);
    s
}

fn run(script: &[u8]) -> (Result<(), rustoshi_consensus::script::interpreter::ScriptError>, Stack) {
    let flags = ScriptFlags::default();
    let leaf = [0u8; 32];
    let mut stack: Stack = Vec::new();
    let r = eval_script_tapscript(
        &mut stack,
        script,
        &flags,
        &DummyChecker,
        TapscriptCtx { tapleaf_hash: &leaf, annex: None },
        1_000_000,
    );
    (r, stack)
}

/// Best of three wall-clock runs, asserting the result each time.
fn time_it(k: usize) -> Duration {
    let script = deep_if_script(k, 20 * k);
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let (r, stack) = run(&script);
        let el = t.elapsed();
        assert!(r.is_ok(), "K={k}: expected Ok, got {r:?}");
        assert_eq!(stack, vec![vec![0x01u8]], "K={k}: expected one true element");
        best = best.min(el);
    }
    best
}

#[test]
fn tapscript_deep_if_nesting_is_linear() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let small = time_it(2000);
    let large = time_it(16000);
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-9);
    eprintln!("K=2000: {small:?}  K=16000: {large:?}  ratio={ratio:.1}");
    assert!(
        ratio < 16.0,
        "condition handling is super-linear: K=2000 {small:?}, K=16000 {large:?}, ratio {ratio:.1} (linear ~8, quadratic ~64)"
    );
}

/// Semantics guard for the O(1) condition stack: nested false branches,
/// OP_ELSE inside a non-executing parent, and NOTIF must behave exactly as
/// the naive "all entries true" model.
#[test]
fn tapscript_condition_stack_semantics() {
    // OP_0 OP_IF (OP_1 OP_IF OP_0 OP_ELSE OP_0 OP_ENDIF) OP_ELSE OP_1 OP_ENDIF
    // The inner IF/ELSE sits under a false parent; its ELSE must not
    // make the inner body execute. Result: one true element.
    let s = vec![
        0x00, OP_IF, OP_1, OP_IF, 0x00, OP_ELSE, 0x00, OP_ENDIF, OP_ELSE, OP_1, OP_ENDIF,
    ];
    let (r, st) = run(&s);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(st, vec![vec![0x01u8]]);

    // OP_1 OP_NOTIF OP_0 OP_ELSE OP_1 OP_ENDIF -> true
    let s = vec![OP_1, OP_NOTIF, 0x00, OP_ELSE, OP_1, OP_ENDIF];
    let (r, st) = run(&s);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(st, vec![vec![0x01u8]]);

    // Multiple ELSE toggles: OP_1 OP_IF OP_ELSE OP_ELSE OP_1 OP_ENDIF -> true
    let s = vec![OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_1, OP_ENDIF];
    let (r, st) = run(&s);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(st, vec![vec![0x01u8]]);

    // False at depth 1 of 3, inner ELSE toggles must keep it skipped.
    // OP_1 OP_IF OP_0 OP_IF OP_1 OP_IF OP_ELSE OP_0 OP_ENDIF OP_ELSE OP_1 OP_ENDIF OP_ENDIF
    let s = vec![
        OP_1, OP_IF, 0x00, OP_IF, OP_1, OP_IF, OP_ELSE, 0x00, OP_ENDIF, OP_ELSE, OP_1,
        OP_ENDIF, OP_ENDIF,
    ];
    let (r, st) = run(&s);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(st, vec![vec![0x01u8]]);

    // Unbalanced: stray ELSE / ENDIF / unclosed IF all fail.
    for s in [vec![OP_ELSE], vec![OP_ENDIF], vec![OP_1, OP_IF, OP_1]] {
        let (r, _) = run(&s);
        assert!(r.is_err(), "expected unbalanced error for {s:02x?}");
    }

    // MINIMALIF stays a tapscript consensus rule: OP_2 OP_IF fails.
    let (r, _) = run(&[0x52, OP_IF, OP_1, OP_ENDIF]);
    assert!(r.is_err(), "MINIMALIF must reject [0x02]");
}

/// Reference model: the pre-fix `Vec<bool>` condition stack, where a branch
/// executes iff every entry is true and an unexecuted OP_ELSE only flips the
/// top when the parent branch is executing. Interprets the token subset used
/// by `condition_stack_matches_reference_model` (OP_0, OP_1, OP_2, OP_NOP,
/// OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF) under tapscript rules (MINIMALIF).
/// Returns Some(final stack) on success, None on any script error.
fn reference_eval(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut vf: Vec<bool> = Vec::new();
    for &op in script {
        let exec = vf.iter().all(|&b| b);
        if !exec {
            match op {
                OP_IF | OP_NOTIF => vf.push(false),
                OP_ELSE => {
                    if vf.is_empty() {
                        return None;
                    }
                    let n = vf.len();
                    if vf[..n - 1].iter().all(|&b| b) {
                        vf[n - 1] = !vf[n - 1];
                    }
                }
                OP_ENDIF => {
                    vf.pop()?;
                }
                _ => {}
            }
            continue;
        }
        match op {
            0x00 => stack.push(vec![]),
            OP_1 => stack.push(vec![1]),
            0x52 => stack.push(vec![2]),
            OP_NOP => {}
            OP_IF | OP_NOTIF => {
                let v = stack.pop()?;
                // Tapscript MINIMALIF: only [] and [0x01].
                if v.len() > 1 || (v.len() == 1 && v[0] != 1) {
                    return None;
                }
                let b = !v.is_empty();
                vf.push(if op == OP_IF { b } else { !b });
            }
            OP_ELSE => {
                let t = vf.last_mut()?;
                *t = !*t;
            }
            OP_ENDIF => {
                vf.pop()?;
            }
            _ => unreachable!(),
        }
    }
    if vf.is_empty() {
        Some(stack)
    } else {
        None
    }
}

/// Differential guard for the consensus risk of the ConditionStack change:
/// over 200,000 deterministic pseudo-random scripts built from push and
/// flow-control opcodes, `eval_script_tapscript` must agree with the
/// pre-fix model on accept/reject and on the final stack. A wrong
/// first-false bookkeeping (e.g. ELSE under a false parent re-enabling a
/// branch, or ENDIF not clearing the false marker) would execute or skip
/// the wrong pushes and show up here as a stack or verdict mismatch.
#[test]
fn condition_stack_matches_reference_model() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const TOKENS: [u8; 8] = [0x00, OP_1, 0x52, OP_NOP, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF];
    // xorshift64*, fixed seed: deterministic across runs.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let (mut ok, mut err) = (0u32, 0u32);
    for _ in 0..200_000 {
        let len = 1 + (next() % 24) as usize;
        // Bias toward pushes of 0/1 so IF arguments are usually MINIMALIF-valid.
        let script: Vec<u8> = (0..len)
            .map(|_| {
                let r = next() % 16;
                if r < 8 { TOKENS[(r % 2) as usize] } else { TOKENS[(r - 8) as usize] }
            })
            .collect();
        let want = reference_eval(&script);
        let (r, st) = run(&script);
        match (&want, &r) {
            (Some(ws), Ok(())) => {
                assert_eq!(&st, ws, "stack mismatch for {script:02x?}");
                ok += 1;
            }
            (None, Err(_)) => err += 1,
            _ => panic!("verdict mismatch for {script:02x?}: model {want:?}, interpreter {r:?}"),
        }
    }
    eprintln!("reference model agreement: {ok} accepted, {err} rejected");
    // The generator must reach both outcomes, or the comparison is vacuous.
    assert!(ok > 10_000 && err > 10_000, "degenerate sample: ok={ok} err={err}");
}
