//! cffix-rustoshi-witness-malleation-before-weight: production wiring.
//!
//! The P2P connect loop in `main.rs` is a closure inside the node's async
//! main loop and cannot be driven from a test. It marks a block's hash
//! FAILED_VALIDITY (`invalid_block_hashes.insert`, then
//! `mark_connect_failed_block_invalid`) exactly when `process_block` returns
//! an error for which `connect_error_is_verdict` holds, i.e.
//! `ValidationError::is_invalid_block_verdict`. The consensus-crate test
//! `test_cffix_witness_malleation_order.rs` shows that a witness-padded copy
//! of an honest block now comes back from `process_block` as
//! BadWitnessNonceSize / BadWitnessCommitment, which are not verdicts. This
//! file pins the two source facts that make that sufficient:
//!
//! 1. the weight check is out of `check_block_with_pow` and sits in
//!    `contextual_check_block` after `check_witness_commitment` (Core
//!    ContextualCheckBlock, src/validation.cpp:4169-4181) — fails on master;
//! 2. the connect loop marks a hash only through `connect_error_is_verdict`,
//!    which is `is_invalid_block_verdict` — passes on master, and guards
//!    against a later edit that marks on every error.

use rustoshi_consensus::ValidationError;

const MAIN_RS: &str = include_str!("../src/main.rs");
const VALIDATION_RS: &str = include_str!("../../crates/consensus/src/validation.rs");

/// Body of the top-level `fn` starting at `sig` (up to the first line that is
/// exactly `}`).
fn fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
    let start = src.find(sig).unwrap_or_else(|| panic!("`{sig}` not found"));
    let rest = &src[start..];
    let end = rest.find("\n}\n").expect("end of fn");
    &rest[..end]
}

/// Code lines only (drop `//` comments) so a comment naming a function does
/// not count as a call.
fn code(body: &str) -> String {
    body.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn cffix_weight_check_runs_after_witness_malleation_not_in_check_block() {
    let check_block = code(fn_body(VALIDATION_RS, "pub fn check_block_with_pow("));
    assert!(
        !check_block.contains("compute_block_weight("),
        "check_block_with_pow must not run the witness-inclusive weight check: witness \
         bytes are not covered by the block hash (Core CheckBlock checks only the \
         stripped size, validation.cpp:3940-3948)"
    );
    assert!(
        check_block.contains("BlockLengthTooLarge"),
        "the stripped-size gate (bad-blk-length) must stay in check_block"
    );

    let contextual = code(fn_body(VALIDATION_RS, "pub fn contextual_check_block("));
    let malleation = contextual
        .find("check_witness_commitment(")
        .expect("contextual_check_block runs the witness malleation check");
    let weight = contextual
        .find("compute_block_weight(")
        .expect("contextual_check_block runs the weight check");
    assert!(
        malleation < weight,
        "the weight check must run after check_witness_commitment (Core \
         ContextualCheckBlock order, validation.cpp:4169-4181)"
    );
}

#[test]
fn cffix_connect_loop_marks_only_on_a_verdict() {
    let verdict_fn = code(fn_body(MAIN_RS, "fn connect_error_is_verdict("));
    assert!(
        verdict_fn.contains("e.is_invalid_block_verdict()"),
        "connect_error_is_verdict must defer to is_invalid_block_verdict"
    );
    // Both connect loops (the P2P block-processing loop and the foreground
    // IBD loop): `connect_invalid` is set only in the verdict branch, and the
    // hash is inserted into `invalid_block_hashes` only when it is set.
    let lines: Vec<&str> = MAIN_RS.lines().map(str::trim).collect();
    let setters: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i] == "connect_invalid = true;")
        .collect();
    assert!(!setters.is_empty(), "connect loops set connect_invalid");
    for &i in &setters {
        assert_eq!(
            lines[i - 1],
            "} else if connect_error_is_verdict(&e) {",
            "main.rs line {}: connect_invalid must be set only on a verdict",
            i + 1
        );
    }
    let guards: Vec<usize> =
        (0..lines.len()).filter(|&i| lines[i] == "if connect_invalid {").collect();
    assert_eq!(guards.len(), setters.len(), "one mark site per connect loop");
    for &i in &guards {
        assert_eq!(lines[i + 1], "invalid_block_hashes.insert(block_hash);");
    }
}

/// The errors a padded copy produces are not verdicts, and the error a
/// committed overweight block produces still is.
#[test]
fn cffix_mutated_witness_errors_are_not_verdicts_weight_is() {
    assert!(!ValidationError::BadWitnessNonceSize.is_invalid_block_verdict());
    assert!(!ValidationError::BadWitnessCommitment.is_invalid_block_verdict());
    assert!(!ValidationError::UnexpectedWitness.is_invalid_block_verdict());
    assert!(ValidationError::WeightExceeded(4_000_001).is_invalid_block_verdict());
}
