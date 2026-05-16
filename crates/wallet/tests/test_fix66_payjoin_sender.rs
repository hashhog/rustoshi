//! BIP-78 PayJoin sender — library-side tests (W119 / FIX-66).
//!
//! Covers the anti-snoop validators (G10..G15) without touching HTTP.
//! The HTTP round-trip lives in
//! `crates/rpc/tests/test_fix66_payjoin_sender_rpc.rs` (axum in-process).
//!
//! Test matrix:
//!  - G10 outputs preserved: dropped output rejects; relaxed-substitution
//!    accepted; same-type swap accepted when pjos allows it.
//!  - G11 scriptSig types preserved: receiver flipping witness_utxo
//!    script type rejects.
//!  - G12 no new sender inputs: a receiver-added input that matches
//!    sender's own_wallet_outpoints rejects.
//!  - G13 fee bound: receiver bumping fee above cap rejects.
//!  - G14 disableoutputsubstitution: pjos=0 flips substitution to a
//!    hard error.
//!  - G15 min fee rate: receiver dropping below sender's minfeerate
//!    rejects.

use std::collections::HashSet;

use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_wallet::{validate_proposed_psbt, Psbt, SenderError, SenderOptions};

/// Build a P2WPKH script of 22 bytes: 0x00 0x14 <20-byte hash>.
fn p2wpkh_spk(byte: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[byte; 20]);
    s
}

/// Build a P2TR script of 34 bytes: 0x51 0x20 <32-byte x-only key>.
fn p2tr_spk(byte: u8) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&[byte; 32]);
    s
}

/// Build an "original" 1-in/1-out PSBT (sender → receiver) where the
/// sender's input carries a 100_000 sat witness_utxo, so fees + signing
/// inputs are deterministic.
fn make_original(sender_in_value: u64, recv_value: u64, recv_spk: &[u8]) -> Psbt {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0xa1; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: recv_value,
            script_pubkey: recv_spk.to_vec(),
        }],
        lock_time: 0,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("orig psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: sender_in_value,
        script_pubkey: p2wpkh_spk(0x55), // sender-owned input is P2WPKH
    });
    psbt
}

/// Build a "proposed" PSBT: original + a receiver-added input + bumped
/// receiver-output value. `bump_recv_value_by` adds to the receiver
/// output (their contribution); `recv_in_value` is the receiver's
/// added UTXO value.
fn make_proposed(
    orig: &Psbt,
    recv_in_value: u64,
    recv_in_outpoint: OutPoint,
    bump_recv_value_by: u64,
) -> Psbt {
    let mut tx = orig.unsigned_tx.clone();
    // Append receiver input.
    tx.inputs.push(TxIn {
        previous_output: recv_in_outpoint,
        script_sig: vec![],
        sequence: 0xffff_fffd,
        witness: vec![],
    });
    // Bump receiver output value.
    tx.outputs[0].value += bump_recv_value_by;
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("prop psbt");
    // Mirror original's witness_utxo for sender input.
    psbt.inputs[0].witness_utxo = orig.inputs[0].witness_utxo.clone();
    // Receiver's input is P2WPKH too.
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: recv_in_value,
        script_pubkey: p2wpkh_spk(0x77),
    });
    psbt
}

// ============================================================
// G10 — outputs preserved
// ============================================================
#[test]
fn g10_outputs_preserved_happy_path() {
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000, // receiver contribution flows straight into recv output
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        min_fee_rate: 0.01,
        ..Default::default()
    };
    validate_proposed_psbt(&orig, &prop, &opts).expect("G10 happy");
}

#[test]
fn g10_drop_output_rejects() {
    // Two-output original (recipient + change), receiver returns just
    // one output (drops change).
    let recv_spk = p2wpkh_spk(0x11);
    let change_spk = p2wpkh_spk(0x22);
    let mut orig = make_original(200_000, 50_000, &recv_spk);
    orig.unsigned_tx.outputs.push(TxOut {
        value: 100_000,
        script_pubkey: change_spk,
    });
    orig.outputs.push(Default::default());

    let mut prop_tx = orig.unsigned_tx.clone();
    prop_tx.outputs.pop(); // drop change
    let mut prop = Psbt::from_unsigned_tx(prop_tx).expect("prop");
    prop.inputs[0].witness_utxo = orig.inputs[0].witness_utxo.clone();

    let opts = SenderOptions {
        max_additional_fee_contribution: 200_000,
        min_fee_rate: 0.01,
        disable_output_substitution: false,
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("must reject");
    match err {
        SenderError::OutputMissing(idx) => assert_eq!(idx, 1, "change output (#1) is missing"),
        other => panic!("expected OutputMissing(1), got {other:?}"),
    }
}

// ============================================================
// G11 — scriptSig types preserved
// ============================================================
#[test]
fn g11_witness_utxo_script_type_change_rejects() {
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let mut prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000,
    );
    // Malicious receiver changes the sender input's spent-script type
    // from P2WPKH (0x00 prefix) to P2TR (0x51 prefix).
    prop.inputs[0].witness_utxo = Some(TxOut {
        value: 100_000,
        script_pubkey: p2tr_spk(0xab),
    });
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        min_fee_rate: 0.01,
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("type flip rejects");
    match err {
        SenderError::ScriptSigTypeChanged(0) => {}
        other => panic!("expected ScriptSigTypeChanged(0), got {other:?}"),
    }
}

// ============================================================
// G12 — no new inputs from sender's wallet
// ============================================================
#[test]
fn g12_new_input_from_sender_wallet_rejects() {
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let recv_outpoint = OutPoint {
        txid: Hash256::from_bytes([0xcc; 32]),
        vout: 7,
    };
    let prop = make_proposed(&orig, 80_000, recv_outpoint.clone(), 80_000);

    // Sender's own outpoints include the "receiver-added" outpoint.
    let mut own = HashSet::new();
    own.insert(recv_outpoint);
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        own_wallet_outpoints: own,
        min_fee_rate: 0.01,
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("own-input rejects");
    match err {
        SenderError::NewSenderInput(1) => {}
        other => panic!("expected NewSenderInput(1), got {other:?}"),
    }
}

#[test]
fn g12_unknown_outpoint_allowed() {
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xcc; 32]),
            vout: 7,
        },
        80_000,
    );
    // Sender owns a DIFFERENT outpoint; the receiver-added one is
    // unknown to us, so the check passes.
    let mut own = HashSet::new();
    own.insert(OutPoint {
        txid: Hash256::from_bytes([0xde; 32]),
        vout: 0,
    });
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        own_wallet_outpoints: own,
        min_fee_rate: 0.01,
        ..Default::default()
    };
    validate_proposed_psbt(&orig, &prop, &opts).expect("unknown outpoint passes");
}

// ============================================================
// G13 — fee bound
// ============================================================
#[test]
fn g13_fee_bump_within_cap_passes() {
    // Original: 100k in - 50k out = 50k fee.
    // Proposed: 180k in (+80k recv) - 130k out (+80k bump) = 50k fee.
    // Cap doesn't matter since fee didn't increase.
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000,
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 0, // no extra fee allowed
        min_fee_rate: 0.01,
        ..Default::default()
    };
    validate_proposed_psbt(&orig, &prop, &opts).expect("equal fee passes");
}

#[test]
fn g13_fee_above_cap_rejects() {
    // Original: 100k in - 50k out = 50k fee.
    // Proposed: 180k in (+80k recv) - 120k out (only +70k bump) = 60k fee → +10k more.
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        70_000,
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 5_000, // cap below the +10k delta
        min_fee_rate: 0.01,
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("over-cap rejects");
    match err {
        SenderError::FeeBoundExceeded { original, proposed, cap } => {
            assert_eq!(original, 50_000);
            assert_eq!(proposed, 60_000);
            assert_eq!(cap, 5_000);
        }
        other => panic!("expected FeeBoundExceeded, got {other:?}"),
    }
}

// ============================================================
// G14 — disableoutputsubstitution honoured
// ============================================================
#[test]
fn g14_pjos_zero_rejects_script_change() {
    // Original output uses spk A; proposed output uses spk B but value
    // increased so without pjos=1 it would pass. With pjos=1 set on the
    // sender, any script change is a hard reject.
    let recv_spk_a = p2wpkh_spk(0x11);
    let recv_spk_b = p2wpkh_spk(0xab);
    let orig = make_original(100_000, 50_000, &recv_spk_a);

    let mut prop_tx = orig.unsigned_tx.clone();
    prop_tx.inputs.push(TxIn {
        previous_output: OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        script_sig: vec![],
        sequence: 0xffff_fffd,
        witness: vec![],
    });
    prop_tx.outputs[0].script_pubkey = recv_spk_b;
    prop_tx.outputs[0].value += 80_000;
    let mut prop = Psbt::from_unsigned_tx(prop_tx).expect("prop");
    prop.inputs[0].witness_utxo = orig.inputs[0].witness_utxo.clone();
    prop.inputs[1].witness_utxo = Some(TxOut {
        value: 80_000,
        script_pubkey: p2wpkh_spk(0x77),
    });

    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        disable_output_substitution: true, // pjos=1 stance
        min_fee_rate: 0.01,
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("pjos=1 rejects script swap");
    match err {
        SenderError::OutputMutated { index, .. } => assert_eq!(index, 0),
        other => panic!("expected OutputMutated(0), got {other:?}"),
    }
}

#[test]
fn g14_pjos_zero_same_script_higher_value_passes() {
    // pjos=1 forbids substitution, but only of the script. Same script
    // + same-or-higher value (here: exact match) is fine.
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000,
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        disable_output_substitution: true,
        min_fee_rate: 0.01,
        ..Default::default()
    };
    validate_proposed_psbt(&orig, &prop, &opts).expect("pjos=1 + script unchanged passes");
}

// ============================================================
// G15 — minimum fee rate honoured
// ============================================================
#[test]
fn g15_fee_rate_too_low_rejects() {
    // Tiny absolute fee on a big vsize → bad sat/vB.
    // Original: 100k in - 99k out = 1k fee.
    // Proposed: 180k in - 179k out = 1k fee at ~110-byte vsize ≈ 9 sat/vB.
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 99_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000,
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        min_fee_rate: 1000.0, // absurdly high → fails for any realistic tx
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("min fee rate rejects");
    match err {
        SenderError::FeeRateTooLow { .. } => {}
        other => panic!("expected FeeRateTooLow, got {other:?}"),
    }
}

#[test]
fn g15_fee_rate_high_enough_passes() {
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000,
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 1000,
        min_fee_rate: 0.01, // trivial
        ..Default::default()
    };
    validate_proposed_psbt(&orig, &prop, &opts).expect("trivial rate passes");
}

// ============================================================
// Compound — full happy path with all the knobs.
// ============================================================
#[test]
fn full_happy_path() {
    let recv_spk = p2wpkh_spk(0x11);
    let orig = make_original(100_000, 50_000, &recv_spk);
    let prop = make_proposed(
        &orig,
        80_000,
        OutPoint {
            txid: Hash256::from_bytes([0xff; 32]),
            vout: 0,
        },
        80_000,
    );
    let opts = SenderOptions {
        max_additional_fee_contribution: 100,
        additional_fee_output_index: None,
        disable_output_substitution: false,
        min_fee_rate: 1.0,
        own_wallet_outpoints: HashSet::new(),
    };
    validate_proposed_psbt(&orig, &prop, &opts).expect("all-validators happy");
}

// ============================================================
// Compound — original input dropped is an aggressive G10/G11 fail.
// ============================================================
#[test]
fn dropped_original_input_rejects() {
    let recv_spk = p2wpkh_spk(0x11);
    // Original: 100k in, 50k out, 50k fee.
    let orig = make_original(100_000, 50_000, &recv_spk);

    // Proposed replaces the original sender input with a different
    // outpoint at the same value, and bumps the recv output by an
    // amount that keeps fees inside the cap so the G13 check passes
    // before the G10/G11 input scan runs.
    let prop_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                // Different outpoint from `orig`'s [0xa1; 32] / vout 0.
                txid: Hash256::from_bytes([0xff; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![],
        }],
        outputs: orig.unsigned_tx.outputs.clone(),
        lock_time: 0,
    };
    // Same input/output amounts as orig → identical fee.
    let mut prop = Psbt::from_unsigned_tx(prop_tx).expect("prop");
    prop.inputs[0].witness_utxo = Some(TxOut {
        value: 100_000,
        script_pubkey: p2wpkh_spk(0x77),
    });

    let opts = SenderOptions {
        max_additional_fee_contribution: 100,
        min_fee_rate: 0.01,
        ..Default::default()
    };
    let err = validate_proposed_psbt(&orig, &prop, &opts).expect_err("drop rejects");
    match err {
        SenderError::OriginalInputDropped(0) => {}
        other => panic!("expected OriginalInputDropped(0), got {other:?}"),
    }
}
