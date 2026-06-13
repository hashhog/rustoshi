//! `converttopsbt` + `joinpsbts` — pure offline RPC functional tests.
//!
//! No node, no regtest sync, no network: each test constructs a bare
//! `RpcServerImpl` over a throwaway `ChainDb` (these two handlers never touch
//! chain/wallet state) and exercises the handler logic directly.
//!
//! References (Bitcoin Core v31.99):
//!   - `src/rpc/rawtransaction.cpp::converttopsbt` (1663)
//!   - `src/rpc/rawtransaction.cpp::joinpsbts`     (1778)
//!   - `src/psbt.cpp::PartiallySignedTransaction::AddInput` (52-63)
//!   - `src/core_io.cpp::DecodeTx` (full byte-consumption gate)
//!
//! Error codes (Core `protocol.h`):
//!   RPC_DESERIALIZATION_ERROR = -22, RPC_INVALID_PARAMETER = -8.

use std::sync::Arc;

use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{PeerState, RpcState, RpcServerImpl, RustoshiRpcServer};
use rustoshi_storage::ChainDb;
use rustoshi_wallet::Psbt;
use tokio::sync::RwLock;

const RPC_DESERIALIZATION_ERROR: i32 = -22;
const RPC_INVALID_PARAMETER: i32 = -8;

/// Bare RPC server with no chain state — `converttopsbt`/`joinpsbts` are pure
/// over their inputs and never read `self.state`.
fn server() -> RpcServerImpl {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
    let state = Arc::new(RwLock::new(RpcState::new(
        db,
        rustoshi_consensus::ChainParams::regtest(),
    )));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    RpcServerImpl::new(state, peer_state)
}

/// A non-coinbase outpoint with a deterministic txid byte pattern.
fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Hash256([byte; 32]),
        vout,
    }
}

/// Standard "no-data" output (a 1-of-nothing OP_TRUE for a valid push-free
/// script). We only care that it round-trips, so any valid scriptPubKey works.
fn op_true_out(value: u64) -> TxOut {
    TxOut {
        value,
        script_pubkey: vec![0x51], // OP_TRUE
    }
}

// ===========================================================================
// converttopsbt
// ===========================================================================

#[tokio::test]
async fn converttopsbt_rejects_inputs_with_scriptsig() {
    let srv = server();

    // One input carrying a (dummy) scriptSig; permitsigdata defaults to false.
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: outpoint(0x11, 0),
            script_sig: vec![0x47, 0x30], // non-empty scriptSig (sig data)
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![op_true_out(1000)],
        lock_time: 0,
    };
    let hex_tx = hex::encode(tx.serialize());

    let err = srv
        .converttopsbt(hex_tx.clone(), None, None)
        .await
        .expect_err("inputs with scriptSig must be rejected when permitsigdata=false");
    assert_eq!(
        err.code(),
        RPC_DESERIALIZATION_ERROR,
        "scriptSig present + permitsigdata=false must be -22"
    );
    assert!(
        err.message()
            .contains("Inputs must not have scriptSigs and scriptWitnesses"),
        "unexpected message: {}",
        err.message()
    );

    // permitsigdata=true: conversion proceeds and the scriptSig is CLEARED.
    let b64 = srv
        .converttopsbt(hex_tx, Some(true), None)
        .await
        .expect("permitsigdata=true must allow conversion");
    let psbt = Psbt::from_base64(&b64).expect("valid PSBT base64");
    assert_eq!(psbt.unsigned_tx.inputs.len(), 1);
    assert!(
        psbt.unsigned_tx.inputs[0].script_sig.is_empty(),
        "scriptSig must be cleared after permitsigdata conversion"
    );
}

#[tokio::test]
async fn converttopsbt_produces_blank_per_input_and_per_output_maps() {
    let srv = server();

    // 2 inputs (no sig data), 2 outputs.
    let tx = Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: outpoint(0x22, 0),
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: vec![],
            },
            TxIn {
                previous_output: outpoint(0x33, 7),
                script_sig: vec![],
                sequence: 0xffff_ffff,
                witness: vec![],
            },
        ],
        outputs: vec![op_true_out(500), op_true_out(600)],
        lock_time: 0,
    };
    let hex_tx = hex::encode(tx.serialize());

    let b64 = srv
        .converttopsbt(hex_tx, None, None)
        .await
        .expect("clean tx must convert");
    let psbt = Psbt::from_base64(&b64).expect("valid PSBT base64");

    // One blank per-input map and one blank per-output map.
    assert_eq!(psbt.inputs.len(), 2, "one per-input map per input");
    assert_eq!(psbt.outputs.len(), 2, "one per-output map per output");
    for inp in &psbt.inputs {
        assert!(inp.is_null(), "per-input map must be blank");
    }
    for out in &psbt.outputs {
        assert!(out.is_null(), "per-output map must be blank");
    }
    // The unsigned tx is preserved verbatim.
    assert_eq!(psbt.unsigned_tx.inputs.len(), 2);
    assert_eq!(psbt.unsigned_tx.outputs.len(), 2);
    assert_eq!(psbt.unsigned_tx.inputs[0].previous_output, outpoint(0x22, 0));
    assert_eq!(psbt.unsigned_tx.inputs[1].sequence, 0xffff_ffff);
}

/// ⭐ The empty-vin full-byte-consumption regression.
///
/// hex `0200000000010000000000000000066a040001020300000000` is a legacy
/// (no-witness) tx with 0 inputs and 1 OP_RETURN output `6a0400010203`. Its
/// leading `00` input-count byte looks like a segwit marker; a witness decode
/// that ignores trailing bytes would silently drop the OP_RETURN output. The
/// handler must reject the witness decode (it consumes only 12 of 25 bytes) and
/// fall back to the legacy decode (which consumes all 25).
const EMPTY_VIN_HEX: &str = "0200000000010000000000000000066a040001020300000000";
const EMPTY_VIN_EXPECTED_PSBT: &str = "cHNidP8BABkCAAAAAAEAAAAAAAAAAAZqBAABAgMAAAAAAAA=";

#[tokio::test]
async fn converttopsbt_empty_vin_heuristic_keeps_op_return_output() {
    let srv = server();

    let b64 = srv
        .converttopsbt(EMPTY_VIN_HEX.to_string(), None, None)
        .await
        .expect("heuristic decode must succeed via legacy fallback");

    // ⭐ Core returns the base64 PSBT verbatim; this is the load-bearing wire
    // assertion. The expected value embeds the 0-input/1-OP_RETURN tx exactly.
    assert_eq!(
        b64, EMPTY_VIN_EXPECTED_PSBT,
        "heuristic converttopsbt must produce the 0-input/1-OP_RETURN PSBT, \
         not a 0-output one"
    );

    // Structurally confirm the embedded raw tx round-trips through the LEGACY
    // (no-witness) decoder with full byte consumption: 0 inputs, 1 OP_RETURN
    // output `6a0400010203`. (We decode the embedded tx bytes directly rather
    // than via `Psbt::from_base64`, whose embedded-tx parse is witness-aware
    // and would itself drop the output for this pathological case.)
    let embedded = embedded_unsigned_tx_from_psbt_b64(&b64);
    assert_eq!(embedded.inputs.len(), 0, "must have 0 inputs");
    assert_eq!(
        embedded.outputs.len(),
        1,
        "the OP_RETURN output must NOT be dropped"
    );
    assert_eq!(
        hex::encode(&embedded.outputs[0].script_pubkey),
        "6a0400010203",
        "output scriptPubKey must be the OP_RETURN 6a0400010203"
    );
    assert_eq!(embedded.outputs[0].value, 0);
}

/// Extract and legacy-decode the embedded unsigned tx (PSBT global key 0x00)
/// from a base64 PSBT, using the no-witness decoder with a full-consumption
/// gate (the converttopsbt-class decode strategy).
fn embedded_unsigned_tx_from_psbt_b64(b64: &str) -> Transaction {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("valid base64");
    // PSBT layout: magic "psbt" 0xff | global map | input maps | output maps.
    // The unsigned tx is the value of global key-type 0x00, encoded as a
    // length-prefixed blob. Walk the magic + the single global key (0x01 0x00),
    // then read the CompactSize-length-prefixed tx blob.
    assert_eq!(&raw[0..5], b"psbt\xff", "PSBT magic");
    let mut i = 5;
    // key length (CompactSize). For PSBT_GLOBAL_UNSIGNED_TX the key is just the
    // single type byte 0x00, so key length == 1.
    let key_len = raw[i] as usize;
    i += 1;
    assert_eq!(key_len, 1, "global unsigned-tx key length");
    assert_eq!(raw[i], 0x00, "PSBT_GLOBAL_UNSIGNED_TX key type");
    i += 1;
    // value: CompactSize length prefix + tx bytes (assume < 253 here).
    let val_len = raw[i] as usize;
    i += 1;
    let tx_bytes = &raw[i..i + val_len];
    let mut cur = std::io::Cursor::new(tx_bytes);
    let tx = Transaction::decode_no_witness(&mut cur).expect("legacy tx decode");
    assert_eq!(
        cur.position() as usize,
        tx_bytes.len(),
        "embedded tx must be fully consumed by the legacy decoder"
    );
    tx
}

#[tokio::test]
async fn converttopsbt_empty_vin_iswitness_true_fails_22() {
    let srv = server();

    // iswitness=true forces the witness decode only; it does NOT fully consume
    // the bytes for this legacy tx, so the conversion must fail with -22.
    let err = srv
        .converttopsbt(EMPTY_VIN_HEX.to_string(), None, Some(true))
        .await
        .expect_err("iswitness=true must fail to decode this legacy tx");
    assert_eq!(
        err.code(),
        RPC_DESERIALIZATION_ERROR,
        "iswitness=true on a non-fully-consuming witness decode must be -22"
    );
    assert!(
        err.message().contains("TX decode failed"),
        "unexpected message: {}",
        err.message()
    );
}

#[tokio::test]
async fn converttopsbt_empty_vin_iswitness_false_succeeds() {
    let srv = server();

    // iswitness=false forces legacy decode only; it fully consumes the bytes,
    // yielding the same 0-input/1-OP_RETURN PSBT as the heuristic path.
    let b64 = srv
        .converttopsbt(EMPTY_VIN_HEX.to_string(), None, Some(false))
        .await
        .expect("iswitness=false legacy decode must succeed");
    assert_eq!(
        b64, EMPTY_VIN_EXPECTED_PSBT,
        "iswitness=false must produce the 0-input/1-OP_RETURN PSBT"
    );
}

// ===========================================================================
// joinpsbts
// ===========================================================================

/// Build a base64 PSBT from a one-input/one-output unsigned tx.
fn psbt_b64(
    version: i32,
    lock_time: u32,
    txin: TxIn,
    txout: TxOut,
) -> String {
    let tx = Transaction {
        version,
        inputs: vec![txin],
        outputs: vec![txout],
        lock_time,
    };
    Psbt::from_unsigned_tx(tx)
        .expect("blank PSBT from unsigned tx")
        .to_base64()
}

#[tokio::test]
async fn joinpsbts_requires_at_least_two() {
    let srv = server();

    let single = psbt_b64(
        2,
        0,
        TxIn {
            previous_output: outpoint(0xaa, 0),
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        },
        op_true_out(1000),
    );

    let err = srv
        .joinpsbts(vec![single.clone()])
        .await
        .expect_err("one PSBT must be rejected");
    assert_eq!(err.code(), RPC_INVALID_PARAMETER, "single PSBT must be -8");
    assert!(
        err.message()
            .contains("At least two PSBTs are required to join PSBTs."),
        "unexpected message: {}",
        err.message()
    );

    // Zero PSBTs is also -8 (txs.len() <= 1).
    let err0 = srv
        .joinpsbts(vec![])
        .await
        .expect_err("zero PSBTs must be rejected");
    assert_eq!(err0.code(), RPC_INVALID_PARAMETER);
}

#[tokio::test]
async fn joinpsbts_rejects_duplicate_full_ctxin() {
    let srv = server();

    let dup_in = TxIn {
        previous_output: outpoint(0xbb, 3),
        script_sig: vec![],
        sequence: 0xffff_ffff,
        witness: vec![],
    };
    let a = psbt_b64(2, 0, dup_in.clone(), op_true_out(100));
    let b = psbt_b64(2, 0, dup_in.clone(), op_true_out(200));

    let err = srv
        .joinpsbts(vec![a, b])
        .await
        .expect_err("identical CTxIn in two PSBTs must be rejected");
    assert_eq!(
        err.code(),
        RPC_INVALID_PARAMETER,
        "duplicate input must be -8"
    );
    assert!(
        err.message().contains("exists in multiple PSBTs"),
        "unexpected message: {}",
        err.message()
    );
}

/// Two inputs sharing an outpoint but with DIFFERENT nSequence are BOTH kept —
/// Core's `CTxIn::operator==` compares prevout AND scriptSig AND nSequence, so
/// they are distinct and not deduplicated.
#[tokio::test]
async fn joinpsbts_keeps_same_outpoint_with_different_sequence() {
    let srv = server();

    let in_seq_a = TxIn {
        previous_output: outpoint(0xcc, 1),
        script_sig: vec![],
        sequence: 0xffff_fffd,
        witness: vec![],
    };
    let in_seq_b = TxIn {
        previous_output: outpoint(0xcc, 1), // same outpoint
        script_sig: vec![],
        sequence: 0xffff_ffff, // different nSequence
        witness: vec![],
    };
    let a = psbt_b64(2, 0, in_seq_a, op_true_out(100));
    let b = psbt_b64(2, 0, in_seq_b, op_true_out(200));

    let merged_b64 = srv
        .joinpsbts(vec![a, b])
        .await
        .expect("same outpoint / different nSequence must both be kept");
    let merged = Psbt::from_base64(&merged_b64).expect("valid PSBT");
    assert_eq!(
        merged.unsigned_tx.inputs.len(),
        2,
        "both inputs sharing an outpoint but differing in nSequence must be kept"
    );
    let seqs: std::collections::BTreeSet<u32> = merged
        .unsigned_tx
        .inputs
        .iter()
        .map(|i| i.sequence)
        .collect();
    assert_eq!(
        seqs,
        [0xffff_fffd, 0xffff_ffff].into_iter().collect(),
        "both distinct nSequence values must be present"
    );
}

/// Set-union of inputs/outputs with best (max) version and best (min) locktime.
#[tokio::test]
async fn joinpsbts_unions_inputs_outputs_and_picks_version_locktime() {
    let srv = server();

    // psbt A: version 2, locktime 500000, one input/one output.
    let a = psbt_b64(
        2,
        500_000,
        TxIn {
            previous_output: outpoint(0x01, 0),
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        },
        op_true_out(1000),
    );
    // psbt B: version 7 (higher → wins), locktime 42 (lower → wins).
    let b = psbt_b64(
        7,
        42,
        TxIn {
            previous_output: outpoint(0x02, 1),
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        },
        op_true_out(2000),
    );

    let merged_b64 = srv
        .joinpsbts(vec![a, b])
        .await
        .expect("disjoint PSBTs must join");
    let merged = Psbt::from_base64(&merged_b64).expect("valid PSBT");

    // Union of inputs and outputs (order may be shuffled).
    assert_eq!(merged.unsigned_tx.inputs.len(), 2, "input set-union");
    assert_eq!(merged.unsigned_tx.outputs.len(), 2, "output set-union");
    // Per-input/per-output maps stay paired (one map per tx entry).
    assert_eq!(merged.inputs.len(), 2);
    assert_eq!(merged.outputs.len(), 2);

    // best_version = max(2, 7) = 7; best_locktime = min(500000, 42) = 42.
    assert_eq!(merged.unsigned_tx.version, 7, "max version wins");
    assert_eq!(merged.unsigned_tx.lock_time, 42, "min locktime wins");

    // Both outpoints present regardless of shuffle.
    let outpoints: std::collections::BTreeSet<(u8, u32)> = merged
        .unsigned_tx
        .inputs
        .iter()
        .map(|i| (i.previous_output.txid.0[0], i.previous_output.vout))
        .collect();
    assert_eq!(
        outpoints,
        [(0x01, 0), (0x02, 1)].into_iter().collect(),
        "both inputs from both PSBTs must be present"
    );
    let values: std::collections::BTreeSet<u64> =
        merged.unsigned_tx.outputs.iter().map(|o| o.value).collect();
    assert_eq!(
        values,
        [1000, 2000].into_iter().collect(),
        "both outputs from both PSBTs must be present"
    );
}

/// ⭐ Sig data is CLEARED on every merged input: Core's `AddInput`
/// unconditionally clears partial_sigs / final_script_sig / final_script_witness.
///
/// Two fixtures are needed because the PSBT serializer drops `partial_sigs`
/// once an input is finalized (BIP-174): one PSBT carries `partial_sigs` ONLY
/// (a partially-signed, non-final input), and one carries `final_script_sig` +
/// `final_script_witness` ONLY (a finalized input). Both must round-trip with
/// their sig data intact (asserted up front), and both must come out of
/// `joinpsbts` with ALL sig fields cleared.
#[tokio::test]
async fn joinpsbts_clears_signature_data_on_merged_inputs() {
    let srv = server();

    // Fixture A: a non-final input carrying partial_sigs only.
    let tx_a = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: outpoint(0xde, 0),
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![op_true_out(1000)],
        lock_time: 0,
    };
    let mut psbt_a = Psbt::from_unsigned_tx(tx_a).expect("blank PSBT");
    // A 33-byte compressed pubkey (0x02 prefix) -> DER-ish sig blob.
    let mut pk = [0u8; 33];
    pk[0] = 0x02;
    pk[1] = 0xab;
    psbt_a.inputs[0]
        .partial_sigs
        .insert(pk, vec![0x30, 0x44, 0x02, 0x20, 0x01]);
    let a_b64 = psbt_a.to_base64();

    // Fixture B: a finalized, disjoint input carrying final_script_sig +
    // final_script_witness only.
    let tx_b = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: outpoint(0xad, 9),
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![op_true_out(2000)],
        lock_time: 0,
    };
    let mut psbt_b = Psbt::from_unsigned_tx(tx_b).expect("blank PSBT");
    psbt_b.inputs[0].final_script_sig = Some(vec![0x47, 0x30, 0x44]);
    psbt_b.inputs[0].final_script_witness = Some(vec![vec![0x30, 0x44], vec![0x02; 33]]);
    let b_b64 = psbt_b.to_base64();

    // Up-front sanity: the fixtures actually carry their sig data on the wire.
    {
        let ra = Psbt::from_base64(&a_b64).expect("valid PSBT A");
        assert!(
            !ra.inputs[0].partial_sigs.is_empty(),
            "fixture A must carry partial_sigs through serialization"
        );
        let rb = Psbt::from_base64(&b_b64).expect("valid PSBT B");
        assert!(
            rb.inputs[0].final_script_sig.is_some(),
            "fixture B must carry final_script_sig"
        );
        assert!(
            rb.inputs[0].final_script_witness.is_some(),
            "fixture B must carry final_script_witness"
        );
    }

    let merged_b64 = srv
        .joinpsbts(vec![a_b64, b_b64])
        .await
        .expect("disjoint signed + finalized PSBTs must join");
    let merged = Psbt::from_base64(&merged_b64).expect("valid PSBT");

    assert_eq!(merged.unsigned_tx.inputs.len(), 2);
    assert_eq!(merged.inputs.len(), 2);
    // EVERY merged input must have its sig data cleared (Core AddInput parity).
    for (idx, inp) in merged.inputs.iter().enumerate() {
        assert!(
            inp.partial_sigs.is_empty(),
            "merged input {idx}: partial_sigs must be cleared"
        );
        assert!(
            inp.final_script_sig.is_none(),
            "merged input {idx}: final_script_sig must be cleared"
        );
        assert!(
            inp.final_script_witness.is_none(),
            "merged input {idx}: final_script_witness must be cleared"
        );
    }
}
