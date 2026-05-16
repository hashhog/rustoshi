//! BIP-78 PayJoin receiver foundation (W119 / FIX-65).
//!
//! Implements the minimal receiver-side state machine specified by
//! [BIP-78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki):
//!
//!  1. Accept an "Original PSBT" (base64) posted to a receiver endpoint.
//!  2. Validate it structurally: parseable PSBTv0, ≥1 input, ≥1 output,
//!     every input has a `witness_utxo` or `non_witness_utxo`, and at
//!     least one output pays a wallet-owned address.
//!  3. Add one receiver input from `Wallet::list_unspent`.
//!  4. Adjust the receiver-output value by
//!     `+receiver_input_value − delta_fee`, where `delta_fee = min(
//!     maxadditionalfeecontribution, est_extra_fee)`.
//!  5. Sign the receiver-added input via the wallet's existing P2WPKH
//!     signer, finalize it, and return the modified PSBT (base64).
//!
//! Errors are returned as [`PayjoinError`] variants which carry the
//! BIP-78 wire-level `errorCode` string the HTTP layer must echo back
//! (`version-unsupported`, `original-psbt-rejected`, `not-enough-money`,
//! `unavailable`).
//!
//! ## Reuse map
//!
//! - FIX-59 wallet encryption: lookups go through the wallet under its
//!   normal lock; if the caller has not unlocked yet the HTTP layer
//!   wraps the resulting `WalletLocked` into [`PayjoinError::Unavailable`].
//! - FIX-61 `sent_txs` tracking: this module adds the receiver-side
//!   analog [`OfferedPayjoin`] keyed on the Original PSBT's unsigned-tx
//!   hash. The map is held by the HTTP layer (REST state) — keeping the
//!   `Wallet` itself untouched preserves the FIX-61 single-purpose
//!   record (outgoing-only) while still preventing concurrent PayJoins
//!   from offering the same receiver UTXO twice.
//! - PSBT signing: receiver inputs are P2WPKH (matching the rustoshi
//!   default `AddressType::P2WPKH`); the signer reuses the same
//!   `segwit_v0_sighash` + ECDSA path used by `Wallet::sign_input`'s
//!   P2WPKH branch, then drops the signature into
//!   `partial_sigs` + `final_script_witness` so the modified PSBT
//!   round-trips through `Psbt::is_finalized` and `Psbt::to_base64`.
//!
//! ## Scope (FIX-65)
//!
//! Receiver-side foundation only:
//!   - G1+G23  POST /payjoin endpoint (request validation in `rpc::rest`)
//!   - G4+G5   Original PSBT decode + structural validation
//!   - G6+G9   Fee output + adjustment
//!   - G7      Receiver input addition (single P2WPKH)
//!   - G17     BIP-78 JSON `errorCode` shape
//!   - G19     UTXO double-offer guard (`offered_payjoins` map)
//!
//! Out of scope (subsequent waves):
//!   - UIH-1 / UIH-2 anti-fingerprinting (FIX-67, BUG-6 G20)
//!   - TTL beyond in-flight (FIX-68, BUG-13 G18)
//!   - Sender-side anti-snoop (FIX-66, BUG-8/9/10 G10..G15)

use std::collections::HashMap;

use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint, TxOut};
use secp256k1::{Message, Secp256k1};

use crate::hd::WalletError;
use crate::psbt::{Psbt, PsbtError};
use crate::wallet::{Wallet, WalletUtxo};

/// BIP-78 specifies an 8 KiB upper bound on Original-PSBT bodies.
/// Anything larger is treated as a protocol violation rather than a
/// resource issue — even a 50-input PSBT comes in well under this.
pub const MAX_ORIGINAL_PSBT_BYTES: usize = 8 * 1024;

/// The five BIP-78 sender query parameters. Captured verbatim from the
/// wire to be forwarded into the receiver flow.
#[derive(Clone, Debug, Default)]
pub struct PayjoinParams {
    /// `v=` — only `1` is supported. Anything else is
    /// [`PayjoinError::VersionUnsupported`].
    pub version: u32,
    /// `additionalfeeoutputindex=` — the index of the output to draw the
    /// extra fee from. Optional.
    pub additional_fee_output_index: Option<usize>,
    /// `maxadditionalfeecontribution=` — receiver cap, in satoshis.
    /// Optional (no cap means the receiver may not deduct anything).
    pub max_additional_fee_contribution: Option<u64>,
    /// `disableoutputsubstitution=` — defaults to `false` (substitution
    /// allowed). Stored verbatim; the receiver foundation does not
    /// substitute outputs yet.
    pub disable_output_substitution: bool,
    /// `minfeerate=` — caller's minimum acceptable resulting fee rate
    /// (sat/vB). Optional. Not enforced by the receiver foundation.
    pub min_fee_rate: Option<f64>,
}

/// In-flight PayJoin offer keyed by the Original-PSBT's unsigned-tx
/// hash. Held by the HTTP layer (see `rpc::rest`) to prevent two
/// concurrent senders being offered the same receiver UTXO.
#[derive(Clone, Debug)]
pub struct OfferedPayjoin {
    /// The receiver UTXO that was added to this PayJoin. Used as the
    /// `offered_outpoints` key for cross-offer conflict detection.
    pub receiver_outpoint: OutPoint,
    /// Unix timestamp (seconds) when the offer was created. Bookkept for
    /// future TTL eviction (FIX-68) but unused in FIX-65.
    pub created_at: u64,
}

/// Errors that flow out of the receiver pipeline. Variants map 1:1 to
/// BIP-78's "Receiver's well known errors" table.
#[derive(Debug, thiserror::Error)]
pub enum PayjoinError {
    /// Sender requested a PayJoin protocol version this receiver does
    /// not implement. BIP-78 says to respond with HTTP 415 +
    /// `{"errorCode": "version-unsupported", ...}`.
    #[error("version-unsupported: only v=1 is supported (got v={0})")]
    VersionUnsupported(u32),
    /// The Original PSBT was malformed or violated a structural rule
    /// (unparseable, no inputs, no outputs, missing prev-utxo data,
    /// or no output paying the wallet). BIP-78 → HTTP 400 +
    /// `{"errorCode": "original-psbt-rejected", "message": "<why>"}`.
    #[error("original-psbt-rejected: {0}")]
    OriginalPsbtRejected(String),
    /// The receiver wallet has no eligible UTXO to add (empty wallet
    /// or every candidate is already offered or locked). BIP-78 →
    /// HTTP 422 + `{"errorCode": "not-enough-money", ...}`.
    #[error("not-enough-money: receiver has no eligible UTXO to add")]
    NotEnoughMoney,
    /// Receiver is temporarily unable to serve this request (wallet
    /// locked, an in-flight conflict, or any other transient state).
    /// BIP-78 → HTTP 503 + `{"errorCode": "unavailable", ...}`.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

impl PayjoinError {
    /// Wire-level error code per BIP-78 §"Receiver's well known errors".
    pub fn code(&self) -> &'static str {
        match self {
            PayjoinError::VersionUnsupported(_) => "version-unsupported",
            PayjoinError::OriginalPsbtRejected(_) => "original-psbt-rejected",
            PayjoinError::NotEnoughMoney => "not-enough-money",
            PayjoinError::Unavailable(_) => "unavailable",
        }
    }

    /// Suggested HTTP status. The REST layer uses this verbatim.
    pub fn http_status(&self) -> u16 {
        match self {
            PayjoinError::VersionUnsupported(_) => 415,
            PayjoinError::OriginalPsbtRejected(_) => 400,
            PayjoinError::NotEnoughMoney => 422,
            PayjoinError::Unavailable(_) => 503,
        }
    }
}

/// Validate the BIP-78 query-param shape. The receiver foundation only
/// enforces `v=1`; remaining params are stored verbatim for future
/// fee-cap / fee-rate enforcement (FIX-67+).
pub fn validate_params(params: &PayjoinParams) -> Result<(), PayjoinError> {
    if params.version != 1 {
        return Err(PayjoinError::VersionUnsupported(params.version));
    }
    Ok(())
}

/// Decode a base64 Original-PSBT body and run structural checks.
///
/// Per BIP-78 §"Receiver checks":
///   - Body MUST be base64.
///   - PSBT MUST be v0 (i.e. parseable by [`Psbt::from_base64`], whose
///     allow-list refuses v=2).
///   - MUST have ≥ 1 input.
///   - MUST have ≥ 1 output.
///   - Every input MUST carry a `witness_utxo` or `non_witness_utxo`
///     (otherwise the receiver cannot reason about the spent amount,
///     defeating fee-rate enforcement).
pub fn decode_and_validate_original(body: &[u8]) -> Result<Psbt, PayjoinError> {
    if body.len() > MAX_ORIGINAL_PSBT_BYTES {
        return Err(PayjoinError::OriginalPsbtRejected(format!(
            "body exceeds BIP-78 limit of {} bytes (got {})",
            MAX_ORIGINAL_PSBT_BYTES,
            body.len()
        )));
    }
    let s = std::str::from_utf8(body)
        .map_err(|e| PayjoinError::OriginalPsbtRejected(format!("body not valid UTF-8: {e}")))?;
    let psbt = Psbt::from_base64(s.trim())
        .map_err(|e: PsbtError| PayjoinError::OriginalPsbtRejected(format!("PSBT decode: {e}")))?;
    if psbt.inputs.is_empty() {
        return Err(PayjoinError::OriginalPsbtRejected(
            "no inputs in Original PSBT".to_string(),
        ));
    }
    if psbt.outputs.is_empty() {
        return Err(PayjoinError::OriginalPsbtRejected(
            "no outputs in Original PSBT".to_string(),
        ));
    }
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
            return Err(PayjoinError::OriginalPsbtRejected(format!(
                "input {i} has neither witness_utxo nor non_witness_utxo"
            )));
        }
    }
    Ok(psbt)
}

/// Locate the output paying a wallet-owned address. Returns
/// `(output_index, address)`. The receiver MUST pay at least one
/// wallet-owned output, otherwise the request is rejected per
/// BIP-78 (sender is not paying *this* receiver).
pub fn find_receiver_output(psbt: &Psbt, wallet: &Wallet) -> Result<(usize, String), PayjoinError> {
    for (i, out) in psbt.unsigned_tx.outputs.iter().enumerate() {
        if let Some(addr) = decode_script_to_address(&out.script_pubkey, wallet.network()) {
            if wallet.is_mine(&addr) {
                return Ok((i, addr));
            }
        }
    }
    Err(PayjoinError::OriginalPsbtRejected(
        "no output pays a wallet-owned address".to_string(),
    ))
}

/// Walk wallet UTXOs and pick a single one to contribute, skipping any
/// outpoint already committed to another in-flight PayJoin (G19) or
/// locked via `lockunspent` (Core parity).
///
/// Returns `NotEnoughMoney` if the wallet has zero eligible UTXOs;
/// returns the first non-conflicting candidate otherwise. This is
/// deliberately naive — UIH-1 / UIH-2 anti-fingerprinting selection
/// lands in FIX-67 (BUG-6 G20).
pub fn pick_receiver_utxo(
    wallet: &Wallet,
    offered: &HashMap<Hash256, OfferedPayjoin>,
) -> Result<WalletUtxo, PayjoinError> {
    let claimed: std::collections::HashSet<OutPoint> = offered
        .values()
        .map(|o| o.receiver_outpoint.clone())
        .collect();
    for utxo in wallet.list_spendable_unspent_unlocked() {
        if !claimed.contains(&utxo.outpoint) {
            return Ok(utxo.clone());
        }
    }
    Err(PayjoinError::NotEnoughMoney)
}

/// Outcome of [`build_modified_psbt`]. Held by the HTTP layer so it can
/// (a) serialise the PSBT into the response body and (b) remember the
/// offered outpoint for the duration of the request.
#[derive(Clone, Debug)]
pub struct ReceiverContribution {
    /// The fully built + signed PSBT to return to the sender.
    pub modified_psbt: Psbt,
    /// The receiver UTXO that was added (committed to `offered_payjoins`
    /// by the caller).
    pub added_utxo: WalletUtxo,
    /// Fee delta applied to the receiver output: `+received_value −
    /// receiver_output_increase`. Only used by tests.
    pub delta_fee_sats: u64,
}

/// Build the modified PSBT: append `utxo` as a new input, bump the
/// receiver output's value by `utxo.value − delta_fee`, sign the new
/// input, and return the resulting PSBT.
///
/// `recv_output_idx` is the output the [`find_receiver_output`] step
/// identified. `delta_fee_sats` is the fee adjustment the receiver
/// applies; it must respect the BIP-78
/// `maxadditionalfeecontribution` cap (enforced by the HTTP layer
/// before this call).
pub fn build_modified_psbt(
    wallet: &Wallet,
    mut psbt: Psbt,
    recv_output_idx: usize,
    utxo: WalletUtxo,
    delta_fee_sats: u64,
) -> Result<ReceiverContribution, PayjoinError> {
    // ---- 1. Append the new receiver input. ---------------------------
    if !is_p2wpkh_spk(&utxo.script_pubkey) {
        return Err(PayjoinError::Unavailable(
            "receiver foundation only contributes P2WPKH inputs".to_string(),
        ));
    }
    psbt.unsigned_tx.inputs.push(rustoshi_primitives::TxIn {
        previous_output: utxo.outpoint.clone(),
        script_sig: vec![],
        // Sender's RBF flag wins for the whole tx; mirror its sequence so
        // we never silently downgrade RBF signalling.
        sequence: 0xffff_fffd,
        witness: vec![],
    });
    psbt.inputs.push(crate::psbt::PsbtInput {
        witness_utxo: Some(TxOut {
            value: utxo.value,
            script_pubkey: utxo.script_pubkey.clone(),
        }),
        ..Default::default()
    });

    // ---- 2. Bump the receiver output. --------------------------------
    if recv_output_idx >= psbt.unsigned_tx.outputs.len() {
        return Err(PayjoinError::Unavailable(
            "receiver output index out of range after augmentation".to_string(),
        ));
    }
    let increment = utxo
        .value
        .checked_sub(delta_fee_sats)
        .ok_or_else(|| PayjoinError::Unavailable(
            "delta_fee exceeds receiver input value".to_string(),
        ))?;
    let new_value = psbt.unsigned_tx.outputs[recv_output_idx]
        .value
        .checked_add(increment)
        .ok_or_else(|| PayjoinError::Unavailable(
            "u64 overflow adjusting receiver output value".to_string(),
        ))?;
    psbt.unsigned_tx.outputs[recv_output_idx].value = new_value;

    // ---- 3. Sign the added input. ------------------------------------
    let input_idx = psbt.unsigned_tx.inputs.len() - 1;
    sign_receiver_input(wallet, &mut psbt, input_idx, &utxo)
        .map_err(|e| PayjoinError::Unavailable(format!("sign receiver input: {e}")))?;

    Ok(ReceiverContribution {
        modified_psbt: psbt,
        added_utxo: utxo,
        delta_fee_sats,
    })
}

/// Top-level driver tying together [`validate_params`],
/// [`decode_and_validate_original`], [`find_receiver_output`],
/// [`pick_receiver_utxo`], and [`build_modified_psbt`].
///
/// `existing_offered` is the HTTP layer's `offered_payjoins` snapshot,
/// passed in so this function stays stateless / unit-testable. The
/// caller is responsible for committing the new offer (and rolling it
/// back if the response fails to send).
pub fn handle_payjoin_request(
    body: &[u8],
    params: &PayjoinParams,
    wallet: &Wallet,
    existing_offered: &HashMap<Hash256, OfferedPayjoin>,
) -> Result<ReceiverContribution, PayjoinError> {
    validate_params(params)?;
    let psbt = decode_and_validate_original(body)?;
    let (recv_idx, _addr) = find_receiver_output(&psbt, wallet)?;
    let utxo = pick_receiver_utxo(wallet, existing_offered)?;
    // Naive fee policy: the receiver bumps the fee by exactly its own
    // added vsize × 1 sat/vB ≈ 68 sat, capped at the sender's
    // `maxadditionalfeecontribution`. This is intentionally tiny — a
    // proper sat/vB-from-`minfeerate` ladder lands with the sender-side
    // anti-snoop closures in FIX-66 / FIX-67.
    const ADDED_INPUT_VSIZE: u64 = 68; // P2WPKH input vsize approximation
    const RECEIVER_FEE_RATE_FLOOR_SAT_VB: u64 = 1;
    let want_delta = ADDED_INPUT_VSIZE * RECEIVER_FEE_RATE_FLOOR_SAT_VB;
    let delta_fee = params
        .max_additional_fee_contribution
        .map(|cap| cap.min(want_delta))
        .unwrap_or(0);
    build_modified_psbt(wallet, psbt, recv_idx, utxo, delta_fee)
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

/// P2WPKH scriptPubKey detector — mirrors the private helper in
/// `wallet.rs`. Duplicated here to avoid widening the wallet module's
/// public surface.
fn is_p2wpkh_spk(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

/// Decode a scriptPubKey back into the encoded address string format
/// `Wallet::is_mine` expects. Returns `None` for unrecognised shapes
/// (bare multisig, OP_RETURN, etc.) — those are by definition not
/// receiver outputs.
fn decode_script_to_address(spk: &[u8], network: Network) -> Option<String> {
    use rustoshi_primitives::Hash160;
    match spk {
        // P2PKH: 0x76 0xa9 0x14 <20> 0x88 0xac
        [0x76, 0xa9, 0x14, rest @ ..]
            if rest.len() == 22 && rest[20] == 0x88 && rest[21] == 0xac =>
        {
            let mut h = [0u8; 20];
            h.copy_from_slice(&rest[..20]);
            Some(
                Address::P2PKH {
                    hash: Hash160::from_bytes(h),
                    network,
                }
                .encode(),
            )
        }
        // P2SH: 0xa9 0x14 <20> 0x87
        [0xa9, 0x14, rest @ ..] if rest.len() == 21 && rest[20] == 0x87 => {
            let mut h = [0u8; 20];
            h.copy_from_slice(&rest[..20]);
            Some(
                Address::P2SH {
                    hash: Hash160::from_bytes(h),
                    network,
                }
                .encode(),
            )
        }
        // P2WPKH: 0x00 0x14 <20>
        [0x00, 0x14, rest @ ..] if rest.len() == 20 => {
            let mut h = [0u8; 20];
            h.copy_from_slice(rest);
            Some(
                Address::P2WPKH {
                    hash: Hash160::from_bytes(h),
                    network,
                }
                .encode(),
            )
        }
        // P2WSH: 0x00 0x20 <32>
        [0x00, 0x20, rest @ ..] if rest.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(rest);
            Some(
                Address::P2WSH {
                    hash: rustoshi_primitives::Hash256(h),
                    network,
                }
                .encode(),
            )
        }
        // P2TR: 0x51 0x20 <32>
        [0x51, 0x20, rest @ ..] if rest.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(rest);
            Some(
                Address::P2TR {
                    output_key: h,
                    network,
                }
                .encode(),
            )
        }
        _ => None,
    }
}

/// Sign a single receiver-added P2WPKH input by deriving the private
/// key from the wallet, computing the BIP-143 segwit-v0 sighash, ECDSA
/// signing, and dropping the signature + pubkey into the PSBT input's
/// `final_script_witness` (FIX-65 fast path; equivalent to the
/// finalize-after-partial-sigs pattern Core uses, but skips the
/// intermediate `partial_sigs` map since we hold the only signing key).
fn sign_receiver_input(
    wallet: &Wallet,
    psbt: &mut Psbt,
    input_idx: usize,
    utxo: &WalletUtxo,
) -> Result<(), WalletError> {
    let sk = wallet
        .private_key_for_address(
            &decode_script_to_address(&utxo.script_pubkey, wallet.network())
                .ok_or_else(|| WalletError::SigningError("unsupported utxo spk".into()))?,
        )
        .ok_or_else(|| WalletError::SigningError(
            "no private key for receiver utxo (wallet locked or unknown path)".into(),
        ))?;
    let secp = Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pk_compressed: [u8; 33] = pk.serialize();
    let pubkey_hash = rustoshi_crypto::hash160(&pk_compressed);
    let script_code = {
        // P2WPKH script code: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&pubkey_hash.0);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    };
    let sighash = rustoshi_crypto::segwit_v0_sighash(
        &psbt.unsigned_tx,
        input_idx,
        &script_code,
        utxo.value,
        0x01,
    );
    let msg = Message::from_digest(sighash.0);
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL

    // Drop straight into final_script_witness — mirrors what
    // `Psbt::finalize_input` does for a 1-sig P2WPKH, but without
    // routing through the partial_sigs map first (FIX-65 receives
    // only its own key).
    let input = &mut psbt.inputs[input_idx];
    input.partial_sigs.insert(pk_compressed, sig_bytes.clone());
    input.final_script_witness = Some(vec![sig_bytes, pk_compressed.to_vec()]);
    Ok(())
}

// =====================================================================
// TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{AddressType, Wallet};
    use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};

    fn test_seed(byte: u8) -> Vec<u8> {
        vec![byte; 64]
    }

    /// Build a 1-in/1-out Original PSBT paying `receiver_address`, with a
    /// dummy sender input that has a witness_utxo populated (so the
    /// validation step passes).
    fn make_original_psbt(receiver_address: &str, network: Network, recv_value: u64) -> Psbt {
        let recv_spk = Address::from_string(receiver_address, Some(network))
            .expect("parse receiver address")
            .to_script_pubkey();

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x01; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: recv_value,
                script_pubkey: recv_spk,
            }],
            lock_time: 0,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt build");
        // Witness UTXO so validation passes — dummy 22-byte P2WPKH.
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: recv_value + 10_000, // sender contributed slightly more
            script_pubkey: {
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[0x77; 20]);
                s
            },
        });
        psbt
    }

    /// Fund `wallet` with one P2WPKH UTXO at its first receive address.
    fn fund_wallet(wallet: &mut Wallet, value: u64) -> WalletUtxo {
        let addr = wallet.get_new_address().expect("fresh recv addr");
        let path = wallet.get_derivation_path(&addr).unwrap().clone();
        let spk = Address::from_string(&addr, Some(wallet.network()))
            .unwrap()
            .to_script_pubkey();
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::from_bytes([0xaa; 32]),
                vout: 1,
            },
            value,
            script_pubkey: spk,
            derivation_path: path,
            confirmations: 10,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        };
        wallet.set_chain_height(200);
        wallet.add_utxo(utxo.clone());
        utxo
    }

    #[test]
    fn validate_params_rejects_v2() {
        let p = PayjoinParams {
            version: 2,
            ..Default::default()
        };
        let err = validate_params(&p).expect_err("v=2 must reject");
        assert_eq!(err.code(), "version-unsupported");
        assert_eq!(err.http_status(), 415);
    }

    #[test]
    fn validate_params_accepts_v1() {
        let p = PayjoinParams {
            version: 1,
            ..Default::default()
        };
        validate_params(&p).expect("v=1 must pass");
    }

    #[test]
    fn decode_rejects_garbage() {
        let err = decode_and_validate_original(b"not a psbt").expect_err("garbage rejects");
        assert_eq!(err.code(), "original-psbt-rejected");
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn decode_rejects_oversize() {
        let big = vec![b'a'; MAX_ORIGINAL_PSBT_BYTES + 1];
        let err = decode_and_validate_original(&big).expect_err("oversize rejects");
        assert_eq!(err.code(), "original-psbt-rejected");
    }

    #[test]
    fn find_receiver_output_finds_wallet_address() {
        let mut wallet = Wallet::from_seed(&test_seed(0x11), Network::Regtest, AddressType::P2WPKH)
            .expect("wallet");
        let addr = wallet.get_new_address().expect("addr");
        let psbt = make_original_psbt(&addr, Network::Regtest, 50_000);
        let (idx, found_addr) = find_receiver_output(&psbt, &wallet).expect("find recv");
        assert_eq!(idx, 0);
        assert_eq!(found_addr, addr);
    }

    #[test]
    fn find_receiver_output_rejects_non_wallet_address() {
        let wallet = Wallet::from_seed(&test_seed(0x12), Network::Regtest, AddressType::P2WPKH)
            .expect("wallet");
        let outsider = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let psbt = make_original_psbt(outsider, Network::Regtest, 50_000);
        let err = find_receiver_output(&psbt, &wallet).expect_err("outsider rejects");
        assert_eq!(err.code(), "original-psbt-rejected");
    }

    #[test]
    fn pick_utxo_returns_not_enough_when_empty() {
        let wallet =
            Wallet::from_seed(&test_seed(0x13), Network::Regtest, AddressType::P2WPKH).unwrap();
        let offered = HashMap::new();
        let err = pick_receiver_utxo(&wallet, &offered).expect_err("empty wallet");
        assert_eq!(err.code(), "not-enough-money");
        assert_eq!(err.http_status(), 422);
    }

    #[test]
    fn pick_utxo_skips_offered_outpoint() {
        let mut wallet =
            Wallet::from_seed(&test_seed(0x14), Network::Regtest, AddressType::P2WPKH).unwrap();
        let utxo = fund_wallet(&mut wallet, 200_000);
        let mut offered = HashMap::new();
        offered.insert(
            Hash256::from_bytes([0xff; 32]),
            OfferedPayjoin {
                receiver_outpoint: utxo.outpoint.clone(),
                created_at: 0,
            },
        );
        let err = pick_receiver_utxo(&wallet, &offered).expect_err("offered conflicts");
        assert_eq!(err.code(), "not-enough-money");
    }

    #[test]
    fn handle_request_happy_path_round_trip() {
        let mut wallet =
            Wallet::from_seed(&test_seed(0x15), Network::Regtest, AddressType::P2WPKH).unwrap();
        let addr = wallet.get_new_address().expect("recv addr");
        fund_wallet(&mut wallet, 500_000);

        let psbt = make_original_psbt(&addr, Network::Regtest, 50_000);
        let body = psbt.to_base64();

        let params = PayjoinParams {
            version: 1,
            max_additional_fee_contribution: Some(1_000),
            ..Default::default()
        };
        let offered = HashMap::new();
        let result =
            handle_payjoin_request(body.as_bytes(), &params, &wallet, &offered).expect("happy");

        // The modified PSBT has exactly one more input than the original.
        assert_eq!(result.modified_psbt.unsigned_tx.inputs.len(), 2);
        assert_eq!(result.modified_psbt.inputs.len(), 2);
        // The receiver output value increased by (added_utxo.value - delta_fee).
        let expected_increment = 500_000 - result.delta_fee_sats;
        assert_eq!(
            result.modified_psbt.unsigned_tx.outputs[0].value,
            50_000 + expected_increment
        );
        // The added input is signed (final_script_witness populated).
        assert!(result.modified_psbt.inputs[1].final_script_witness.is_some());
        // PSBT round-trips through base64 unchanged.
        let reserialized = result.modified_psbt.to_base64();
        let parsed = Psbt::from_base64(&reserialized).expect("round-trip");
        assert_eq!(parsed.unsigned_tx.inputs.len(), 2);
    }

    #[test]
    fn handle_request_no_money_when_wallet_empty() {
        let mut wallet =
            Wallet::from_seed(&test_seed(0x16), Network::Regtest, AddressType::P2WPKH).unwrap();
        let addr = wallet.get_new_address().expect("recv");
        let psbt = make_original_psbt(&addr, Network::Regtest, 50_000);
        let body = psbt.to_base64();

        let params = PayjoinParams {
            version: 1,
            ..Default::default()
        };
        let offered = HashMap::new();
        let err = handle_payjoin_request(body.as_bytes(), &params, &wallet, &offered)
            .expect_err("empty wallet");
        assert_eq!(err.code(), "not-enough-money");
    }

    #[test]
    fn handle_request_rejects_v2() {
        let wallet =
            Wallet::from_seed(&test_seed(0x17), Network::Regtest, AddressType::P2WPKH).unwrap();
        let params = PayjoinParams {
            version: 2,
            ..Default::default()
        };
        let offered = HashMap::new();
        let err = handle_payjoin_request(b"anything", &params, &wallet, &offered)
            .expect_err("v=2 rejects");
        assert_eq!(err.code(), "version-unsupported");
    }
}
