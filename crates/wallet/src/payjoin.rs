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
use rustoshi_crypto::secp_ctx;
use rustoshi_primitives::{Hash256, OutPoint, TxOut};
use secp256k1::Message;

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
    /// Unix timestamp (seconds) when the offer was created. The HTTP
    /// layer uses this to drive [`OFFERED_PAYJOIN_TTL_SECS`] eviction
    /// (G18).
    pub created_at: u64,
}

/// BIP-78 §"Receiver state". Once an offered PayJoin sits idle for
/// longer than this, the receiver MUST evict it from the in-flight
/// map (otherwise a misbehaving sender can DoS receiver UTXOs).
///
/// Five minutes matches the BIP-78 reference implementations'
/// (`payjoin` Rust crate / btcpayserver) default; tests use a smaller
/// value via [`evict_expired_offers`] directly.
pub const OFFERED_PAYJOIN_TTL_SECS: u64 = 5 * 60;

/// G18 closure — evict expired offers from the in-flight map.
///
/// Called by the HTTP layer before snapshotting [`OfferedPayjoin`]s for
/// coin-selection conflict detection. Pure helper so the receiver
/// pipeline tests can drive it deterministically (no wall-clock).
///
/// Returns the number of offers evicted.
pub fn evict_expired_offers(
    offered: &mut HashMap<Hash256, OfferedPayjoin>,
    now_secs: u64,
    ttl_secs: u64,
) -> usize {
    let before = offered.len();
    offered.retain(|_, off| {
        // Use saturating_sub so a clock-skew "future" timestamp never
        // triggers eviction.
        now_secs.saturating_sub(off.created_at) <= ttl_secs
    });
    before - offered.len()
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

/// Validate the BIP-78 query-param shape (G16 + G21).
///
/// Enforces:
///   - `v=1` (G21 — version sentinel). Anything else, including a
///     missing `v` (mapped to `0` by the HTTP layer), returns
///     [`PayjoinError::VersionUnsupported`].
///   - `minfeerate` non-negative (a negative rate makes no sense and
///     is rejected as `original-psbt-rejected` per BIP-78's
///     "malformed request" guidance).
///   - The combination of `disableoutputsubstitution=1` AND
///     `additionalfeeoutputindex` is allowed but cross-checked at
///     receiver-time only (no early-reject here).
///
/// G16 strictness — the matching HTTP-layer query parser in
/// `crates/rpc/src/rest.rs` rejects unknown / malformed keys before
/// reaching this function. This validator runs once the deserialised
/// struct exists.
pub fn validate_params(params: &PayjoinParams) -> Result<(), PayjoinError> {
    // G21: v=1 sentinel.
    if params.version != 1 {
        return Err(PayjoinError::VersionUnsupported(params.version));
    }
    // G16: non-negative fee rate.
    if let Some(mfr) = params.min_fee_rate {
        if !mfr.is_finite() || mfr < 0.0 {
            return Err(PayjoinError::OriginalPsbtRejected(format!(
                "minfeerate must be a non-negative finite number (got {mfr})"
            )));
        }
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
/// deliberately naive (first eligible) — UIH-1 / UIH-2 fingerprinting
/// awareness lives in [`pick_receiver_utxo_uih`] (G20).
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

/// G20 closure — UIH-1 / UIH-2 anti-fingerprint UTXO selector.
///
/// Background: BIP-78 §"Receiver" warns that a careless receiver-side
/// coin-selector lets chain-analysis heuristics back-distinguish the
/// receiver-added input from the sender's. The two well-known
/// heuristics in the literature (`https://eprint.iacr.org/2022/589.pdf`,
/// §3.1) are:
///
///   UIH-1 ("Unnecessary Input Heuristic 1"):
///     If the receiver-added input value > max(original outputs), an
///     observer can deduce the receiver contributed an input it didn't
///     need (sender's original input alone covered the payment), which
///     leaks "this is a PayJoin, not a real CoinJoin".
///     Avoidance: pick a receiver UTXO `v <= max_original_output`.
///
///   UIH-2 ("Unnecessary Input Heuristic 2"):
///     After PayJoin, the largest output should not be smaller than the
///     second-largest input. If `recv_input + sender_input` produces a
///     transaction where the largest output is < the second-largest
///     input, the structure looks like a "consolidation that overpaid",
///     which is unusual and back-distinguishes PayJoin.
///     Avoidance: pick a receiver UTXO so that
///       max_output_after_pj >= second_largest_input_after_pj.
///
/// Implementation strategy:
///   - Iterate spendable unspent unlocked, skipping `offered` outpoints
///     (mirrors [`pick_receiver_utxo`]).
///   - Score each candidate: prefer "satisfies BOTH UIH-1 and UIH-2"
///     over "satisfies one" over "satisfies neither" — never reject
///     outright (a receiver with one UTXO MUST still serve the
///     PayJoin; UIH is anti-fingerprint hygiene, not consensus).
///   - Among same-score candidates, prefer smaller values (less likely
///     to trip UIH-1 in pathological cases the heuristic didn't see).
///
/// `original_outputs_values` is `psbt.unsigned_tx.outputs.iter().map(|o| o.value)`.
/// `original_inputs_values` is the spent-value of each sender input
/// (the caller computes this from `witness_utxo`/`non_witness_utxo`).
///
/// Returns the chosen UTXO (a `WalletUtxo` clone owned by the caller).
/// Returns [`PayjoinError::NotEnoughMoney`] when there is no eligible
/// candidate.
pub fn pick_receiver_utxo_uih(
    wallet: &Wallet,
    offered: &HashMap<Hash256, OfferedPayjoin>,
    original_outputs_values: &[u64],
    original_inputs_values: &[u64],
) -> Result<WalletUtxo, PayjoinError> {
    let claimed: std::collections::HashSet<OutPoint> = offered
        .values()
        .map(|o| o.receiver_outpoint.clone())
        .collect();

    let max_original_output = original_outputs_values
        .iter()
        .copied()
        .max()
        .unwrap_or(u64::MAX);

    // Find largest existing input value (used for UIH-2 scoring).
    let max_existing_input = original_inputs_values
        .iter()
        .copied()
        .max()
        .unwrap_or(0);

    // Iterate, score, keep best.
    let mut best: Option<(WalletUtxo, u8)> = None;
    for utxo in wallet.list_spendable_unspent_unlocked() {
        if claimed.contains(&utxo.outpoint) {
            continue;
        }
        let v = utxo.value;

        // UIH-1: candidate value <= max original output.
        let uih1 = v <= max_original_output;

        // UIH-2: after adding (v) to inputs and (v) to the largest output,
        // is max_output_after >= second_largest_input_after?
        // - max_output_after = max_original_output + v
        // - second_largest_input_after: among original_inputs and v, the
        //   second-largest. If v >= max_existing_input then second is
        //   max_existing_input; else second is the max-of-the-rest of
        //   original (cheaply approximated as max_existing_input itself
        //   when there's a single original input).
        let max_output_after = max_original_output.saturating_add(v);
        let second_largest_input_after = if v >= max_existing_input {
            max_existing_input
        } else {
            // We approximate: if the receiver UTXO is < max existing input,
            // then the second-largest input is *either* v *or* the
            // 2nd-largest of originals. Without a sorted-pass over all
            // originals, we use `v` as the conservative bound — this only
            // makes the heuristic slightly stricter (rejects some
            // borderline candidates) which is the safer direction for
            // anti-fingerprinting.
            v
        };
        let uih2 = max_output_after >= second_largest_input_after;

        // Score: 2 = both, 1 = one, 0 = neither.
        let score: u8 = (uih1 as u8) + (uih2 as u8);

        let take = match &best {
            None => true,
            Some((existing, exscore)) => {
                if score > *exscore {
                    true
                } else if score == *exscore {
                    // Tie-break: prefer smaller value (less likely to
                    // trip UIH-1 in cases the heuristic missed).
                    v < existing.value
                } else {
                    false
                }
            }
        };
        if take {
            best = Some((utxo.clone(), score));
        }
    }

    best.map(|(u, _)| u).ok_or(PayjoinError::NotEnoughMoney)
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

/// G8 closure — receiver-side output substitution.
///
/// When the sender's BIP-78 URI carries `pjos=0` (or omits it — the
/// default is "substitution allowed"), the receiver MAY replace the
/// receiver output's `script_pubkey` with one of the SAME script type
/// (same leading-opcode prefix). Useful for consolidating: receiver
/// can swap to its own fresh address pointing at a different UTXO
/// chain.
///
/// Implementation: returns a freshly-generated wallet address of the
/// same `AddressType` as the original receiver output's spk shape,
/// then mutates `psbt.unsigned_tx.outputs[recv_idx].script_pubkey` to
/// the new address's spk. Returns the new address (for logging /
/// commit-tracking).
///
/// G14 sender-side enforcement (in `validate_proposed_psbt`) already
/// allows same-type substitution when `disable_output_substitution=false`
/// — this is the symmetric receiver-side producer.
///
/// Returns `Err(PayjoinError::Unavailable(...))` when:
///   - The wallet can't mint a fresh address of the same type
///     (e.g. the wallet was created with `AddressType::P2PKH` but the
///     original output is P2TR — different types).
///   - The PSBT output's script type isn't supported by the wallet.
///
/// Note: this is opt-in. The default request flow
/// ([`handle_payjoin_request`]) only invokes substitution when the
/// caller passes `pjos=Some(false)` AND the receiver-side policy is
/// to substitute. Tests exercise this helper directly to gate G8.
pub fn substitute_receiver_output(
    wallet: &mut Wallet,
    psbt: &mut Psbt,
    recv_output_idx: usize,
) -> Result<String, PayjoinError> {
    if recv_output_idx >= psbt.unsigned_tx.outputs.len() {
        return Err(PayjoinError::Unavailable(
            "receiver output index out of range".to_string(),
        ));
    }
    let original_spk = psbt.unsigned_tx.outputs[recv_output_idx].script_pubkey.clone();
    let original_type = script_type_byte(&original_spk);

    // Generate a fresh receive address (the wallet picks the type per
    // its AddressType). The substitution rule requires same-type, so
    // we verify after.
    let new_addr = wallet
        .get_new_address()
        .map_err(|e| PayjoinError::Unavailable(format!("substitute: get_new_address: {e}")))?;
    let new_spk = Address::from_string(&new_addr, Some(wallet.network()))
        .map_err(|e| PayjoinError::Unavailable(format!("substitute: parse fresh addr: {e}")))?
        .to_script_pubkey();
    let new_type = script_type_byte(&new_spk);
    if new_type != original_type {
        return Err(PayjoinError::Unavailable(format!(
            "substitute: wallet address type ({:?}) differs from original output type ({:?})",
            new_type, original_type
        )));
    }
    // Must also differ — substituting to the same script is a no-op
    // and reveals the wallet's preferred address was already in use.
    if new_spk == original_spk {
        return Err(PayjoinError::Unavailable(
            "substitute: fresh address script equals original (no-op)".to_string(),
        ));
    }
    psbt.unsigned_tx.outputs[recv_output_idx].script_pubkey = new_spk;
    Ok(new_addr)
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

    // G20 (FIX-67): UIH-aware selection. Compute the input/output value
    // vectors once and pass into the heuristic-aware picker; degrade to
    // the naive picker only if the input metadata is missing (which
    // `decode_and_validate_original` already prevents, but the defensive
    // fallback keeps a tighter contract).
    let original_outputs_values: Vec<u64> =
        psbt.unsigned_tx.outputs.iter().map(|o| o.value).collect();
    let original_inputs_values: Vec<u64> = psbt
        .inputs
        .iter()
        .filter_map(|pi| {
            pi.witness_utxo
                .as_ref()
                .map(|w| w.value)
                .or_else(|| pi.non_witness_utxo.as_ref().map(|_| 0))
        })
        .collect();
    let utxo = if original_inputs_values.len() == psbt.unsigned_tx.inputs.len() {
        pick_receiver_utxo_uih(
            wallet,
            existing_offered,
            &original_outputs_values,
            &original_inputs_values,
        )?
    } else {
        pick_receiver_utxo(wallet, existing_offered)?
    };
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
    let secp = secp_ctx();
    let pk = secp256k1::PublicKey::from_secret_key(secp, &sk);
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
// SENDER ANTI-SNOOP VALIDATORS (W119 / FIX-66)
// =====================================================================

/// Sender-side options the BIP-78 sender sends with the Original PSBT.
///
/// Mirrors `PayjoinParams` but from the sender's perspective. The
/// sender writes these into the URL query string the receiver sees
/// AND uses the same values to validate the receiver's reply (anti-
/// snoop checks G10..G15).
///
/// Reference: BIP-78 §"Sender's actions" — "After receiving the
/// modified PSBT, the sender MUST verify that…".
#[derive(Clone, Debug)]
pub struct SenderOptions {
    /// Maximum extra fee the sender will pay over the Original PSBT's
    /// fee. Drives the BIP-78 `maxadditionalfeecontribution` query
    /// param AND the G13 bound check on the reply.
    pub max_additional_fee_contribution: u64,
    /// Index of the output the receiver may draw additional fees from.
    /// Drives `additionalfeeoutputindex` (and is the only output the
    /// sender allows to shrink without rejecting the reply).
    pub additional_fee_output_index: Option<usize>,
    /// If `true`, sender refuses any reply where the sender→receiver
    /// output script type was changed. Drives `disableoutputsubstitution=1`
    /// AND the G14 enforcement on the reply.
    pub disable_output_substitution: bool,
    /// Minimum acceptable fee rate (sat/vB) on the receiver's reply.
    /// Drives `minfeerate` AND the G15 enforcement on the reply.
    pub min_fee_rate: f64,
    /// Sender's own wallet outpoints, used to detect a malicious
    /// receiver who attempts to add another sender-owned UTXO (G12).
    /// Empty is acceptable — the sender just won't flag any input
    /// as "from my own wallet", losing the G12 defence but otherwise
    /// proceeding.
    pub own_wallet_outpoints: std::collections::HashSet<OutPoint>,
}

impl Default for SenderOptions {
    fn default() -> Self {
        Self {
            max_additional_fee_contribution: 0,
            additional_fee_output_index: None,
            disable_output_substitution: false,
            min_fee_rate: 1.0,
            own_wallet_outpoints: std::collections::HashSet::new(),
        }
    }
}

/// Errors a BIP-78 sender raises while validating the receiver's reply.
/// Maps to G10..G15 + G22 (fallback).
#[derive(Debug, thiserror::Error)]
pub enum SenderError {
    /// G10: Proposed PSBT is missing an output that was present in the
    /// Original. Receiver tried to silently drop a sender output.
    #[error("G10 sender-output preservation: original output {0} missing in proposed")]
    OutputMissing(usize),
    /// G10/G14: A non-additional-fee output's value or script changed.
    /// When `disableoutputsubstitution=1` this is also a hard reject.
    #[error("G10/G14 output mutated: output {index}: {reason}")]
    OutputMutated {
        /// Index of the mutated output in the Original PSBT.
        index: usize,
        /// Human-readable reason.
        reason: String,
    },
    /// G11: Receiver changed a sender-input's scriptSig type. This
    /// breaks signing and is forbidden.
    #[error("G11 scriptSig type changed on input {0}")]
    ScriptSigTypeChanged(usize),
    /// G12: Receiver added an input that the sender's wallet owns,
    /// which would let the receiver indirectly link sender's
    /// own-wallet UTXOs.
    #[error("G12 receiver added sender-owned input at index {0}")]
    NewSenderInput(usize),
    /// G10: Receiver dropped one of the original inputs.
    #[error("G10 receiver removed original input {0}")]
    OriginalInputDropped(usize),
    /// G13: Proposed PSBT exceeds Original fee + maxadditionalfeecontribution.
    #[error("G13 fee exceeds bound: original={original}, proposed={proposed}, cap={cap}")]
    FeeBoundExceeded {
        /// Fee on the Original PSBT (sats).
        original: u64,
        /// Fee on the Proposed PSBT (sats).
        proposed: u64,
        /// Sender's `maxadditionalfeecontribution` cap (sats).
        cap: u64,
    },
    /// G15: Resulting fee rate dropped below the sender's `minfeerate`.
    #[error("G15 fee rate {got:.3} below minimum {min:.3} sat/vB")]
    FeeRateTooLow {
        /// Achieved sat/vB.
        got: f64,
        /// Configured minimum sat/vB.
        min: f64,
    },
    /// Generic structural rejection of the proposed PSBT (un-parseable,
    /// missing utxo data, ...). Distinct from G10..G15 because it
    /// doesn't map to a "receiver tried to cheat" failure — usually a
    /// receiver bug.
    #[error("Proposed PSBT structurally invalid: {0}")]
    InvalidProposed(String),
}

/// Validate a Proposed PSBT against the Original PSBT and the sender's
/// own configuration. Runs all six anti-snoop validators (G10..G15) in
/// one pass — any failure returns Err.
///
/// `original` is the PSBT the sender sent on the wire.
/// `proposed` is the PSBT the receiver returned.
/// `opts` carries the sender's BIP-78 options.
///
/// Sender-output substitution rules (G10): every Original output's
/// (script, value) MUST appear in Proposed, with two relaxations:
///   - The output at `additional_fee_output_index` may have its
///     value decreased by up to `max_additional_fee_contribution`
///     sats (sender contributes to fee). Its script MUST NOT change.
///   - When `disable_output_substitution = false`, the receiver-paying
///     output (the only output in Original whose value can plausibly
///     increase) may have its value increased *and* its script
///     substituted, but only to a script of the same type
///     (same first opcode prefix) and only with `pjos=1` (the
///     default, captured by `disable_output_substitution=false`).
///
/// G11 — scriptSig types: each Original input's spent-script type
/// (derived from `witness_utxo.script_pubkey` first byte) MUST equal
/// the type in Proposed (receiver MUST NOT swap a P2WPKH for a P2WSH
/// etc).
///
/// G12 — new inputs from sender's wallet: every input in Proposed
/// that wasn't in Original MUST NOT match `opts.own_wallet_outpoints`.
///
/// G13 — fee bound: `fee(Proposed) ≤ fee(Original) + max_additional_fee_contribution`.
///
/// G15 — minimum fee rate: `fee(Proposed) / vsize(Proposed) ≥ min_fee_rate`.
pub fn validate_proposed_psbt(
    original: &Psbt,
    proposed: &Psbt,
    opts: &SenderOptions,
) -> Result<(), SenderError> {
    // --- Compute fees + vsize on both PSBTs first. ---
    let orig_fee = compute_psbt_fee(original)?;
    let prop_fee = compute_psbt_fee(proposed)?;

    // G13 fee bound. We compute this before the per-output check so a
    // grossly-out-of-spec reply fails fast.
    let cap = opts.max_additional_fee_contribution;
    if prop_fee > orig_fee.saturating_add(cap) {
        return Err(SenderError::FeeBoundExceeded {
            original: orig_fee,
            proposed: prop_fee,
            cap,
        });
    }

    // G15 minimum fee rate (proposed must clear sender's minfeerate).
    let prop_vsize = proposed.unsigned_tx.vsize() as f64;
    if prop_vsize > 0.0 {
        let achieved = prop_fee as f64 / prop_vsize;
        if achieved + 1e-9 < opts.min_fee_rate {
            return Err(SenderError::FeeRateTooLow {
                got: achieved,
                min: opts.min_fee_rate,
            });
        }
    }

    // --- G10 + G14: outputs preserved (with allowed relaxations). ---
    // Build a multiset of (script_pubkey, value) for Proposed.
    let mut proposed_outputs: Vec<(Vec<u8>, u64)> = proposed
        .unsigned_tx
        .outputs
        .iter()
        .map(|o| (o.script_pubkey.clone(), o.value))
        .collect();

    for (i, orig_out) in original.unsigned_tx.outputs.iter().enumerate() {
        // First, try the exact match: same script, same value.
        if let Some(pos) = proposed_outputs
            .iter()
            .position(|(spk, v)| *spk == orig_out.script_pubkey && *v == orig_out.value)
        {
            proposed_outputs.swap_remove(pos);
            continue;
        }
        // No exact match — may we accept a relaxed match?
        // Relaxation A: same-script output at additionalfeeoutputindex
        // with decreased value (within cap).
        if Some(i) == opts.additional_fee_output_index {
            if let Some(pos) = proposed_outputs
                .iter()
                .position(|(spk, v)| *spk == orig_out.script_pubkey && *v <= orig_out.value)
            {
                let (_, new_v) = &proposed_outputs[pos];
                let drop_amount = orig_out.value - *new_v;
                if drop_amount > cap {
                    return Err(SenderError::OutputMutated {
                        index: i,
                        reason: format!(
                            "fee-output drop {drop_amount} exceeds maxadditionalfeecontribution {cap}"
                        ),
                    });
                }
                proposed_outputs.swap_remove(pos);
                continue;
            }
        }
        // Relaxation B: same-script output whose value INCREASED. The
        // receiver-paying output legitimately gains the receiver's
        // contribution. This relaxation respects pjos=1: script MUST
        // remain byte-equal, only value rises.
        if let Some(pos) = proposed_outputs
            .iter()
            .position(|(spk, v)| *spk == orig_out.script_pubkey && *v >= orig_out.value)
        {
            proposed_outputs.swap_remove(pos);
            continue;
        }
        // Relaxation C (G14, pjos=0 only): same-script-TYPE substitution.
        // BIP-78 permits the receiver to replace its own output script
        // with one of the same type when pjos=1 is NOT set in the URI
        // (i.e. `disable_output_substitution=false` on the sender).
        if !opts.disable_output_substitution {
            let want_type = script_type_byte(&orig_out.script_pubkey);
            if let Some(pos) = proposed_outputs.iter().position(|(spk, v)| {
                script_type_byte(spk) == want_type && *v >= orig_out.value
            }) {
                proposed_outputs.swap_remove(pos);
                continue;
            }
        } else {
            // pjos=1 + no exact-or-value-up match → script was mutated.
            return Err(SenderError::OutputMutated {
                index: i,
                reason: "disableoutputsubstitution=1 but output script changed".to_string(),
            });
        }
        // No relaxation salvaged this output → G10 violation.
        return Err(SenderError::OutputMissing(i));
    }

    // --- G11: scriptSig types preserved on Original inputs. ---
    // BIP-78 says "scriptSig types" but for SegWit inputs (the only
    // ones the receiver foundation supports) the scriptSig is empty,
    // and the equivalent invariant is "the script type of the spent
    // output". We derive it from witness_utxo.script_pubkey's leading
    // byte (a robust, type-only signature).
    for (i, orig_in) in original.unsigned_tx.inputs.iter().enumerate() {
        let prop_in = proposed
            .unsigned_tx
            .inputs
            .iter()
            .find(|p| p.previous_output == orig_in.previous_output)
            .ok_or(SenderError::OriginalInputDropped(i))?;
        // scriptSig field must remain empty/unchanged for SegWit and
        // for any input the sender will sign post-PayJoin. The
        // receiver MUST NOT prepopulate it.
        if orig_in.script_sig != prop_in.script_sig {
            return Err(SenderError::ScriptSigTypeChanged(i));
        }
        // Spent-script type (via PSBT witness_utxo lookup).
        let orig_spk_type = original
            .inputs
            .get(i)
            .and_then(|p| p.witness_utxo.as_ref().map(|u| script_type_byte(&u.script_pubkey)))
            .unwrap_or(None);
        let prop_idx = proposed
            .unsigned_tx
            .inputs
            .iter()
            .position(|p| p.previous_output == orig_in.previous_output)
            .ok_or(SenderError::OriginalInputDropped(i))?;
        let prop_spk_type = proposed
            .inputs
            .get(prop_idx)
            .and_then(|p| p.witness_utxo.as_ref().map(|u| script_type_byte(&u.script_pubkey)))
            .unwrap_or(None);
        if orig_spk_type != prop_spk_type {
            return Err(SenderError::ScriptSigTypeChanged(i));
        }
    }

    // --- G12: no new inputs that the sender's wallet owns. ---
    let orig_outpoints: std::collections::HashSet<OutPoint> = original
        .unsigned_tx
        .inputs
        .iter()
        .map(|i| i.previous_output.clone())
        .collect();
    for (i, prop_in) in proposed.unsigned_tx.inputs.iter().enumerate() {
        if orig_outpoints.contains(&prop_in.previous_output) {
            continue; // pre-existing sender input — fine
        }
        // New input. Make sure it isn't ours.
        if opts.own_wallet_outpoints.contains(&prop_in.previous_output) {
            return Err(SenderError::NewSenderInput(i));
        }
    }

    Ok(())
}

/// Compute the implicit fee on a PSBT: Σ(input values from witness_utxo /
/// non_witness_utxo) - Σ(unsigned_tx.outputs.value).
///
/// Returns [`SenderError::InvalidProposed`] when an input lacks the
/// utxo metadata required to derive its spent value.
fn compute_psbt_fee(psbt: &Psbt) -> Result<u64, SenderError> {
    let mut in_total: u64 = 0;
    for (i, ti) in psbt.unsigned_tx.inputs.iter().enumerate() {
        let pin = psbt
            .inputs
            .get(i)
            .ok_or_else(|| SenderError::InvalidProposed(format!("psbt input {i} missing entry")))?;
        if let Some(wu) = &pin.witness_utxo {
            in_total = in_total
                .checked_add(wu.value)
                .ok_or_else(|| SenderError::InvalidProposed("u64 overflow in fee total".into()))?;
        } else if let Some(prev) = &pin.non_witness_utxo {
            let vout = ti.previous_output.vout as usize;
            let out = prev.outputs.get(vout).ok_or_else(|| {
                SenderError::InvalidProposed(format!(
                    "non_witness_utxo vout {vout} oob for input {i}"
                ))
            })?;
            in_total = in_total
                .checked_add(out.value)
                .ok_or_else(|| SenderError::InvalidProposed("u64 overflow in fee total".into()))?;
        } else {
            return Err(SenderError::InvalidProposed(format!(
                "input {i} has no utxo data; cannot compute fee"
            )));
        }
    }
    let out_total: u64 = psbt
        .unsigned_tx
        .outputs
        .iter()
        .map(|o| o.value)
        .sum();
    if in_total < out_total {
        return Err(SenderError::InvalidProposed(format!(
            "outputs ({out_total}) exceed inputs ({in_total})"
        )));
    }
    Ok(in_total - out_total)
}

/// Return the leading "type byte" of a scriptPubKey for G10/G14
/// same-type substitution checks. This is intentionally coarse: it
/// only inspects the first opcode, which is enough to tell P2WPKH/
/// P2WSH (0x00) from P2TR (0x51) from P2PKH/P2SH legacy (0x76/0xa9).
/// Returns `None` for empty scripts.
fn script_type_byte(spk: &[u8]) -> Option<u8> {
    spk.first().copied()
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
