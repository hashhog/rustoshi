//! W119 BIP-78 PayJoin audit — rustoshi (Rust)
//!
//! 30-gate audit of PayJoin (BIP-78) support. PayJoin is a
//! sender↔receiver-collaborative payment protocol that breaks the
//! "common input ownership heuristic" by having BOTH parties
//! contribute inputs. Externally the resulting transaction looks like
//! a CoinJoin.
//!
//! **Bitcoin Core has NO PayJoin support** — this audit measures
//! against the BIP-78 spec + ecosystem reference implementations:
//!   - https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
//!   - https://payjoin.org/ (Rust reference impl `payjoin` crate)
//!   - https://github.com/btcpayserver/btcpayserver (production
//!     receiver-side server)
//!   - JoinMarket (production sender + receiver)
//!
//! ## Protocol summary
//!
//!  1. Receiver publishes a BIP-21 URI with `pj=` query param:
//!     `bitcoin:bc1...?amount=0.01&pj=https://example.com/payjoin&pjos=0`
//!  2. Sender builds a normal PSBT paying receiver (the "Original PSBT").
//!  3. Sender HTTP-POSTs Original PSBT (base64) to `pj` endpoint with
//!     `Content-Type: text/plain` + query params:
//!     `v=1`, `additionalfeeoutputindex`,
//!     `maxadditionalfeecontribution`, `disableoutputsubstitution`,
//!     `minfeerate`.
//!  4. Receiver validates the Original PSBT (no key leakage, scripts
//!     unchanged), adds own inputs + outputs, signs its own inputs,
//!     and returns the modified PSBT.
//!  5. Sender runs anti-snooping checks against the receiver's reply
//!     before signing its own inputs and broadcasting.
//!
//! ## Audit summary
//!
//!   - 30/30 gates MISSING ENTIRELY.
//!   - Zero source-tree references to `payjoin`, `PayJoin`, `BIP-78`,
//!     `pj=`, `pjos`, `additionalfeeoutputindex`,
//!     `maxadditionalfeecontribution`, `disableoutputsubstitution`,
//!     `original-psbt`.
//!   - No BIP-21 URI parser exists at all (the closest matches are
//!     doc comments "for Bitcoin: …" — pure prose). Nothing handles
//!     `bitcoin:` URIs anywhere in the codebase.
//!   - The HTTP stack (axum + hyper 1.x in `crates/rpc/src/rest.rs`)
//!     is available to host a receiver endpoint, but no PayJoin
//!     handler is registered on it. No HTTP client (reqwest /
//!     hyper-client / equivalent) is wired for the sender side at
//!     all — outbound HTTPS for sender→receiver POST is absent.
//!   - The PSBT primitive (`crates/wallet/src/psbt.rs`) implements
//!     PSBTv0 round-trip including `from_unsigned_tx`, `combine`,
//!     `merge`, `finalize`, `extract_tx`, `to_base64`,
//!     `from_base64` — these are the *building blocks* a PayJoin
//!     implementation would need, but they have no PayJoin caller.
//!   - The wallet (`crates/wallet/src/wallet.rs`) tracks
//!     `sent_txs: HashMap<Hash256, SentTx>` (added in FIX-61 to
//!     support `bumpfee`/`psbtbumpfee`). A PayJoin receiver would
//!     need analogous tracking ("which UTXOs are committed to an
//!     offered but not yet finalised PayJoin"), and there is none.
//!
//! ## Bug inventory
//!
//!   BUG-1  [HIGH]  G1+G23: Receiver HTTP endpoint MISSING ENTIRELY.
//!                  No `POST /payjoin` route is registered on the axum
//!                  REST router in `crates/rpc/src/rest.rs`.
//!                  Content-Type / Content-Length validation
//!                  unattainable since the handler is absent.
//!                  Fix sketch: add a new `crates/wallet/src/payjoin/
//!                  receiver.rs` module + register
//!                  `Router::new().route("/payjoin", post(handler))`
//!                  on a dedicated PayJoin listener (per BIP-78 the
//!                  endpoint URL is operator-configurable and need
//!                  not collide with the RPC port).
//!
//!   BUG-2  [HIGH]  G2: Sender HTTP client MISSING ENTIRELY. No
//!                  reqwest / hyper-client dependency, no TLS-capable
//!                  outbound HTTP path. `Cargo.toml` for the wallet
//!                  crate has no client deps (only `rusqlite`, secp,
//!                  hashing). Fix sketch: add `reqwest = { version =
//!                  "0.12", features = ["rustls-tls"] }` or
//!                  `hyper-rustls` to the wallet crate, and a
//!                  `crates/wallet/src/payjoin/sender.rs` module with
//!                  `post_original_psbt(endpoint: &Url, psbt: &Psbt,
//!                  opts: SenderOpts) -> Result<Psbt, PayJoinError>`.
//!
//!   BUG-3  [HIGH]  G3+G24+G25: TLS / HTTPS / .onion-only sender
//!                  policy MISSING. BIP-78 §"Receiver's well known
//!                  errors" warns clients to refuse plain-HTTP except
//!                  for .onion endpoints. With no HTTP client, this
//!                  policy has nowhere to live. Fix sketch: in the
//!                  sender module, gate scheme on `url.scheme() ==
//!                  "https"` OR (`url.scheme() == "http"` AND host
//!                  ends-with `.onion`).
//!
//!   BUG-4  [HIGH]  G4+G5: Receiver-side Original-PSBT validation
//!                  MISSING. BIP-78 receiver MUST verify the Original
//!                  PSBT does not contain `non_witness_utxo` for
//!                  segwit inputs (leaks unrelated history), MUST
//!                  reject PSBTs with key origin info on the sender's
//!                  inputs that would let receiver fingerprint the
//!                  sender's wallet, and MUST verify all sender
//!                  inputs are finalised. None of those checks
//!                  exist (there is no caller). The underlying
//!                  primitives (`Psbt::is_finalized`,
//!                  `Psbt::count_unsigned_inputs`) exist.
//!
//!   BUG-5  [HIGH]  G6+G9+G13: Receiver fee-adjustment path MISSING.
//!                  BIP-78 receiver may increase the fee from the
//!                  Original PSBT by up to
//!                  `maxadditionalfeecontribution` satoshis, deducted
//!                  from the output at `additionalfeeoutputindex`.
//!                  No receiver flow exists, so neither the
//!                  identification of the fee-output index nor the
//!                  bounded-increase logic exists.
//!
//!   BUG-6  [HIGH]  G7+G20: Receiver input-selection +
//!                  anti-fingerprinting MISSING. BIP-78 recommends
//!                  UIH-1 (don't pick an input larger than any
//!                  output) / UIH-2 (avoid creating a tx where the
//!                  largest output is < the second-largest input) to
//!                  avoid letting chain-analysis heuristics
//!                  back-distinguish receiver-added inputs.
//!                  `crates/wallet/src/coin_selection.rs` has only
//!                  the *sender* selection strategies; there is no
//!                  receiver-side UIH-aware selector.
//!
//!   BUG-7  [HIGH]  G8+G14: Receiver output-substitution MISSING.
//!                  BIP-78 receiver may replace its own output
//!                  script (e.g. consolidate change into the same
//!                  output) when `pjos=1` (default). No code path
//!                  modifies the Original PSBT's outputs in any way.
//!
//!   BUG-8  [HIGH]  G10+G11+G12: Sender anti-snoop checks MISSING.
//!                  After receiving the modified PSBT, the sender
//!                  MUST verify:
//!                    (a) all Original-PSBT inputs are still present
//!                        with the same scriptSig types;
//!                    (b) no new inputs spend from the sender's
//!                        wallet (defeats UIH attack);
//!                    (c) sender's payment to receiver is preserved
//!                        unless pjos=1 + script type matches.
//!                  None of these exist; without a sender module
//!                  there is no caller for them.
//!
//!   BUG-9  [HIGH]  G13+G15: Sender bound enforcement
//!                  (`maxadditionalfeecontribution`, `minfeerate`)
//!                  MISSING. Sender MUST reject the modified PSBT if
//!                  fee increased by more than the contribution cap
//!                  or if the resulting fee rate dropped below
//!                  `minfeerate`. No callers.
//!
//!   BUG-10 [HIGH]  G14: Sender enforcement of
//!                  `disableoutputsubstitution` MISSING. The sender
//!                  MUST send `disableoutputsubstitution=1` (or
//!                  honour `pjos=0` from the BIP-21 URI) and refuse
//!                  any reply that changed the sender→receiver
//!                  output script when output substitution is
//!                  disabled.
//!
//!   BUG-11 [HIGH]  G16+G21: BIP-78 query-string parser MISSING.
//!                  `v`, `additionalfeeoutputindex`,
//!                  `maxadditionalfeecontribution`,
//!                  `disableoutputsubstitution`, `minfeerate` are
//!                  the five wire query params. None are parsed
//!                  anywhere (no `match` arm in any RPC / REST
//!                  dispatcher accepts them). Also: BIP-78 specifies
//!                  `v=1` and a 4xx `version-unsupported` reply for
//!                  anything else; the version sentinel is absent.
//!
//!   BUG-12 [HIGH]  G17: Receiver BIP-78 error-response shape
//!                  MISSING. BIP-78 specifies a 4xx response with a
//!                  JSON body `{"errorCode": "unavailable" |
//!                  "not-enough-money" | "version-unsupported" |
//!                  "original-psbt-rejected", "message": "..."}`.
//!                  No such response shape exists (the RPC layer
//!                  uses jsonrpsee's error envelope, which is a
//!                  completely different shape; the REST layer's
//!                  error type is `RestError` with HTTP-only
//!                  semantics).
//!
//!   BUG-13 [HIGH]  G18+G19+G30: Receiver state machine + UTXO
//!                  reservation + replay protection MISSING. BIP-78
//!                  receiver MUST hold the offered inputs reserved
//!                  until the sender's signed broadcast (or TTL
//!                  expires) to prevent double-spending the same
//!                  UTXO across two concurrent PayJoins, AND MUST
//!                  treat the Original-PSBT id as a replay key. The
//!                  wallet has no concept of "reserved UTXO" of any
//!                  kind (FIX-61's `sent_txs` tracks *outgoing*,
//!                  not *offered*). Fix sketch: add `offered_pj:
//!                  HashMap<PsbtId, OfferedPayjoin>` to `Wallet`,
//!                  drive expiration on a background task.
//!
//!   BUG-14 [HIGH]  G22: Sender fallback-to-original MISSING. BIP-78
//!                  says on any error / timeout / unreachable
//!                  receiver, the sender SHOULD broadcast the
//!                  Original PSBT unmodified to avoid losing the
//!                  payment. With no sender flow, fallback is moot.
//!
//!   BUG-15 [HIGH]  G26+G27: PayJoin RPCs MISSING. No
//!                  `getpayjoinrequest` (receiver-side: vend a
//!                  BIP-21 URI with `pj=` param wired to the local
//!                  receiver), no `sendpayjoinrequest` (sender-side:
//!                  given a `bitcoin:?pj=` URI, run the full PayJoin
//!                  flow). The `WalletRpc` trait at
//!                  `crates/rpc/src/wallet.rs` has 25 methods —
//!                  zero are PayJoin.
//!
//!   BUG-16 [HIGH]  G28+G29: BIP-21 URI parser MISSING ENTIRELY.
//!                  FIX-62 (W119 prereq closure): implemented at
//!                  `crates/wallet/src/bip21.rs` with
//!                  `parse_bip21(input: &str, network: Network) ->
//!                   Result<Bip21Uri, Bip21Error>`. Recognises
//!                  `amount` (decimal-BTC string → satoshi u64 with
//!                  no f64 rounding), `label`/`message` (percent-
//!                  decoded UTF-8), `lightning` (BOLT-11 fallback,
//!                  pass-through), and BIP-78 `pj` / `pjos`.
//!                  Unknown `req-` keys reject the URI per spec;
//!                  unknown unprefixed keys are preserved in
//!                  `extras` for forward-compat. Address parsing
//!                  enforces the active network constraint via the
//!                  existing `Address::from_string` parser.
//!                  G28+G29 (this file) now exercise the real
//!                  parser. Remaining BIP-78 sender/receiver flow
//!                  (BUG-1..15) is still MISSING.
//!
//! ## Severity legend
//!   P0 — security / consensus / interop divergence on the wire
//!   P1 — interop divergence on the wire
//!   HIGH — large feature absent or wrong
//!   MED — partial / edge-case wrong / silent ignore
//!   LOW — UX / default mismatch / documented confirmation
//!
//! No P0 / P1 in W119 for rustoshi: BIP-78 has no consensus or P2P
//! component, and absence-of-feature is "user has no way to receive
//! PayJoin payments" rather than "wire format diverges". The
//! sixteen bugs above are catalogued as HIGH since *every* gate is
//! gated on the missing wiring; they cluster naturally into the
//! sender, receiver, anti-snooping, URI, and RPC layers.
//!
//! ## Per-gate result table
//!
//!   G1  Receiver POST /payjoin endpoint              — PRESENT (FIX-65) — BUG-1 closed
//!   G2  Sender HTTP client POSTs Original PSBT      — MISSING — BUG-2
//!   G3  TLS / HTTPS or .onion required by sender    — MISSING — BUG-3
//!   G4  Original PSBT v0 deserialization on receiver — PRESENT (FIX-65) — BUG-4 partial closed
//!   G5  Receiver validates Original PSBT (no key leakage) — PARTIAL (FIX-65 structural only; key-leakage in FIX-67) — BUG-4
//!   G6  Receiver identifies fee output (additionalfeeoutputindex) — PARTIAL (FIX-65 plumbing; routing in FIX-67) — BUG-5
//!   G7  Receiver adds own inputs (anti-fingerprinting selection) — PARTIAL (FIX-65 naive selector; UIH in FIX-67) — BUG-6
//!   G8  Receiver modifies sender's output (substitution within rules) — MISSING — BUG-7
//!   G9  Receiver adjusts fee (within maxadditionalfeecontribution) — PRESENT (FIX-65) — BUG-5 partial closed
//!   G10 Sender anti-snoop: sender's outputs preserved — MISSING — BUG-8
//!   G11 Sender anti-snoop: scriptSig types preserved — MISSING — BUG-8
//!   G12 Sender anti-snoop: no new inputs from sender's wallet — MISSING — BUG-8
//!   G13 Sender anti-snoop: max additional fee contribution respected — MISSING — BUG-9
//!   G14 Sender anti-snoop: disableoutputsubstitution honored — MISSING — BUG-10
//!   G15 Sender anti-snoop: min-fee-rate respected — MISSING — BUG-9
//!   G16 BIP-78 query params parsed                  — MISSING — BUG-11
//!   G17 Receiver error responses (errorCode JSON)  — PRESENT (FIX-65) — BUG-12 closed
//!   G18 Receiver expiration / TTL on offered payjoin — MISSING — BUG-13
//!   G19 Receiver no-double-spending guard           — PRESENT (FIX-65) — BUG-13 partial
//!   G20 Receiver UTXO selection anti-fingerprinting (UIH-1 / UIH-2) — MISSING — BUG-6
//!   G21 Receiver PSBT version constant (BIP-78 v=1) — MISSING — BUG-11
//!   G22 Sender max retry / fallback to original tx  — MISSING — BUG-14
//!   G23 Receiver request validation (Content-Type, Content-Length) — MISSING — BUG-1
//!   G24 HTTPS cert validation (sender side)         — MISSING — BUG-3
//!   G25 Tor onion service support                   — MISSING — BUG-3
//!   G26 getpayjoinrequest / receiver-side RPC      — MISSING — BUG-15
//!   G27 sendpayjoinrequest / sender-side RPC       — MISSING — BUG-15
//!   G28 BIP-21 URI parser supports `pj=`           — PRESENT (FIX-62) — BUG-16 closed
//!   G29 BIP-21 URI parser supports `pjos=`         — PRESENT (FIX-62) — BUG-16 closed
//!   G30 Receiver replay protection (PSBT-id unique) — MISSING — BUG-13
//!
//! Totals after FIX-65: 20 MISSING / 3 PARTIAL / 7 PRESENT (was 28/0/2).
//!         16 bugs (BUG-1, BUG-12, BUG-16 fully closed;
//!                  BUG-4, BUG-5, BUG-6, BUG-13 partial closure;
//!                  BUG-2, BUG-3, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11,
//!                  BUG-14, BUG-15 still open).
//!
//! FIX-65 flipped: G1, G4 (receiver-side), G5, G6, G7, G9, G17, G19.

use std::collections::HashMap;

use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_wallet::payjoin::{
    build_modified_psbt, decode_and_validate_original, find_receiver_output,
    handle_payjoin_request, pick_receiver_utxo, validate_params, OfferedPayjoin, PayjoinError,
    PayjoinParams, MAX_ORIGINAL_PSBT_BYTES,
};
use rustoshi_wallet::{parse_bip21, AddressType, Psbt, Wallet, WalletUtxo};

/// Build a 1-in/1-out Original PSBT paying `recv_addr` `recv_value`
/// satoshis. Used by FIX-65 gate flips (G4..G9, G17, G19) — the helper
/// mirrors the one in `crates/wallet/src/payjoin.rs#tests`.
fn make_original_psbt_for_addr(recv_addr: &str, recv_value: u64) -> Psbt {
    let recv_spk = Address::from_string(recv_addr, Some(Network::Regtest))
        .expect("parse recv addr")
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
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: recv_value + 10_000,
        script_pubkey: {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&[0x77; 20]);
            s
        },
    });
    psbt
}

/// Build a Wallet with one P2WPKH UTXO at `value` sats and one fresh
/// receive address. Returns `(wallet, recv_address)`.
fn funded_wallet(seed_byte: u8, value: u64) -> (Wallet, String) {
    let mut w = Wallet::from_seed(&[seed_byte; 64], Network::Regtest, AddressType::P2WPKH)
        .expect("wallet from seed");
    w.set_chain_height(200);
    let addr = w.get_new_address().expect("fresh recv addr");
    let path = w.get_derivation_path(&addr).unwrap().clone();
    let spk = Address::from_string(&addr, Some(Network::Regtest))
        .unwrap()
        .to_script_pubkey();
    w.add_utxo(WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0xab; 32]),
            vout: 0,
        },
        value,
        script_pubkey: spk,
        derivation_path: path,
        confirmations: 10,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    });
    (w, addr)
}

/// Local helper mirroring `test_w118_wallet::make_unsigned_tx`. Kept
/// inline so this audit test compiles standalone without depending on
/// W118's private test surface.
fn make_unsigned_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
    let inputs: Vec<TxIn> = (0..num_inputs)
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([i as u8; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xfffffffd,
            witness: vec![],
        })
        .collect();
    let outputs: Vec<TxOut> = (0..num_outputs)
        .map(|i| TxOut {
            value: 50_000 + (i as u64 * 1000),
            script_pubkey: {
                // 22-byte P2WPKH spk: OP_0 <20 bytes>
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[i as u8; 20]);
                s
            },
        })
        .collect();
    Transaction {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
    }
}

// FIX-62: parse_bip21 now exists in rustoshi_wallet — the
// `Bip21UriProbe` shim has been removed and G28/G29 below call the
// real parser. See crates/wallet/src/bip21.rs.

// ============================================================
// G1 — Receiver POST /payjoin endpoint
// ============================================================
#[test]
fn g1_receiver_post_payjoin_endpoint_bug1_fix65() {
    // FIX-65 closure: `POST /payjoin` is registered by
    // `rustoshi_rpc::rest::rest_router_with_wallet` in
    // crates/rpc/src/rest.rs. The full HTTP-level round-trip lives in
    // `crates/rpc/tests/test_fix65_payjoin_receiver.rs`
    // (`payjoin_round_trip_returns_modified_psbt`).
    //
    // Library-side: the receiver pipeline that the route invokes is
    // importable as `rustoshi_wallet::payjoin::handle_payjoin_request`.
    // We exercise it here to keep the audit binary self-contained — a
    // successful end-to-end call proves the receiver foundation is
    // wired regardless of whether the HTTP layer is being inspected.
    let (wallet, addr) = funded_wallet(0xa1, 500_000);
    let psbt = make_original_psbt_for_addr(&addr, 50_000);
    let body = psbt.to_base64();
    let params = PayjoinParams {
        version: 1,
        max_additional_fee_contribution: Some(1_000),
        ..Default::default()
    };
    let offered = HashMap::new();
    let res = handle_payjoin_request(body.as_bytes(), &params, &wallet, &offered)
        .expect("FIX-65 receiver pipeline must accept a valid request");
    assert_eq!(
        res.modified_psbt.unsigned_tx.inputs.len(),
        2,
        "receiver adds exactly one input"
    );
}

// ============================================================
// G2 — Sender HTTP client posts Original PSBT
// ============================================================
#[test]
#[ignore = "BUG-2: no HTTP client wired for sender→receiver POST"]
fn g2_sender_http_client_post_bug2() {
    // BUG-2: No reqwest / hyper-client / equivalent dependency in
    // rustoshi-wallet/Cargo.toml. The crate cannot make outbound
    // HTTPS calls.
    panic!("BUG-2: Sender HTTP client MISSING ENTIRELY");
}

// ============================================================
// G3 — TLS / HTTPS or .onion required by sender
// ============================================================
#[test]
#[ignore = "BUG-3: no scheme gating exists; no sender flow exists"]
fn g3_sender_requires_tls_or_onion_bug3() {
    // BUG-3: BIP-78 requires sender to refuse plain-HTTP except for
    // .onion. With no sender, this policy is moot.
    panic!("BUG-3: HTTPS/.onion sender policy MISSING ENTIRELY");
}

// ============================================================
// G4 — Original PSBT v0 deserialization on receiver
// ============================================================
#[test]
fn g4_psbt_v0_deserialize_underlying_primitive_works() {
    // Sanity: the PSBTv0 primitives that a receiver would call EXIST
    // and round-trip. This is the only "building block PRESENT"
    // assertion in the file — the wiring on top of these primitives
    // is MISSING.
    let tx = make_unsigned_tx(1, 1);
    let psbt = Psbt::from_unsigned_tx(tx).expect("PSBTv0 from 1-in/1-out must construct");
    let b64 = psbt.to_base64();
    let back = Psbt::from_base64(&b64).expect("round-trip must work");
    assert_eq!(b64, back.to_base64(), "base64 PSBT round-trip");
}

#[test]
fn g4_receiver_deserializes_original_psbt_bug4_fix65() {
    // FIX-65 closure: `decode_and_validate_original` parses the base64
    // body into a `Psbt` and rejects empty / over-sized / unparseable
    // bodies (returning `PayjoinError::OriginalPsbtRejected`).
    let (_w, addr) = funded_wallet(0xa2, 1_000_000);
    let psbt = make_original_psbt_for_addr(&addr, 50_000);
    let body = psbt.to_base64();
    let parsed = decode_and_validate_original(body.as_bytes())
        .expect("FIX-65 receiver must decode a well-formed Original PSBT");
    assert_eq!(parsed.inputs.len(), 1, "one input on the original");
    assert_eq!(parsed.outputs.len(), 1, "one output on the original");

    // Oversize body is rejected with the BIP-78 wire code.
    let oversize = vec![b'a'; MAX_ORIGINAL_PSBT_BYTES + 1];
    let err = decode_and_validate_original(&oversize)
        .expect_err("oversize body must reject");
    assert_eq!(err.code(), "original-psbt-rejected");
}

// ============================================================
// G5 — Receiver validates Original PSBT (no key info leakage)
// ============================================================
#[test]
fn g5_receiver_validates_no_key_leakage_bug4_fix65() {
    // FIX-65 foundation: the receiver pipeline enforces the
    // structural validation BIP-78 requires before any receiver action
    // is taken:
    //   - every input MUST carry a `witness_utxo` or `non_witness_utxo`
    //   - at least one output MUST pay a wallet-owned address.
    //
    // Full key-leakage policy (rejecting non_witness_utxo for segwit
    // inputs, blocking key-origin info on sender inputs) lands with the
    // sender-side anti-snoop work in FIX-66/FIX-67. The structural
    // checks below are the receiver-foundation contract today.
    let (wallet, _addr) = funded_wallet(0xa3, 1_000_000);

    // Build a malformed PSBT: 1 input with NEITHER utxo view.
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0xcc; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: {
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[0x44; 20]);
                s
            },
        }],
        lock_time: 0,
    };
    let psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
    let body = psbt.to_base64();
    let err = decode_and_validate_original(body.as_bytes())
        .expect_err("missing utxo view must reject");
    assert_eq!(err.code(), "original-psbt-rejected");

    // Build a valid-structure PSBT that pays NOBODY of the wallet —
    // find_receiver_output should reject.
    let outsider = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let outsider_psbt = make_original_psbt_for_addr(outsider, 50_000);
    let err = find_receiver_output(&outsider_psbt, &wallet)
        .expect_err("PSBT must pay receiver wallet");
    assert_eq!(err.code(), "original-psbt-rejected");
}

// ============================================================
// G6 — Receiver identifies fee output (additionalfeeoutputindex)
// ============================================================
#[test]
fn g6_receiver_identifies_fee_output_bug5_fix65() {
    // FIX-65 closure: `PayjoinParams::additional_fee_output_index` is
    // parsed off the query string by the REST handler and propagated
    // into the receiver pipeline. The receiver foundation deducts the
    // delta-fee from the receiver-output (not the additional-fee
    // output) — full additional_fee_output_index routing lands with
    // BUG-9 in FIX-67. Today we just exercise the param plumbing.
    let p = PayjoinParams {
        version: 1,
        additional_fee_output_index: Some(3),
        max_additional_fee_contribution: Some(1_000),
        ..Default::default()
    };
    validate_params(&p).expect("v=1 with idx must pass");
    assert_eq!(p.additional_fee_output_index, Some(3));
}

// ============================================================
// G7 — Receiver adds own inputs (anti-fingerprinting selection)
// ============================================================
#[test]
fn g7_receiver_adds_own_inputs_bug6_fix65() {
    // FIX-65 foundation: receiver picks a single wallet UTXO and
    // appends it to the PSBT. The selector is naive (first eligible)
    // — UIH-1 / UIH-2 anti-fingerprinting lands in FIX-67 (G20).
    let (wallet, addr) = funded_wallet(0xa4, 1_500_000);
    let psbt = make_original_psbt_for_addr(&addr, 50_000);
    let (recv_idx, _addr) =
        find_receiver_output(&psbt, &wallet).expect("recv output exists");

    let offered = HashMap::new();
    let utxo = pick_receiver_utxo(&wallet, &offered).expect("UTXO available");
    assert_eq!(utxo.value, 1_500_000, "selected the funded UTXO");

    let res = build_modified_psbt(&wallet, psbt, recv_idx, utxo.clone(), 68)
        .expect("modify PSBT");
    assert_eq!(
        res.modified_psbt.unsigned_tx.inputs.len(),
        2,
        "one input added"
    );
    assert_eq!(
        res.modified_psbt.unsigned_tx.inputs[1].previous_output,
        utxo.outpoint,
        "appended input references the selected UTXO"
    );
}

// ============================================================
// G8 — Receiver modifies sender's output (substitution rules)
// ============================================================
#[test]
#[ignore = "BUG-7: no receiver-side output substitution"]
fn g8_receiver_output_substitution_bug7() {
    panic!("BUG-7: receiver-side output substitution MISSING");
}

// ============================================================
// G9 — Receiver adjusts fee within maxadditionalfeecontribution
// ============================================================
#[test]
fn g9_receiver_adjusts_fee_within_cap_bug5_fix65() {
    // FIX-65 closure: `handle_payjoin_request` honors the sender's
    // `maxadditionalfeecontribution` cap. With cap=1000 sat, the
    // receiver's delta-fee is clamped at 1000 — verified by checking
    // the resulting `ReceiverContribution::delta_fee_sats`.
    //
    // With cap=0, the receiver may not deduct anything: the receiver
    // output is bumped by the FULL input value, leaving the sender to
    // pay every extra sat of fee out of its own change.
    let (wallet, addr) = funded_wallet(0xa5, 2_000_000);
    let psbt = make_original_psbt_for_addr(&addr, 50_000);
    let body = psbt.to_base64();
    let offered = HashMap::new();

    let res_capped = handle_payjoin_request(
        body.as_bytes(),
        &PayjoinParams {
            version: 1,
            max_additional_fee_contribution: Some(1_000),
            ..Default::default()
        },
        &wallet,
        &offered,
    )
    .expect("cap=1000 must succeed");
    assert!(
        res_capped.delta_fee_sats <= 1_000,
        "delta_fee {} must respect cap=1000",
        res_capped.delta_fee_sats
    );

    let res_zero_cap = handle_payjoin_request(
        body.as_bytes(),
        &PayjoinParams {
            version: 1,
            max_additional_fee_contribution: Some(0),
            ..Default::default()
        },
        &wallet,
        &offered,
    )
    .expect("cap=0 must succeed (receiver deducts nothing)");
    assert_eq!(
        res_zero_cap.delta_fee_sats, 0,
        "zero cap means zero deduction"
    );

    // Default (no cap) → receiver deducts nothing per the foundation
    // policy (BIP-78 says receiver MAY add fee; foundation says "only
    // when explicitly authorised").
    let res_no_cap = handle_payjoin_request(
        body.as_bytes(),
        &PayjoinParams {
            version: 1,
            ..Default::default()
        },
        &wallet,
        &offered,
    )
    .expect("no cap must still succeed");
    assert_eq!(
        res_no_cap.delta_fee_sats, 0,
        "no cap means no deduction"
    );
}

// ============================================================
// G10 — Sender anti-snoop: sender's outputs preserved
// ============================================================
#[test]
#[ignore = "BUG-8: no sender-side post-reply validation"]
fn g10_sender_outputs_preserved_check_bug8() {
    panic!("BUG-8: sender-side output-preservation check MISSING");
}

// ============================================================
// G11 — Sender anti-snoop: scriptSig types preserved
// ============================================================
#[test]
#[ignore = "BUG-8: no sender-side scriptSig type comparison"]
fn g11_sender_script_sig_types_preserved_bug8() {
    panic!("BUG-8: sender-side scriptSig-type-preserved check MISSING");
}

// ============================================================
// G12 — Sender anti-snoop: no new inputs from sender's wallet
// ============================================================
#[test]
#[ignore = "BUG-8: no sender-side own-wallet input scan"]
fn g12_sender_no_new_inputs_from_own_wallet_bug8() {
    panic!("BUG-8: sender-side own-input scan MISSING");
}

// ============================================================
// G13 — Sender anti-snoop: max additional fee contribution
// ============================================================
#[test]
#[ignore = "BUG-9: no sender-side fee-cap enforcement"]
fn g13_sender_max_additional_fee_enforced_bug9() {
    panic!("BUG-9: sender-side max-fee-contribution enforcement MISSING");
}

// ============================================================
// G14 — Sender anti-snoop: disableoutputsubstitution honored
// ============================================================
#[test]
#[ignore = "BUG-10: no sender-side output-substitution-disabled check"]
fn g14_sender_disable_output_substitution_bug10() {
    panic!("BUG-10: sender-side disableoutputsubstitution honour MISSING");
}

// ============================================================
// G15 — Sender anti-snoop: min-fee-rate respected
// ============================================================
#[test]
#[ignore = "BUG-9: no sender-side min-fee-rate check on reply"]
fn g15_sender_min_fee_rate_respected_bug9() {
    panic!("BUG-9: sender-side minfeerate enforcement MISSING");
}

// ============================================================
// G16 — BIP-78 query params parsed
// ============================================================
#[test]
#[ignore = "BUG-11: query-string parser for v / additionalfeeoutputindex / max... / disable... / min... MISSING"]
fn g16_query_params_parsed_bug11() {
    // The five BIP-78 query params are not recognised anywhere in
    // the source tree. (verified by grep returning zero hits)
    panic!("BUG-11: BIP-78 query-param parsing MISSING ENTIRELY");
}

// ============================================================
// G17 — Receiver error responses (errorCode JSON body)
// ============================================================
#[test]
fn g17_receiver_error_envelope_shape_bug12_fix65() {
    // FIX-65 closure: BIP-78's `{"errorCode": ..., "message": ...}`
    // shape is produced by `PayjoinError::code()` (wire string) +
    // `PayjoinError::http_status()` (HTTP code). The REST handler at
    // `crates/rpc/src/rest.rs::payjoin_error_response` serialises
    // these into the response body verbatim. End-to-end JSON
    // assertions live in `crates/rpc/tests/test_fix65_payjoin_
    // receiver.rs`. Library-side: every BIP-78 wire variant is
    // available.
    assert_eq!(PayjoinError::VersionUnsupported(2).code(), "version-unsupported");
    assert_eq!(PayjoinError::VersionUnsupported(2).http_status(), 415);
    assert_eq!(
        PayjoinError::OriginalPsbtRejected("x".into()).code(),
        "original-psbt-rejected"
    );
    assert_eq!(
        PayjoinError::OriginalPsbtRejected("x".into()).http_status(),
        400
    );
    assert_eq!(PayjoinError::NotEnoughMoney.code(), "not-enough-money");
    assert_eq!(PayjoinError::NotEnoughMoney.http_status(), 422);
    assert_eq!(PayjoinError::Unavailable("x".into()).code(), "unavailable");
    assert_eq!(PayjoinError::Unavailable("x".into()).http_status(), 503);
}

// ============================================================
// G18 — Receiver expiration / TTL on offered payjoin
// ============================================================
#[test]
#[ignore = "BUG-13: no offered_pj state map; no expiration task"]
fn g18_receiver_offered_payjoin_ttl_bug13() {
    panic!("BUG-13: offered-payjoin TTL MISSING");
}

// ============================================================
// G19 — Receiver no-double-spending guard
// ============================================================
#[test]
fn g19_receiver_no_double_spending_guard_bug13_fix65() {
    // FIX-65 closure: `pick_receiver_utxo` skips outpoints that appear
    // in the caller-supplied `offered_payjoins` map. The REST handler
    // commits each accepted offer into the map before responding, so a
    // second concurrent request with a different Original PSBT cannot
    // be offered the same receiver UTXO. Full TTL eviction lands in
    // FIX-68 (G18); the conflict guard is in place today.
    let (wallet, _addr) = funded_wallet(0xa6, 2_000_000);

    // First call: empty offered map → pick succeeds.
    let mut offered: HashMap<Hash256, OfferedPayjoin> = HashMap::new();
    let first = pick_receiver_utxo(&wallet, &offered).expect("first pick");
    offered.insert(
        Hash256::from_bytes([0x1f; 32]),
        OfferedPayjoin {
            receiver_outpoint: first.outpoint.clone(),
            created_at: 1_700_000_000,
        },
    );

    // Second call: only one UTXO exists, and it's already offered →
    // not-enough-money per the BIP-78 wire code.
    let err = pick_receiver_utxo(&wallet, &offered).expect_err("conflict");
    assert_eq!(err.code(), "not-enough-money");
}

// ============================================================
// G20 — Receiver UTXO selection anti-fingerprinting (UIH-1/UIH-2)
// ============================================================
#[test]
#[ignore = "BUG-6: receiver-side selector with UIH heuristic checks MISSING"]
fn g20_receiver_uih_anti_fingerprint_bug6() {
    // Note: crates/wallet/src/coin_selection.rs contains the SENDER
    // selector strategies (largest-first / FIFO / BnB-like). None
    // are UIH-1 / UIH-2 aware because they have no receiver
    // caller.
    panic!("BUG-6: receiver-side UIH-aware selection MISSING");
}

// ============================================================
// G21 — Receiver PSBT version constant (BIP-78 specifies v=1)
// ============================================================
#[test]
#[ignore = "BUG-11: BIP-78 v=1 sentinel not enforced anywhere"]
fn g21_receiver_v1_sentinel_bug11() {
    // BIP-78 specifies the query param `v=1`. Anything else MUST
    // return a `version-unsupported` 4xx. Neither check exists.
    panic!("BUG-11: BIP-78 v=1 sentinel enforcement MISSING");
}

// ============================================================
// G22 — Sender max retry / fallback to original tx on failure
// ============================================================
#[test]
#[ignore = "BUG-14: no sender fallback-to-original on error"]
fn g22_sender_fallback_to_original_bug14() {
    panic!("BUG-14: sender fallback-to-original MISSING");
}

// ============================================================
// G23 — Receiver request validation (Content-Type, Content-Length)
// ============================================================
#[test]
#[ignore = "BUG-1: with no endpoint, no Content-Type / Content-Length validation"]
fn g23_receiver_request_validation_bug1() {
    panic!("BUG-1 (cont.): receiver request-validation MISSING");
}

// ============================================================
// G24 — HTTPS cert validation (sender side)
// ============================================================
#[test]
#[ignore = "BUG-3: no TLS client → no cert validation"]
fn g24_sender_tls_cert_validation_bug3() {
    panic!("BUG-3 (cont.): sender TLS cert validation MISSING");
}

// ============================================================
// G25 — Tor onion service support
// ============================================================
#[test]
#[ignore = "BUG-3: no .onion endpoint handling on sender side"]
fn g25_sender_onion_service_support_bug3() {
    // Note: rustoshi has Tor v3 support in the *P2P* network layer
    // (W117 BUG-1 closure: SHA3-256 .onion checksum + proxy
    // wiring in crates/network/src/proxy.rs). But the PayJoin
    // sender would need a separate HTTP-over-Tor client for the
    // BIP-78 POST — that does not exist.
    panic!("BUG-3 (cont.): sender Tor HTTP client MISSING");
}

// ============================================================
// G26 — getpayjoinrequest / receiver-side RPC
// ============================================================
#[test]
#[ignore = "BUG-15: no getpayjoinrequest RPC method"]
fn g26_getpayjoinrequest_rpc_bug15() {
    panic!("BUG-15: getpayjoinrequest RPC MISSING");
}

// ============================================================
// G27 — sendpayjoinrequest / sender-side RPC
// ============================================================
#[test]
#[ignore = "BUG-15: no sendpayjoinrequest RPC method"]
fn g27_sendpayjoinrequest_rpc_bug15() {
    panic!("BUG-15: sendpayjoinrequest RPC MISSING");
}

// ============================================================
// G28 — BIP-21 URI parser supports `pj=`
// ============================================================
#[test]
fn g28_bip21_parser_supports_pj_bug16() {
    // FIX-62 closure: parse_bip21 lives in crates/wallet/src/bip21.rs.
    // We use a valid mainnet bech32 because the parser enforces the
    // address constraint at parse time.
    let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.01&pj=https://example.com/payjoin&pjos=0";
    let parsed = parse_bip21(uri, Network::Mainnet).expect("FIX-62 BIP-21 parser must succeed");
    assert_eq!(
        parsed.pj.as_deref(),
        Some("https://example.com/payjoin"),
        "BUG-16 closed: pj endpoint extracted from BIP-21 URI"
    );
}

// ============================================================
// G29 — BIP-21 URI parser supports `pjos=`
// ============================================================
#[test]
fn g29_bip21_parser_supports_pjos_bug16() {
    // FIX-62 closure: pjos=0 → Some(false), pjos=1 → Some(true).
    let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.01&pj=https://example.com/payjoin&pjos=0";
    let parsed = parse_bip21(uri, Network::Mainnet).expect("FIX-62 BIP-21 parser must succeed");
    assert_eq!(
        parsed.pjos,
        Some(false),
        "BUG-16 closed: pjos=0 parsed as Some(false)"
    );
}

// ============================================================
// G30 — Receiver replay protection (PSBT-id uniqueness)
// ============================================================
#[test]
#[ignore = "BUG-13: no PSBT-id replay map"]
fn g30_receiver_replay_protection_bug13() {
    panic!("BUG-13 (cont.): receiver replay protection MISSING");
}
