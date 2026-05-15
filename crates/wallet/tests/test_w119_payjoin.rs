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
//!   G1  Receiver POST /payjoin endpoint              — MISSING — BUG-1
//!   G2  Sender HTTP client POSTs Original PSBT      — MISSING — BUG-2
//!   G3  TLS / HTTPS or .onion required by sender    — MISSING — BUG-3
//!   G4  Original PSBT v0 deserialization on receiver — MISSING — BUG-4
//!   G5  Receiver validates Original PSBT (no key leakage) — MISSING — BUG-4
//!   G6  Receiver identifies fee output (additionalfeeoutputindex) — MISSING — BUG-5
//!   G7  Receiver adds own inputs (anti-fingerprinting selection) — MISSING — BUG-6
//!   G8  Receiver modifies sender's output (substitution within rules) — MISSING — BUG-7
//!   G9  Receiver adjusts fee (within maxadditionalfeecontribution) — MISSING — BUG-5
//!   G10 Sender anti-snoop: sender's outputs preserved — MISSING — BUG-8
//!   G11 Sender anti-snoop: scriptSig types preserved — MISSING — BUG-8
//!   G12 Sender anti-snoop: no new inputs from sender's wallet — MISSING — BUG-8
//!   G13 Sender anti-snoop: max additional fee contribution respected — MISSING — BUG-9
//!   G14 Sender anti-snoop: disableoutputsubstitution honored — MISSING — BUG-10
//!   G15 Sender anti-snoop: min-fee-rate respected — MISSING — BUG-9
//!   G16 BIP-78 query params parsed                  — MISSING — BUG-11
//!   G17 Receiver error responses (errorCode JSON)  — MISSING — BUG-12
//!   G18 Receiver expiration / TTL on offered payjoin — MISSING — BUG-13
//!   G19 Receiver no-double-spending guard           — MISSING — BUG-13
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
//! Totals: 30 MISSING ENTIRELY / 0 PARTIAL / 0 PRESENT.
//!         16 bugs.

use rustoshi_crypto::address::Network;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_wallet::{parse_bip21, Psbt};

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
#[ignore = "BUG-1: no POST /payjoin route registered on the axum REST router"]
fn g1_receiver_post_payjoin_endpoint_bug1() {
    // BUG-1: Expected: an HTTP POST handler accepting an Original
    // PSBT body at a configurable PayJoin endpoint. Reality: no such
    // route exists in crates/rpc/src/rest.rs.
    panic!("BUG-1: Receiver HTTP endpoint MISSING ENTIRELY");
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
#[ignore = "BUG-4: no receiver path to feed Original PSBT into Psbt::deserialize"]
fn g4_receiver_deserializes_original_psbt_bug4() {
    // BUG-4: Underlying Psbt::deserialize exists (see test above),
    // but no caller passes the HTTP POST body in.
    panic!("BUG-4: receiver-side Original-PSBT deserialization path MISSING");
}

// ============================================================
// G5 — Receiver validates Original PSBT (no key info leakage)
// ============================================================
#[test]
#[ignore = "BUG-4: no receiver-side validation: no caller checks key leakage / finalisation"]
fn g5_receiver_validates_no_key_leakage_bug4() {
    // BUG-4 (cont): BIP-78 receiver MUST reject Original PSBTs that
    // expose unrelated wallet history (non_witness_utxo for segwit
    // inputs) or sender HD-key origin info. Primitives exist; no
    // caller.
    panic!("BUG-4: receiver-side Original-PSBT validation MISSING");
}

// ============================================================
// G6 — Receiver identifies fee output (additionalfeeoutputindex)
// ============================================================
#[test]
#[ignore = "BUG-5: no receiver code parses additionalfeeoutputindex query param"]
fn g6_receiver_identifies_fee_output_bug5() {
    panic!("BUG-5: additionalfeeoutputindex parsing + lookup MISSING");
}

// ============================================================
// G7 — Receiver adds own inputs (anti-fingerprinting selection)
// ============================================================
#[test]
#[ignore = "BUG-6: no receiver-side UIH-aware coin selection"]
fn g7_receiver_adds_own_inputs_bug6() {
    panic!("BUG-6: receiver-side input addition MISSING");
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
#[ignore = "BUG-5: no receiver fee-adjustment path"]
fn g9_receiver_adjusts_fee_within_cap_bug5() {
    panic!("BUG-5: receiver-side fee adjustment MISSING");
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
#[ignore = "BUG-12: no errorCode-shaped JSON body anywhere; RPC errors use jsonrpsee envelope"]
fn g17_receiver_error_envelope_shape_bug12() {
    // BIP-78 specifies the response body shape:
    //   `{"errorCode": "unavailable" | "not-enough-money" |
    //    "version-unsupported" | "original-psbt-rejected",
    //    "message": "..."}`
    // The RPC layer uses jsonrpsee's `{"jsonrpc":"2.0","error":
    //   {"code":N,"message":"..."}}`; the REST layer uses
    //   `RestError`. Neither matches BIP-78.
    panic!("BUG-12: BIP-78 errorCode response shape MISSING");
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
#[ignore = "BUG-13: no offered-UTXO reservation"]
fn g19_receiver_no_double_spending_guard_bug13() {
    panic!("BUG-13: offered-UTXO reservation MISSING");
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
