//! BIP-341 Taproot signature hash computation.
//!
//! As of W27-C the canonical implementation lives in
//! `rustoshi_crypto::taproot` so that the wallet (and any other
//! non-consensus crate) can call it without taking a wallet→consensus
//! dependency edge. This module re-exports those names for the
//! consensus crate's existing call sites.
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
//!
//! Validated 2026-04-28 against `bitcoin-core/src/test/data/bip341_wallet_vectors.json`
//! via the rustoshi-shim driver in `tools/bip341-vector-runner/`. All
//! 7/7 keyPathSpending vectors pass byte-perfect on `sigMsg` + `sigHash`.

pub use rustoshi_crypto::taproot::{
    build_sig_msg, compute_taproot_sighash, is_valid_taproot_hash_type, TaprootPrevouts,
    TaprootSighashError, TapscriptContext, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_DEFAULT,
    SIGHASH_NONE, SIGHASH_SINGLE,
};
