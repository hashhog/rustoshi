//! Rustoshi consensus crate
//!
//! Bitcoin consensus rules: script interpretation, block validation, chain selection,
//! and difficulty adjustment.
//!
//! # Modules
//!
//! - `script`: Bitcoin Script interpreter with support for P2PKH, P2SH, P2WPKH,
//!   P2WSH, and basic multisig. Includes proper handling of consensus vs policy
//!   flags.
//!
//! # Consensus vs Policy
//!
//! When validating blocks, only use consensus flags. Adding policy flags
//! (CLEANSTACK, LOW_S, etc.) to block validation will cause valid blocks
//! to be rejected, forking the node from the network.
//!
//! See `ScriptFlags::consensus_flags()` for the correct flags to use during
//! block validation.

pub mod script;

pub use script::{
    eval_script, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, verify_script,
    DummyChecker, Opcode, ScriptError, ScriptFlags, SigVersion, SignatureChecker, Stack,
};
