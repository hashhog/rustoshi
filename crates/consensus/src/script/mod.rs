//! Bitcoin Script interpreter and related types.
//!
//! This module provides a complete Bitcoin Script virtual machine capable of
//! evaluating P2PKH, P2SH, P2WPKH, P2WSH, and basic multisig scripts.
//!
//! # Overview
//!
//! Bitcoin Script is a stack-based language used to define spending conditions
//! for transaction outputs. Each output has a "locking script" (scriptPubKey)
//! that specifies what must be provided to spend it. Each input has an
//! "unlocking script" (scriptSig) and optionally witness data that satisfies
//! the locking conditions.
//!
//! # Script Types
//!
//! - **P2PKH** (Pay-to-Public-Key-Hash): The most common legacy script type.
//!   Requires a signature and public key that hashes to the specified hash.
//!
//! - **P2SH** (Pay-to-Script-Hash): Allows arbitrary scripts to be committed
//!   via their hash. The actual script is revealed at spending time.
//!
//! - **P2WPKH** (Pay-to-Witness-Public-Key-Hash): SegWit version of P2PKH.
//!   Moves signature data to the witness for lower fees.
//!
//! - **P2WSH** (Pay-to-Witness-Script-Hash): SegWit version of P2SH.
//!
//! - **P2TR** (Pay-to-Taproot): The newest script type using Schnorr signatures
//!   and Merkle trees of scripts.
//!
//! - **P2A** (Pay-to-Anchor): A special anyone-can-spend output type used for
//!   CPFP fee bumping in Lightning and similar protocols. The script is
//!   `OP_1 <0x4e73>` (4 bytes total). P2A outputs are exempt from dust thresholds.
//!
//! # Consensus vs Policy
//!
//! **CRITICAL**: Only 7 verification flags are consensus-enforced:
//! - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT
//!
//! Other flags (CLEANSTACK, LOW_S, MINIMALDATA, etc.) are policy-only and
//! must NOT be enforced during block validation.
//!
//! # Example
//!
//! ```
//! use rustoshi_consensus::script::{
//!     eval_script, verify_script, ScriptFlags, DummyChecker, SigVersion,
//!     is_p2a, is_p2pkh, is_p2sh, is_p2wpkh, is_p2wsh,
//! };
//!
//! // A simple script that pushes true
//! let script = [0x51]; // OP_1
//! let mut stack = Vec::new();
//! let flags = ScriptFlags::default();
//! let checker = DummyChecker;
//!
//! eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).unwrap();
//! assert_eq!(stack.len(), 1);
//! ```

pub mod interpreter;
pub mod num;
pub mod opcodes;

pub use interpreter::{
    eval_script, is_p2a, is_p2a_program, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh,
    is_push_only, parse_witness_program, verify_script, DummyChecker, ScriptError, ScriptFlags,
    SigVersion, SignatureChecker, Stack,
    LOCKTIME_THRESHOLD, MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG,
    MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE, MAX_STACK_SIZE,
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG,
};
pub use num::{
    bool_to_stack, decode_script_num, encode_script_num, stack_bool, ScriptNumError,
    DEFAULT_MAX_NUM_SIZE, LOCKTIME_MAX_NUM_SIZE,
};
pub use opcodes::Opcode;
