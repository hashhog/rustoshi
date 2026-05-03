//! Bitcoin Script interpreter.
//!
//! This module implements the Bitcoin Script virtual machine, capable of
//! evaluating P2PKH, P2SH, P2WPKH, P2WSH, and basic multisig scripts.
//!
//! # Script Evaluation Model
//!
//! Bitcoin Script is a stack-based language with two stacks:
//! - Main stack: primary data stack for operations
//! - Alt stack: auxiliary stack accessed via OP_TOALTSTACK/OP_FROMALTSTACK
//!
//! Scripts are evaluated left-to-right. Push operations add data to the stack,
//! and opcodes consume/produce stack elements.
//!
//! # Verification Flow
//!
//! 1. Evaluate scriptSig to populate the stack
//! 2. Copy the stack (for P2SH)
//! 3. Evaluate scriptPubKey with the resulting stack
//! 4. If P2SH: deserialize and evaluate the redeem script
//! 5. If SegWit: evaluate the witness program
//! 6. Check that the final stack has exactly one true element (CLEANSTACK)
//!
//! # Consensus vs Policy Flags
//!
//! **CRITICAL**: Only 9 flags are consensus-enforced during block validation:
//! - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, NULLFAIL, WITNESS_PUBKEYTYPE, TAPROOT
//!
//! Policy flags (CLEANSTACK, SIGPUSHONLY, LOW_S, etc.) are enforced for
//! mempool acceptance but NOT during block validation. Adding policy flags
//! to consensus causes valid blocks to be rejected!

use crate::script::num::{
    bool_to_stack, decode_script_num, encode_script_num, stack_bool, ScriptNumError,
    DEFAULT_MAX_NUM_SIZE, LOCKTIME_MAX_NUM_SIZE,
};
use crate::script::opcodes::Opcode;
use rustoshi_crypto::{hash160, sha256, sha256d};
use sha1::Sha1;
use sha2::Digest;
use thiserror::Error;

/// Maximum sizes and limits for script execution.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
pub const MAX_STACK_SIZE: usize = 1000;
pub const MAX_OPS_PER_SCRIPT: usize = 201;
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Threshold for interpreting locktime as timestamp vs block height.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Sequence number flags for relative locktime (BIP-68).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;

/// Script verification flags.
///
/// **IMPORTANT**: When validating blocks, only use consensus flags:
/// - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, NULLFAIL, WITNESS_PUBKEYTYPE, TAPROOT
///
/// Policy flags should only be used for mempool validation.
#[derive(Clone, Debug, Default)]
pub struct ScriptFlags {
    // ========== Consensus flags (enforced during block validation) ==========
    /// BIP-16: Pay-to-Script-Hash (consensus)
    pub verify_p2sh: bool,
    /// BIP-66: Strict DER signature encoding (consensus)
    pub verify_dersig: bool,
    /// BIP-65: OP_CHECKLOCKTIMEVERIFY (consensus)
    pub verify_checklocktimeverify: bool,
    /// BIP-68/112/113: OP_CHECKSEQUENCEVERIFY (consensus)
    pub verify_checksequenceverify: bool,
    /// BIP-141: Segregated Witness (consensus)
    pub verify_witness: bool,
    /// BIP-147: NULLDUMMY - dummy element must be empty (consensus, activated with SegWit)
    pub verify_nulldummy: bool,
    /// BIP-146: NULLFAIL - failed signature must be empty (consensus, activated with SegWit)
    pub verify_nullfail: bool,
    /// BIP-141: Witness pubkeys must be compressed (consensus, activated with SegWit)
    pub verify_witness_pubkeytype: bool,
    /// BIP-341/342: Taproot (consensus)
    pub verify_taproot: bool,

    // ========== Policy flags (NOT consensus) ==========
    /// Require strict DER + low-S + compressed pubkeys
    pub verify_strictenc: bool,
    /// BIP-62 rule 5: Low-S signatures
    pub verify_low_s: bool,
    /// scriptSig must be push-only
    pub verify_sigpushonly: bool,
    /// Require minimal push encodings
    pub verify_minimaldata: bool,
    /// Exactly one element remaining on stack
    pub verify_cleanstack: bool,
    /// Fail on upgradable NOPs
    pub verify_discourage_upgradable_nops: bool,
    /// Fail on upgradable witness versions
    pub verify_discourage_upgradable_witness_program: bool,
    /// OP_IF/NOTIF argument must be minimal
    pub verify_minimalif: bool,
    /// Fail on upgradable taproot versions
    pub verify_discourage_upgradable_taproot_version: bool,
    /// Fail on OP_SUCCESS opcodes
    pub verify_discourage_op_success: bool,
    /// Fail on upgradable pubkey types
    pub verify_discourage_upgradable_pubkeytype: bool,
    /// OP_CODESEPARATOR forbidden in witness v0
    pub verify_const_scriptcode: bool,
}

impl ScriptFlags {
    /// Create flags for consensus validation at a given block height.
    ///
    /// Only enables consensus-critical flags based on soft fork activation.
    /// Does NOT enable policy flags.
    pub fn consensus_flags(height: u32, testnet4: bool) -> Self {
        // Activation heights (mainnet / testnet4)
        let p2sh_height = if testnet4 { 1 } else { 173_805 };
        let bip66_height = if testnet4 { 1 } else { 363_725 };
        let bip65_height = if testnet4 { 1 } else { 388_381 };
        let csv_height = if testnet4 { 1 } else { 419_328 };
        let segwit_height = if testnet4 { 1 } else { 481_824 };
        let taproot_height = if testnet4 { 1 } else { 709_632 };

        ScriptFlags {
            verify_p2sh: height >= p2sh_height,
            verify_dersig: height >= bip66_height,
            verify_checklocktimeverify: height >= bip65_height,
            verify_checksequenceverify: height >= csv_height,
            verify_witness: height >= segwit_height,
            verify_nulldummy: height >= segwit_height, // BIP-147 activated with SegWit
            verify_nullfail: height >= segwit_height,  // BIP-146 activated with SegWit
            verify_witness_pubkeytype: height >= segwit_height, // BIP-141 activated with SegWit
            verify_taproot: height >= taproot_height,
            ..Default::default()
        }
    }

    /// Create flags for mempool/policy validation.
    ///
    /// Enables all consensus flags plus policy flags.
    pub fn standard_flags() -> Self {
        ScriptFlags {
            verify_p2sh: true,
            verify_dersig: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_witness: true,
            verify_nulldummy: true,
            verify_taproot: true,
            verify_strictenc: true,
            verify_low_s: true,
            verify_sigpushonly: true,
            verify_minimaldata: true,
            verify_cleanstack: true,
            verify_discourage_upgradable_nops: true,
            verify_discourage_upgradable_witness_program: true,
            verify_minimalif: true,
            verify_nullfail: true,
            verify_witness_pubkeytype: true,
            verify_discourage_upgradable_taproot_version: true,
            verify_discourage_op_success: true,
            verify_discourage_upgradable_pubkeytype: true,
            verify_const_scriptcode: true,
        }
    }

    /// Convert flags to a 32-bit integer for use as a cache key.
    ///
    /// Each flag is assigned a bit position. This allows the cache to
    /// distinguish between different verification contexts.
    pub fn to_bits(&self) -> u32 {
        let mut bits: u32 = 0;
        if self.verify_p2sh {
            bits |= 1 << 0;
        }
        if self.verify_dersig {
            bits |= 1 << 1;
        }
        if self.verify_checklocktimeverify {
            bits |= 1 << 2;
        }
        if self.verify_checksequenceverify {
            bits |= 1 << 3;
        }
        if self.verify_witness {
            bits |= 1 << 4;
        }
        if self.verify_nulldummy {
            bits |= 1 << 5;
        }
        if self.verify_nullfail {
            bits |= 1 << 6;
        }
        if self.verify_witness_pubkeytype {
            bits |= 1 << 7;
        }
        if self.verify_taproot {
            bits |= 1 << 8;
        }
        if self.verify_strictenc {
            bits |= 1 << 9;
        }
        if self.verify_low_s {
            bits |= 1 << 10;
        }
        if self.verify_sigpushonly {
            bits |= 1 << 11;
        }
        if self.verify_minimaldata {
            bits |= 1 << 12;
        }
        if self.verify_cleanstack {
            bits |= 1 << 13;
        }
        if self.verify_discourage_upgradable_nops {
            bits |= 1 << 14;
        }
        if self.verify_discourage_upgradable_witness_program {
            bits |= 1 << 15;
        }
        if self.verify_minimalif {
            bits |= 1 << 16;
        }
        if self.verify_discourage_upgradable_taproot_version {
            bits |= 1 << 17;
        }
        if self.verify_discourage_op_success {
            bits |= 1 << 18;
        }
        if self.verify_discourage_upgradable_pubkeytype {
            bits |= 1 << 19;
        }
        if self.verify_const_scriptcode {
            bits |= 1 << 20;
        }
        bits
    }
}

/// Errors that can occur during script evaluation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScriptError {
    #[error("script too large")]
    ScriptSize,
    #[error("stack overflow")]
    StackOverflow,
    #[error("stack underflow")]
    StackUnderflow,
    #[error("altstack underflow")]
    AltStackUnderflow,
    #[error("op count exceeded")]
    OpCount,
    #[error("disabled opcode")]
    DisabledOpcode,
    #[error("OP_RETURN encountered")]
    OpReturn,
    #[error("unbalanced conditional")]
    UnbalancedConditional,
    #[error("invalid opcode")]
    InvalidOpcode,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("push size exceeded")]
    PushSize,
    #[error("script number error: {0}")]
    NumberError(#[from] ScriptNumError),
    #[error("verify failed")]
    VerifyFailed,
    #[error("equalverify failed")]
    EqualVerifyFailed,
    #[error("checksigverify failed")]
    CheckSigVerifyFailed,
    #[error("checkmultisigverify failed")]
    CheckMultiSigVerifyFailed,
    #[error("numequalverify failed")]
    NumEqualVerifyFailed,
    #[error("invalid pubkey count")]
    PubkeyCount,
    #[error("invalid sig count")]
    SigCount,
    #[error("null dummy violation")]
    NullDummy,
    #[error("clean stack violation")]
    CleanStack,
    #[error("witness program mismatch")]
    WitnessProgramMismatch,
    #[error("invalid witness program length")]
    WitnessProgramLength,
    #[error("negative locktime")]
    NegativeLocktime,
    #[error("unsatisfied locktime")]
    UnsatisfiedLocktime,
    #[error("minimal if violation")]
    MinimalIf,
    #[error("null fail violation")]
    NullFail,
    #[error("witness unexpected")]
    WitnessUnexpected,
    #[error("witness malleated")]
    WitnessMalleated,
    #[error("invalid stack operation")]
    InvalidStackOperation,
    #[error("bad opcode")]
    BadOpcode,
    #[error("push only violation")]
    SigPushOnly,
    #[error("negative pick/roll index")]
    NegativePickRoll,
    #[error("pick/roll index out of bounds")]
    PickRollOutOfBounds,
    #[error("witness pubkey must be compressed")]
    WitnessPubkeyType,
    #[error("script evaluated to false")]
    EvalFalse,
    #[error("non-minimal push")]
    MinimalPush,
    #[error("non-strict DER signature")]
    SigDer,
    #[error("invalid public key type")]
    PubKeyType,
    #[error("invalid signature hash type")]
    SigHashType,
    #[error("discourage upgradable NOPs")]
    DiscourageUpgradableNops,
    #[error("signature high S value")]
    SigHighS,
    #[error("tapscript empty pubkey")]
    TapscriptEmptyPubkey,
    #[error("tapscript checkmultisig")]
    TapscriptCheckmultisig,
    #[error("tapscript validation weight exceeded")]
    TapscriptValidationWeight,
    #[error("witness program wrong length")]
    WitnessProgramWrongLength,
    #[error("taproot program mismatch")]
    WitnessProgramMismatch2,
}

/// Signature version for sighash computation.
///
/// Different script types use different signature hash algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigVersion {
    /// Legacy (pre-SegWit) scripts: P2PKH, bare scripts, P2SH
    Base,
    /// SegWit v0: P2WPKH, P2WSH (BIP-143)
    WitnessV0,
    /// Tapscript: P2TR script-path (BIP-342)
    Tapscript,
}

/// Signature checker trait — abstracts signature verification.
///
/// This trait allows the interpreter to be tested independently of
/// transaction context. Implementations provide signature verification
/// and locktime checking.
pub trait SignatureChecker {
    /// Verify a signature against a public key.
    ///
    /// # Arguments
    /// * `sig` - The full signature bytes INCLUDING the sighash type byte at the end
    /// * `pubkey` - The public key bytes
    /// * `script_code` - The subscript for sighash computation (after last OP_CODESEPARATOR)
    /// * `sig_version` - Which sighash algorithm to use
    ///
    /// # Returns
    /// True if the signature is valid for this transaction input.
    fn check_sig(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool;

    /// Check if the transaction's locktime satisfies the requirement.
    ///
    /// For OP_CHECKLOCKTIMEVERIFY (BIP-65).
    fn check_locktime(&self, locktime: i64) -> bool;

    /// Check if the transaction input's sequence satisfies the requirement.
    ///
    /// For OP_CHECKSEQUENCEVERIFY (BIP-112).
    fn check_sequence(&self, sequence: i64) -> bool;

    /// Verify a BIP-340 Schnorr signature for Taproot key-path spending.
    ///
    /// `sig` is 64 bytes (SIGHASH_DEFAULT) or 65 bytes (with explicit
    /// sighash type byte at offset 64). `xonly_pubkey` is the 32-byte
    /// x-only output key from the witness program.
    ///
    /// `annex` should be `Some(_)` if a witness annex is present; the
    /// bytes must include the leading 0x50.
    ///
    /// Default impl returns false so legacy `DummyChecker` and similar
    /// stubs continue to compile.
    fn check_schnorr_sig(
        &self,
        _sig: &[u8],
        _xonly_pubkey: &[u8; 32],
        _annex: Option<&[u8]>,
    ) -> bool {
        false
    }

    /// Verify a BIP-340 Schnorr signature for tapscript script-path
    /// (BIP-342 OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD).
    ///
    /// Same as `check_schnorr_sig` but uses BIP-341 sighash with
    /// ext_flag=1 — the digest commits to `tapleaf_hash` and the
    /// position of the most recent OP_CODESEPARATOR (0xFFFFFFFF if
    /// none has been encountered).
    fn check_schnorr_sig_tapscript(
        &self,
        _sig: &[u8],
        _xonly_pubkey: &[u8; 32],
        _tapleaf_hash: &[u8; 32],
        _codesep_pos: u32,
        _annex: Option<&[u8]>,
    ) -> bool {
        false
    }
}

/// Dummy signature checker that always returns false.
///
/// Useful for script parsing and testing without transaction context.
pub struct DummyChecker;

impl SignatureChecker for DummyChecker {
    fn check_sig(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
        false
    }

    fn check_locktime(&self, _: i64) -> bool {
        false
    }

    fn check_sequence(&self, _: i64) -> bool {
        false
    }
}

/// Get the subscript for signature hashing.
///
/// Returns the portion of the script starting after the last OP_CODESEPARATOR.
/// If no OP_CODESEPARATOR has been encountered (codesep_pos is the sentinel
/// value 0xFFFFFFFF), returns the full script.
///
/// # Arguments
/// * `full_script` - The complete script being executed
/// * `codesep_pos` - Position of last OP_CODESEPARATOR, or 0xFFFFFFFF if none
fn get_subscript(full_script: &[u8], codesep_pos: u32) -> &[u8] {
    if codesep_pos == 0xFFFFFFFF {
        // No OP_CODESEPARATOR encountered, use full script
        full_script
    } else {
        // Start after the OP_CODESEPARATOR
        let start = (codesep_pos as usize) + 1;
        if start < full_script.len() {
            &full_script[start..]
        } else {
            &[]
        }
    }
}

/// Check that a push opcode uses the minimal encoding for the given data.
///
/// Bitcoin Core's CheckMinimalPush: ensures the most compact push opcode is used.
fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    if data.is_empty() {
        // Empty data should use OP_0 (0x00)
        return opcode == 0x00;
    }
    if data.len() == 1 {
        if data[0] >= 1 && data[0] <= 16 {
            // Single byte 1-16 should use OP_1..OP_16
            return opcode == 0x51 + (data[0] - 1);
        }
        if data[0] == 0x81 {
            // 0x81 (-1) should use OP_1NEGATE
            return opcode == 0x4f;
        }
    }
    if data.len() <= 75 {
        // Should use direct push (opcode == length)
        return opcode as usize == data.len();
    }
    if data.len() <= 255 {
        // Should use OP_PUSHDATA1
        return opcode == 0x4c;
    }
    if data.len() <= 65535 {
        // Should use OP_PUSHDATA2
        return opcode == 0x4d;
    }
    true
}

/// Strict DER signature encoding check (BIP-66).
///
/// The signature includes the hashtype byte at the end.
/// Format: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s> <hashtype>
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Empty signature is always valid (it just fails verification)
    if sig.is_empty() {
        return true;
    }

    // Minimum: 30 06 02 01 R 02 01 S hashtype = 9 bytes
    // Maximum: 30 44 02 21 R(33) 02 21 S(33) hashtype = 73 bytes
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    // Compound tag
    if sig[0] != 0x30 {
        return false;
    }

    // Total length should be sig.len() - 3 (tag, length byte, hashtype)
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }

    // R value
    if sig[2] != 0x02 {
        return false;
    }
    let len_r = sig[3] as usize;
    if len_r == 0 {
        return false;
    }
    // 5 = 3 (header: tag, len, r_tag) + 1 (r_len) + at least 1 for s
    if 5 + len_r >= sig.len() {
        return false;
    }

    // S value
    let s_offset = 4 + len_r;
    if sig[s_offset] != 0x02 {
        return false;
    }
    let len_s = sig[s_offset + 1] as usize;
    if len_s == 0 {
        return false;
    }

    // Total: 4 (header) + len_r + 2 (s header) + len_s + 1 (hashtype)
    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    // R must not be negative (high bit of first byte)
    if sig[4] & 0x80 != 0 {
        return false;
    }
    // R must not have excessive zero-padding
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }

    // S must not be negative
    let s_data_offset = s_offset + 2;
    if sig[s_data_offset] & 0x80 != 0 {
        return false;
    }
    // S must not have excessive zero-padding
    if len_s > 1 && sig[s_data_offset] == 0x00 && sig[s_data_offset + 1] & 0x80 == 0 {
        return false;
    }

    true
}

/// Check if a signature has a low S value (BIP-62 rule 5).
///
/// The S value must be at most half the curve order.
fn is_low_s_signature(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return true;
    }
    if !is_valid_signature_encoding(sig) {
        return false;
    }
    // Extract S value
    let len_r = sig[3] as usize;
    let s_offset = 4 + len_r;
    let len_s = sig[s_offset + 1] as usize;
    let s_data = &sig[s_offset + 2..s_offset + 2 + len_s];

    // Half curve order for secp256k1:
    // 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    let half_order: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    ];

    // S must be <= half_order
    // Pad S to 32 bytes for comparison
    if s_data.len() > 32 {
        return false;
    }
    let mut s_padded = [0u8; 32];
    s_padded[32 - s_data.len()..].copy_from_slice(s_data);

    s_padded <= half_order
}

/// Check if a pubkey is compressed or uncompressed (but NOT hybrid).
///
/// Valid formats:
/// - Compressed: 33 bytes, starts with 0x02 or 0x03
/// - Uncompressed: 65 bytes, starts with 0x04
///
/// Rejects hybrid keys (0x06, 0x07).
fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    if pubkey.is_empty() {
        return false;
    }
    match pubkey[0] {
        0x02 | 0x03 => pubkey.len() == 33,
        0x04 => pubkey.len() == 65,
        _ => false,
    }
}

/// Check if a signature's hashtype byte is one of the defined types.
///
/// Valid hashtypes: SIGHASH_ALL(1), SIGHASH_NONE(2), SIGHASH_SINGLE(3),
/// optionally combined with SIGHASH_ANYONECANPAY(0x80).
fn is_defined_hashtype(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return true;
    }
    let hashtype = sig[sig.len() - 1] & 0x1f;
    (1..=3).contains(&hashtype)
}

/// Perform STRICTENC/DERSIG/LOW_S signature checks.
///
/// Called from CHECKSIG/CHECKMULTISIG before actual signature verification.
fn check_signature_encoding(sig: &[u8], flags: &ScriptFlags) -> Result<(), ScriptError> {
    if sig.is_empty() {
        return Ok(());
    }
    if (flags.verify_dersig || flags.verify_strictenc || flags.verify_low_s)
        && !is_valid_signature_encoding(sig)
    {
        return Err(ScriptError::SigDer);
    }
    if flags.verify_low_s && !is_low_s_signature(sig) {
        return Err(ScriptError::SigHighS);
    }
    if flags.verify_strictenc && !is_defined_hashtype(sig) {
        return Err(ScriptError::SigHashType);
    }
    Ok(())
}

/// Perform STRICTENC public key checks.
///
/// Called from CHECKSIG/CHECKMULTISIG when STRICTENC flag is set.
fn check_pubkey_encoding(pubkey: &[u8], flags: &ScriptFlags) -> Result<(), ScriptError> {
    if flags.verify_strictenc && !is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ScriptError::PubKeyType);
    }
    Ok(())
}

/// The stack type used by the script interpreter.
pub type Stack = Vec<Vec<u8>>;

/// Tapscript script-path execution context — BIP-342 OP_CHECKSIG and
/// OP_CHECKSIGADD need access to the tapleaf hash and witness annex
/// to compute the BIP-341 ext_flag=1 sighash. Only set when entering
/// a tapscript leaf via `eval_script_tapscript`.
pub struct TapscriptCtx<'a> {
    pub tapleaf_hash: &'a [u8; 32],
    pub annex: Option<&'a [u8]>,
}

/// Execution context for script evaluation.
struct ExecContext<'a> {
    stack: Stack,
    altstack: Stack,
    exec_stack: Vec<bool>, // IF/ELSE nesting state
    op_count: usize,
    flags: &'a ScriptFlags,
    checker: &'a dyn SignatureChecker,
    sig_version: SigVersion,
    codesep_pos: u32, // Position of last OP_CODESEPARATOR
    tapscript: Option<TapscriptCtx<'a>>, // Some(_) iff sig_version == Tapscript
    /// BIP-342 tapscript validation-weight budget. Mirrors Core's
    /// `ScriptExecutionData::m_validation_weight_left` (interpreter.cpp:362).
    /// Initialized at the tapscript leaf entry to
    /// `GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET (50)`,
    /// decremented by `VALIDATION_WEIGHT_PER_SIGOP_PASSED (50)` for every
    /// non-empty CHECKSIG / CHECKSIGVERIFY / CHECKSIGADD. Negative residue
    /// aborts with `TapscriptValidationWeight`.
    validation_weight_left: i64,
    /// Whether `validation_weight_left` is initialized. Defensive guard
    /// mirroring Core's `m_validation_weight_left_init`. False for
    /// legacy / SegWit-v0 contexts where the budget is not consulted.
    validation_weight_init: bool,
}

impl<'a> ExecContext<'a> {
    fn with_stack(
        stack: Stack,
        flags: &'a ScriptFlags,
        checker: &'a dyn SignatureChecker,
        sig_version: SigVersion,
    ) -> Self {
        ExecContext {
            stack,
            altstack: Vec::new(),
            exec_stack: Vec::new(),
            op_count: 0,
            flags,
            checker,
            sig_version,
            codesep_pos: 0xFFFFFFFF,
            tapscript: None,
            validation_weight_left: 0,
            validation_weight_init: false,
        }
    }

    fn with_stack_tapscript(
        stack: Stack,
        flags: &'a ScriptFlags,
        checker: &'a dyn SignatureChecker,
        tapscript: TapscriptCtx<'a>,
        validation_weight_left: i64,
    ) -> Self {
        ExecContext {
            stack,
            altstack: Vec::new(),
            exec_stack: Vec::new(),
            op_count: 0,
            flags,
            checker,
            sig_version: SigVersion::Tapscript,
            codesep_pos: 0xFFFFFFFF,
            tapscript: Some(tapscript),
            validation_weight_left,
            validation_weight_init: true,
        }
    }

    /// Decrement the BIP-342 validation-weight counter by 50 (one
    /// `VALIDATION_WEIGHT_PER_SIGOP_PASSED`). Returns
    /// `TapscriptValidationWeight` if the residue would go negative,
    /// matching Core's `m_validation_weight_left -= 50; if (... < 0) ...`
    /// at interpreter.cpp:362-365. Caller must only invoke this when
    /// processing a non-empty signature on the tapscript path; this is
    /// `interpreter.cpp`'s `success = !sig.empty()` gate.
    fn consume_validation_weight(&mut self) -> Result<(), ScriptError> {
        debug_assert!(self.validation_weight_init);
        self.validation_weight_left -= 50;
        if self.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
        Ok(())
    }

    /// Check if we're in an executing branch.
    fn executing(&self) -> bool {
        self.exec_stack.iter().all(|&b| b)
    }

    /// Check stack size limits.
    fn check_stack_size(&self) -> Result<(), ScriptError> {
        if self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackOverflow);
        }
        Ok(())
    }

    /// Pop one element from the stack.
    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    /// Peek at the top element without removing it.
    fn top(&self) -> Result<&Vec<u8>, ScriptError> {
        self.stack.last().ok_or(ScriptError::StackUnderflow)
    }

    /// Get a reference to an element at index from top (0 = top).
    fn at(&self, index: usize) -> Result<&Vec<u8>, ScriptError> {
        if index >= self.stack.len() {
            return Err(ScriptError::InvalidStackOperation);
        }
        Ok(&self.stack[self.stack.len() - 1 - index])
    }

    /// Push an element onto the stack.
    fn push(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        self.stack.push(data);
        self.check_stack_size()
    }
}

/// Evaluate a script with the given context.
///
/// This is the core script execution engine. It processes opcodes
/// sequentially, managing the execution stack for IF/ELSE/ENDIF blocks.
///
/// # Arguments
/// * `ctx` - Execution context (stack, flags, checker)
/// * `script` - The script bytecode to execute
/// * `full_script` - The complete script (for CODESEPARATOR handling)
///
/// # Returns
/// Ok(()) if execution completes without error.
fn eval_script_internal(
    ctx: &mut ExecContext,
    script: &[u8],
    full_script: &[u8],
) -> Result<(), ScriptError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let mut pc = 0usize;

    while pc < script.len() {
        let opcode_byte = script[pc];
        let opcode = Opcode::from_u8(opcode_byte);
        let executing = ctx.executing();
        pc += 1;

        // Check for always-illegal opcodes (even in non-executing branches)
        if opcode.is_always_illegal() {
            return Err(ScriptError::BadOpcode);
        }

        // Handle direct push opcodes (0x01-0x4b)
        if (0x01..=0x4b).contains(&opcode_byte) {
            let len = opcode_byte as usize;
            if pc + len > script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let data = script[pc..pc + len].to_vec();
            if executing {
                if ctx.flags.verify_minimaldata && !check_minimal_push(&data, opcode_byte) {
                    return Err(ScriptError::MinimalPush);
                }
                ctx.push(data)?;
            }
            pc += len;
            continue;
        }

        // Handle OP_PUSHDATA1/2/4
        if opcode == Opcode::OP_PUSHDATA1 {
            if pc >= script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let len = script[pc] as usize;
            pc += 1;
            if pc + len > script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let data = script[pc..pc + len].to_vec();
            // PUSH_SIZE check applies even in non-executing branches
            if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
            if executing {
                if ctx.flags.verify_minimaldata && !check_minimal_push(&data, 0x4c) {
                    return Err(ScriptError::MinimalPush);
                }
                ctx.push(data)?;
            }
            pc += len;
            continue;
        }

        if opcode == Opcode::OP_PUSHDATA2 {
            if pc + 2 > script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            if pc + len > script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let data = script[pc..pc + len].to_vec();
            if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
            if executing {
                if ctx.flags.verify_minimaldata && !check_minimal_push(&data, 0x4d) {
                    return Err(ScriptError::MinimalPush);
                }
                ctx.push(data)?;
            }
            pc += len;
            continue;
        }

        if opcode == Opcode::OP_PUSHDATA4 {
            if pc + 4 > script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let len = u32::from_le_bytes([script[pc], script[pc + 1], script[pc + 2], script[pc + 3]])
                as usize;
            pc += 4;
            if pc + len > script.len() {
                return Err(ScriptError::BadOpcode);
            }
            let data = script[pc..pc + len].to_vec();
            if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
            if executing {
                if ctx.flags.verify_minimaldata && !check_minimal_push(&data, 0x4e) {
                    return Err(ScriptError::MinimalPush);
                }
                ctx.push(data)?;
            }
            pc += len;
            continue;
        }

        // Count non-push opcodes
        if opcode_byte > 0x60 {
            // > OP_16
            ctx.op_count += 1;
            if ctx.op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::OpCount);
            }
        }

        // Check for disabled opcodes (even in non-executing branches)
        if opcode.is_disabled() {
            return Err(ScriptError::DisabledOpcode);
        }

        // Handle flow control in non-executing branches
        if !executing {
            match opcode {
                Opcode::OP_IF | Opcode::OP_NOTIF => {
                    ctx.exec_stack.push(false);
                }
                Opcode::OP_ELSE => {
                    if ctx.exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    // Only flip if we're in the active branch of the parent
                    let parent_executing = ctx.exec_stack[..ctx.exec_stack.len() - 1]
                        .iter()
                        .all(|&b| b);
                    if parent_executing {
                        let last = ctx.exec_stack.last_mut().unwrap();
                        *last = !*last;
                    }
                }
                Opcode::OP_ENDIF => {
                    if ctx.exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    ctx.exec_stack.pop();
                }
                // OP_RETURN in non-executing branch does NOT terminate
                _ => {}
            }
            continue;
        }

        // Execute opcodes (when in an executing branch)
        match opcode {
            // ==================== Push value ====================
            Opcode::OP_0 => {
                ctx.push(vec![])?;
            }
            Opcode::OP_1NEGATE => {
                ctx.push(encode_script_num(-1))?;
            }
            Opcode::OP_RESERVED => {
                return Err(ScriptError::BadOpcode);
            }
            Opcode::OP_1
            | Opcode::OP_2
            | Opcode::OP_3
            | Opcode::OP_4
            | Opcode::OP_5
            | Opcode::OP_6
            | Opcode::OP_7
            | Opcode::OP_8
            | Opcode::OP_9
            | Opcode::OP_10
            | Opcode::OP_11
            | Opcode::OP_12
            | Opcode::OP_13
            | Opcode::OP_14
            | Opcode::OP_15
            | Opcode::OP_16 => {
                let n = (opcode_byte - 0x50) as i64;
                ctx.push(encode_script_num(n))?;
            }

            // ==================== Flow control ====================
            Opcode::OP_NOP => {}
            Opcode::OP_VER => {
                return Err(ScriptError::BadOpcode);
            }
            Opcode::OP_IF => {
                let cond = {
                    if ctx.stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let val = ctx.pop()?;
                    // MINIMALIF: argument must be exactly empty or [0x01].
                    // - Tapscript: unconditional consensus rule
                    // - Witness v0: policy rule, enabled via verify_minimalif flag
                    let check_minimalif = ctx.sig_version == SigVersion::Tapscript
                        || (ctx.sig_version == SigVersion::WitnessV0
                            && ctx.flags.verify_minimalif);
                    if check_minimalif {
                        // Only [] (empty) and [0x01] are valid.
                        // [0x00], [0x02], multi-byte values all fail.
                        if val.len() > 1 || (val.len() == 1 && val[0] != 1) {
                            return Err(ScriptError::MinimalIf);
                        }
                    }
                    stack_bool(&val)
                };
                ctx.exec_stack.push(cond);
            }
            Opcode::OP_NOTIF => {
                let cond = {
                    if ctx.stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let val = ctx.pop()?;
                    // MINIMALIF: argument must be exactly empty or [0x01].
                    // - Tapscript: unconditional consensus rule
                    // - Witness v0: policy rule, enabled via verify_minimalif flag
                    let check_minimalif = ctx.sig_version == SigVersion::Tapscript
                        || (ctx.sig_version == SigVersion::WitnessV0
                            && ctx.flags.verify_minimalif);
                    if check_minimalif {
                        // Only [] (empty) and [0x01] are valid.
                        // [0x00], [0x02], multi-byte values all fail.
                        if val.len() > 1 || (val.len() == 1 && val[0] != 1) {
                            return Err(ScriptError::MinimalIf);
                        }
                    }
                    !stack_bool(&val)
                };
                ctx.exec_stack.push(cond);
            }
            Opcode::OP_ELSE => {
                if ctx.exec_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                let last = ctx.exec_stack.last_mut().unwrap();
                *last = !*last;
            }
            Opcode::OP_ENDIF => {
                if ctx.exec_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                ctx.exec_stack.pop();
            }
            Opcode::OP_VERIFY => {
                let val = ctx.pop()?;
                if !stack_bool(&val) {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            Opcode::OP_RETURN => {
                return Err(ScriptError::OpReturn);
            }

            // ==================== Stack operations ====================
            Opcode::OP_TOALTSTACK => {
                let val = ctx.pop()?;
                ctx.altstack.push(val);
                ctx.check_stack_size()?;
            }
            Opcode::OP_FROMALTSTACK => {
                let val = ctx.altstack.pop().ok_or(ScriptError::AltStackUnderflow)?;
                ctx.push(val)?;
            }
            Opcode::OP_2DROP => {
                ctx.pop()?;
                ctx.pop()?;
            }
            Opcode::OP_2DUP => {
                if ctx.stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let a = ctx.at(1)?.clone();
                let b = ctx.at(0)?.clone();
                ctx.push(a)?;
                ctx.push(b)?;
            }
            Opcode::OP_3DUP => {
                if ctx.stack.len() < 3 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let a = ctx.at(2)?.clone();
                let b = ctx.at(1)?.clone();
                let c = ctx.at(0)?.clone();
                ctx.push(a)?;
                ctx.push(b)?;
                ctx.push(c)?;
            }
            Opcode::OP_2OVER => {
                if ctx.stack.len() < 4 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let a = ctx.at(3)?.clone();
                let b = ctx.at(2)?.clone();
                ctx.push(a)?;
                ctx.push(b)?;
            }
            Opcode::OP_2ROT => {
                if ctx.stack.len() < 6 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let len = ctx.stack.len();
                let a = ctx.stack.remove(len - 6);
                let b = ctx.stack.remove(len - 6); // was at len-5, now at len-6
                ctx.stack.push(a);
                ctx.stack.push(b);
            }
            Opcode::OP_2SWAP => {
                if ctx.stack.len() < 4 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let len = ctx.stack.len();
                ctx.stack.swap(len - 4, len - 2);
                ctx.stack.swap(len - 3, len - 1);
            }
            Opcode::OP_IFDUP => {
                let val = ctx.top()?.clone();
                if stack_bool(&val) {
                    ctx.push(val)?;
                }
            }
            Opcode::OP_DEPTH => {
                let depth = ctx.stack.len() as i64;
                ctx.push(encode_script_num(depth))?;
            }
            Opcode::OP_DROP => {
                ctx.pop()?;
            }
            Opcode::OP_DUP => {
                let val = ctx.top()?.clone();
                ctx.push(val)?;
            }
            Opcode::OP_NIP => {
                if ctx.stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let len = ctx.stack.len();
                ctx.stack.remove(len - 2);
            }
            Opcode::OP_OVER => {
                if ctx.stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let val = ctx.at(1)?.clone();
                ctx.push(val)?;
            }
            Opcode::OP_PICK => {
                let n_data = ctx.pop()?;
                let n = decode_script_num(&n_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n < 0 {
                    return Err(ScriptError::NegativePickRoll);
                }
                let n = n as usize;
                if n >= ctx.stack.len() {
                    return Err(ScriptError::PickRollOutOfBounds);
                }
                let val = ctx.at(n)?.clone();
                ctx.push(val)?;
            }
            Opcode::OP_ROLL => {
                let n_data = ctx.pop()?;
                let n = decode_script_num(&n_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n < 0 {
                    return Err(ScriptError::NegativePickRoll);
                }
                let n = n as usize;
                if n >= ctx.stack.len() {
                    return Err(ScriptError::PickRollOutOfBounds);
                }
                let len = ctx.stack.len();
                let val = ctx.stack.remove(len - 1 - n);
                ctx.stack.push(val);
            }
            Opcode::OP_ROT => {
                if ctx.stack.len() < 3 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let len = ctx.stack.len();
                let val = ctx.stack.remove(len - 3);
                ctx.stack.push(val);
            }
            Opcode::OP_SWAP => {
                if ctx.stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let len = ctx.stack.len();
                ctx.stack.swap(len - 2, len - 1);
            }
            Opcode::OP_TUCK => {
                if ctx.stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let top = ctx.top()?.clone();
                let len = ctx.stack.len();
                ctx.stack.insert(len - 2, top);
                ctx.check_stack_size()?;
            }

            // ==================== Splice (only OP_SIZE is enabled) ====================
            Opcode::OP_SIZE => {
                let val = ctx.top()?;
                let size = val.len() as i64;
                ctx.push(encode_script_num(size))?;
            }

            // ==================== Bitwise logic ====================
            Opcode::OP_EQUAL => {
                let a = ctx.pop()?;
                let b = ctx.pop()?;
                ctx.push(bool_to_stack(a == b))?;
            }
            Opcode::OP_EQUALVERIFY => {
                let a = ctx.pop()?;
                let b = ctx.pop()?;
                if a != b {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }
            Opcode::OP_RESERVED1 | Opcode::OP_RESERVED2 => {
                return Err(ScriptError::BadOpcode);
            }

            // ==================== Arithmetic ====================
            Opcode::OP_1ADD => {
                let a = ctx.pop()?;
                let n = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(n + 1))?;
            }
            Opcode::OP_1SUB => {
                let a = ctx.pop()?;
                let n = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(n - 1))?;
            }
            Opcode::OP_NEGATE => {
                let a = ctx.pop()?;
                let n = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(-n))?;
            }
            Opcode::OP_ABS => {
                let a = ctx.pop()?;
                let n = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(n.abs()))?;
            }
            Opcode::OP_NOT => {
                let a = ctx.pop()?;
                let n = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(n == 0))?;
            }
            Opcode::OP_0NOTEQUAL => {
                let a = ctx.pop()?;
                let n = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(n != 0))?;
            }
            Opcode::OP_ADD => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(na + nb))?;
            }
            Opcode::OP_SUB => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(na - nb))?;
            }
            Opcode::OP_BOOLAND => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na != 0 && nb != 0))?;
            }
            Opcode::OP_BOOLOR => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na != 0 || nb != 0))?;
            }
            Opcode::OP_NUMEQUAL => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na == nb))?;
            }
            Opcode::OP_NUMEQUALVERIFY => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if na != nb {
                    return Err(ScriptError::NumEqualVerifyFailed);
                }
            }
            Opcode::OP_NUMNOTEQUAL => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na != nb))?;
            }
            Opcode::OP_LESSTHAN => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na < nb))?;
            }
            Opcode::OP_GREATERTHAN => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na > nb))?;
            }
            Opcode::OP_LESSTHANOREQUAL => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na <= nb))?;
            }
            Opcode::OP_GREATERTHANOREQUAL => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(na >= nb))?;
            }
            Opcode::OP_MIN => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(na.min(nb)))?;
            }
            Opcode::OP_MAX => {
                let b = ctx.pop()?;
                let a = ctx.pop()?;
                let na = decode_script_num(&a, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nb = decode_script_num(&b, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(encode_script_num(na.max(nb)))?;
            }
            Opcode::OP_WITHIN => {
                let max = ctx.pop()?;
                let min = ctx.pop()?;
                let x = ctx.pop()?;
                let nx = decode_script_num(&x, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nmin = decode_script_num(&min, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                let nmax = decode_script_num(&max, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                ctx.push(bool_to_stack(nmin <= nx && nx < nmax))?;
            }

            // ==================== Crypto ====================
            Opcode::OP_RIPEMD160 => {
                use ripemd::{Ripemd160, Digest as RipemdDigest};
                let data = ctx.pop()?;
                let mut hasher = Ripemd160::new();
                hasher.update(&data);
                ctx.push(hasher.finalize().to_vec())?;
            }
            Opcode::OP_SHA1 => {
                let data = ctx.pop()?;
                let mut hasher = Sha1::new();
                hasher.update(&data);
                ctx.push(hasher.finalize().to_vec())?;
            }
            Opcode::OP_SHA256 => {
                let data = ctx.pop()?;
                ctx.push(sha256(&data).to_vec())?;
            }
            Opcode::OP_HASH160 => {
                let data = ctx.pop()?;
                ctx.push(hash160(&data).0.to_vec())?;
            }
            Opcode::OP_HASH256 => {
                let data = ctx.pop()?;
                ctx.push(sha256d(&data).0.to_vec())?;
            }
            Opcode::OP_CODESEPARATOR => {
                // In witness v0, OP_CODESEPARATOR is forbidden if CONST_SCRIPTCODE is set
                if ctx.sig_version == SigVersion::WitnessV0 && ctx.flags.verify_const_scriptcode {
                    return Err(ScriptError::BadOpcode);
                }
                // Update the position for signature hashing
                // Store the position OF the OP_CODESEPARATOR opcode.
                // The subscript for sighash will start AFTER this position.
                ctx.codesep_pos = (pc - 1) as u32;
            }
            Opcode::OP_CHECKSIG => {
                // Pop pubkey first (top), then signature (deeper)
                // This order is CRITICAL - swapping breaks all signature verification
                let pubkey = ctx.pop()?;
                let sig = ctx.pop()?;

                if ctx.sig_version == SigVersion::Tapscript {
                    // BIP-342 tapscript rules.
                    // Validation-weight budget: decrement by 50 BEFORE pubkey
                    // inspection, but only when the signature is non-empty.
                    // Mirrors Core's `success = !sig.empty()` gate at
                    // interpreter.cpp:357-366. Per Core's comment, "Passing
                    // with an upgradable public key version is also counted",
                    // so the deduction fires before the 32-byte vs. unknown
                    // branching below.
                    if !sig.is_empty() {
                        ctx.consume_validation_weight()?;
                    }
                    if pubkey.is_empty() {
                        return Err(ScriptError::TapscriptEmptyPubkey);
                    }
                    if pubkey.len() == 32 {
                        // 32-byte pubkey: Schnorr signature check via BIP-341
                        // sighash with ext_flag=1 (script-path).
                        let success = if sig.is_empty() {
                            false
                        } else if let Some(ts) = ctx.tapscript.as_ref() {
                            let mut xonly = [0u8; 32];
                            xonly.copy_from_slice(&pubkey);
                            ctx.checker.check_schnorr_sig_tapscript(
                                &sig,
                                &xonly,
                                ts.tapleaf_hash,
                                ctx.codesep_pos,
                                ts.annex,
                            )
                        } else {
                            // Tapscript context unavailable — caller invoked
                            // eval_script (no tapscript ctx) on a tapscript leaf.
                            // Fail closed; this is an internal-API misuse.
                            false
                        };
                        if !success && !sig.is_empty() {
                            return Err(ScriptError::NullFail);
                        }
                        ctx.push(bool_to_stack(success))?;
                    } else {
                        // Unknown pubkey type in tapscript: succeeds unconditionally
                        // (soft-fork safe: future key types)
                        ctx.push(bool_to_stack(true))?;
                    }
                } else {
                    // Legacy / SegWit v0 CHECKSIG
                    // STRICTENC/DERSIG/LOW_S signature encoding checks
                    check_signature_encoding(&sig, ctx.flags)?;
                    // STRICTENC pubkey type check
                    check_pubkey_encoding(&pubkey, ctx.flags)?;

                    // BIP-141: Witness v0 requires compressed pubkeys
                    if ctx.flags.verify_witness_pubkeytype
                        && ctx.sig_version == SigVersion::WitnessV0
                        && !is_compressed_pubkey(&pubkey)
                    {
                        return Err(ScriptError::WitnessPubkeyType);
                    }

                    let success = if sig.is_empty() {
                        false
                    } else {
                        // Compute the subscript starting after the last OP_CODESEPARATOR
                        let subscript = get_subscript(full_script, ctx.codesep_pos);
                        // Pass full signature including sighash type byte
                        ctx.checker.check_sig(&sig, &pubkey, subscript, ctx.sig_version)
                    };

                    // NULLFAIL: failed sig must be empty
                    if !success && ctx.flags.verify_nullfail && !sig.is_empty() {
                        return Err(ScriptError::NullFail);
                    }

                    ctx.push(bool_to_stack(success))?;
                }
            }
            Opcode::OP_CHECKSIGVERIFY => {
                let pubkey = ctx.pop()?;
                let sig = ctx.pop()?;

                if ctx.sig_version == SigVersion::Tapscript {
                    // BIP-342 tapscript rules. See OP_CHECKSIG above for the
                    // budget-gate rationale; CHECKSIGVERIFY follows the same
                    // EvalChecksigTapscript path as CHECKSIG in Core.
                    if !sig.is_empty() {
                        ctx.consume_validation_weight()?;
                    }
                    if pubkey.is_empty() {
                        return Err(ScriptError::TapscriptEmptyPubkey);
                    }
                    if pubkey.len() == 32 {
                        let success = if sig.is_empty() {
                            false
                        } else if let Some(ts) = ctx.tapscript.as_ref() {
                            let mut xonly = [0u8; 32];
                            xonly.copy_from_slice(&pubkey);
                            ctx.checker.check_schnorr_sig_tapscript(
                                &sig,
                                &xonly,
                                ts.tapleaf_hash,
                                ctx.codesep_pos,
                                ts.annex,
                            )
                        } else {
                            false
                        };
                        if !success && !sig.is_empty() {
                            return Err(ScriptError::NullFail);
                        }
                        if !success {
                            return Err(ScriptError::CheckSigVerifyFailed);
                        }
                    }
                    // Unknown pubkey type: succeeds unconditionally
                } else {
                    // STRICTENC/DERSIG/LOW_S signature encoding checks
                    check_signature_encoding(&sig, ctx.flags)?;
                    // STRICTENC pubkey type check
                    check_pubkey_encoding(&pubkey, ctx.flags)?;

                    // BIP-141: Witness v0 requires compressed pubkeys
                    if ctx.flags.verify_witness_pubkeytype
                        && ctx.sig_version == SigVersion::WitnessV0
                        && !is_compressed_pubkey(&pubkey)
                    {
                        return Err(ScriptError::WitnessPubkeyType);
                    }

                    let success = if sig.is_empty() {
                        false
                    } else {
                        // Compute the subscript starting after the last OP_CODESEPARATOR
                        let subscript = get_subscript(full_script, ctx.codesep_pos);
                        // Pass full signature including sighash type byte
                        ctx.checker.check_sig(&sig, &pubkey, subscript, ctx.sig_version)
                    };

                    if !success && ctx.flags.verify_nullfail && !sig.is_empty() {
                        return Err(ScriptError::NullFail);
                    }

                    if !success {
                        return Err(ScriptError::CheckSigVerifyFailed);
                    }
                }
            }
            Opcode::OP_CHECKMULTISIG => {
                // BIP-342: CHECKMULTISIG disabled in tapscript
                if ctx.sig_version == SigVersion::Tapscript {
                    return Err(ScriptError::TapscriptCheckmultisig);
                }
                // Pop nKeys
                let n_keys_data = ctx.pop()?;
                let n_keys = decode_script_num(&n_keys_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n_keys < 0 || n_keys > MAX_PUBKEYS_PER_MULTISIG as i64 {
                    return Err(ScriptError::PubkeyCount);
                }
                let n_keys = n_keys as usize;

                // Add to op count (each key counts as an op)
                ctx.op_count += n_keys;
                if ctx.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }

                // Pop pubkeys
                let mut pubkeys = Vec::with_capacity(n_keys);
                for _ in 0..n_keys {
                    let pk = ctx.pop()?;
                    pubkeys.push(pk);
                }

                // Pop nSigs
                let n_sigs_data = ctx.pop()?;
                let n_sigs = decode_script_num(&n_sigs_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n_sigs < 0 || n_sigs > n_keys as i64 {
                    return Err(ScriptError::SigCount);
                }
                let n_sigs = n_sigs as usize;

                // Pop signatures
                let mut sigs = Vec::with_capacity(n_sigs);
                for _ in 0..n_sigs {
                    let s = ctx.pop()?;
                    sigs.push(s);
                }

                // Pop the dummy element (CHECKMULTISIG bug)
                let dummy = ctx.pop()?;
                if ctx.flags.verify_nulldummy && !dummy.is_empty() {
                    return Err(ScriptError::NullDummy);
                }

                // Verify signatures in order
                // Each signature must match a pubkey, and pubkeys are consumed left-to-right
                // Compute the subscript starting after the last OP_CODESEPARATOR
                let subscript = get_subscript(full_script, ctx.codesep_pos);
                let mut key_idx = 0;
                let mut sig_idx = 0;
                let mut success = true;
                while sig_idx < n_sigs {
                    let sig = &sigs[sig_idx];

                    // Check signature encoding (only when we actually try to use it)
                    check_signature_encoding(sig, ctx.flags)?;

                    if sig.is_empty() {
                        // Empty signature always fails
                        success = false;
                        break;
                    }

                    let mut found = false;

                    while key_idx < n_keys {
                        let pubkey = &pubkeys[key_idx];
                        key_idx += 1;

                        // Check pubkey encoding (only when we actually try to use it)
                        check_pubkey_encoding(pubkey, ctx.flags)?;

                        // BIP-141: Witness v0 requires compressed pubkeys
                        if ctx.flags.verify_witness_pubkeytype
                            && ctx.sig_version == SigVersion::WitnessV0
                            && !is_compressed_pubkey(pubkey)
                        {
                            return Err(ScriptError::WitnessPubkeyType);
                        }

                        // Pass full signature including sighash type byte
                        if ctx.checker.check_sig(sig, pubkey, subscript, ctx.sig_version) {
                            found = true;
                            break;
                        }

                        // Remaining sigs > remaining keys means failure
                        let sigs_remaining = n_sigs - sig_idx;
                        let keys_remaining = n_keys - key_idx;
                        if sigs_remaining > keys_remaining {
                            success = false;
                            break;
                        }
                    }

                    if !found {
                        success = false;
                        break;
                    }
                    sig_idx += 1;
                }

                // NULLFAIL: if failed, all sigs must be empty
                if !success && ctx.flags.verify_nullfail {
                    for sig in &sigs {
                        if !sig.is_empty() {
                            return Err(ScriptError::NullFail);
                        }
                    }
                }

                ctx.push(bool_to_stack(success))?;
            }
            Opcode::OP_CHECKMULTISIGVERIFY => {
                // BIP-342: CHECKMULTISIGVERIFY disabled in tapscript
                if ctx.sig_version == SigVersion::Tapscript {
                    return Err(ScriptError::TapscriptCheckmultisig);
                }
                // Same logic as OP_CHECKMULTISIG, but return error instead of pushing
                let n_keys_data = ctx.pop()?;
                let n_keys = decode_script_num(&n_keys_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n_keys < 0 || n_keys > MAX_PUBKEYS_PER_MULTISIG as i64 {
                    return Err(ScriptError::PubkeyCount);
                }
                let n_keys = n_keys as usize;

                ctx.op_count += n_keys;
                if ctx.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }

                let mut pubkeys = Vec::with_capacity(n_keys);
                for _ in 0..n_keys {
                    let pk = ctx.pop()?;
                    pubkeys.push(pk);
                }

                let n_sigs_data = ctx.pop()?;
                let n_sigs = decode_script_num(&n_sigs_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n_sigs < 0 || n_sigs > n_keys as i64 {
                    return Err(ScriptError::SigCount);
                }
                let n_sigs = n_sigs as usize;

                let mut sigs = Vec::with_capacity(n_sigs);
                for _ in 0..n_sigs {
                    let s = ctx.pop()?;
                    sigs.push(s);
                }

                let dummy = ctx.pop()?;
                if ctx.flags.verify_nulldummy && !dummy.is_empty() {
                    return Err(ScriptError::NullDummy);
                }

                // Compute the subscript starting after the last OP_CODESEPARATOR
                let subscript = get_subscript(full_script, ctx.codesep_pos);
                let mut key_idx = 0;
                let mut sig_idx = 0;
                let mut success = true;
                while sig_idx < n_sigs {
                    let sig = &sigs[sig_idx];

                    // Check signature encoding
                    check_signature_encoding(sig, ctx.flags)?;

                    if sig.is_empty() {
                        success = false;
                        break;
                    }

                    let mut found = false;

                    while key_idx < n_keys {
                        let pubkey = &pubkeys[key_idx];
                        key_idx += 1;

                        // Check pubkey encoding
                        check_pubkey_encoding(pubkey, ctx.flags)?;

                        // BIP-141: Witness v0 requires compressed pubkeys
                        if ctx.flags.verify_witness_pubkeytype
                            && ctx.sig_version == SigVersion::WitnessV0
                            && !is_compressed_pubkey(pubkey)
                        {
                            return Err(ScriptError::WitnessPubkeyType);
                        }

                        // Pass full signature including sighash type byte
                        if ctx.checker.check_sig(sig, pubkey, subscript, ctx.sig_version) {
                            found = true;
                            break;
                        }

                        // Remaining sigs > remaining keys means failure
                        let sigs_remaining = n_sigs - sig_idx;
                        let keys_remaining = n_keys - key_idx;
                        if sigs_remaining > keys_remaining {
                            success = false;
                            break;
                        }
                    }

                    if !found {
                        success = false;
                        break;
                    }
                    sig_idx += 1;
                }

                if !success && ctx.flags.verify_nullfail {
                    for sig in &sigs {
                        if !sig.is_empty() {
                            return Err(ScriptError::NullFail);
                        }
                    }
                }

                if !success {
                    return Err(ScriptError::CheckMultiSigVerifyFailed);
                }
            }

            // ==================== Locktime ====================
            Opcode::OP_NOP1 => {
                if ctx.flags.verify_discourage_upgradable_nops {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }
            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                if !ctx.flags.verify_checklocktimeverify {
                    // Pre-BIP-65: treat as NOP
                    if ctx.flags.verify_discourage_upgradable_nops {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                } else {
                    // BIP-65: verify locktime
                    let locktime_data = ctx.top()?;
                    let locktime = decode_script_num(locktime_data, ctx.flags.verify_minimaldata, LOCKTIME_MAX_NUM_SIZE)?;
                    if locktime < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if !ctx.checker.check_locktime(locktime) {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }
            }
            Opcode::OP_CHECKSEQUENCEVERIFY => {
                if !ctx.flags.verify_checksequenceverify {
                    // Pre-BIP-112: treat as NOP
                    if ctx.flags.verify_discourage_upgradable_nops {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                } else {
                    // BIP-112: verify sequence
                    let seq_data = ctx.top()?;
                    let sequence = decode_script_num(seq_data, ctx.flags.verify_minimaldata, LOCKTIME_MAX_NUM_SIZE)?;
                    if sequence < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    // If the disable flag is set, skip the check
                    if (sequence as u32 & SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0
                        && !ctx.checker.check_sequence(sequence)
                    {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }
            }
            Opcode::OP_NOP4
            | Opcode::OP_NOP5
            | Opcode::OP_NOP6
            | Opcode::OP_NOP7
            | Opcode::OP_NOP8
            | Opcode::OP_NOP9
            | Opcode::OP_NOP10 => {
                if ctx.flags.verify_discourage_upgradable_nops {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }

            // ==================== Tapscript ====================
            Opcode::OP_CHECKSIGADD => {
                // BIP-342: only valid in tapscript.
                if ctx.sig_version != SigVersion::Tapscript {
                    return Err(ScriptError::BadOpcode);
                }

                // Stack order (top-down): pubkey, num, sig.
                let pubkey = ctx.pop()?;
                let num_bytes = ctx.pop()?;
                let sig = ctx.pop()?;

                let num = decode_script_num(
                    &num_bytes,
                    ctx.flags.verify_minimaldata,
                    DEFAULT_MAX_NUM_SIZE,
                )?;

                // BIP-342 validation-weight budget: see OP_CHECKSIG above.
                // CHECKSIGADD goes through the same EvalChecksigTapscript
                // path in Core, which decrements the budget on every
                // !sig.empty() path before the pubkey type check.
                if !sig.is_empty() {
                    ctx.consume_validation_weight()?;
                }

                if pubkey.is_empty() {
                    return Err(ScriptError::TapscriptEmptyPubkey);
                }

                let success = if pubkey.len() == 32 {
                    if sig.is_empty() {
                        false
                    } else if let Some(ts) = ctx.tapscript.as_ref() {
                        let mut xonly = [0u8; 32];
                        xonly.copy_from_slice(&pubkey);
                        ctx.checker.check_schnorr_sig_tapscript(
                            &sig,
                            &xonly,
                            ts.tapleaf_hash,
                            ctx.codesep_pos,
                            ts.annex,
                        )
                    } else {
                        false
                    }
                } else {
                    // BIP-342: unknown pubkey type — succeed unconditionally
                    // (soft-fork safe). DISCOURAGE_UPGRADABLE_PUBKEYTYPE
                    // is a SegWit-v0 flag and does NOT apply to tapscript.
                    true
                };

                if !success && !sig.is_empty() {
                    return Err(ScriptError::NullFail);
                }

                let result = if success { num + 1 } else { num };
                ctx.push(encode_script_num(result))?;
            }

            // ==================== Invalid/Unknown ====================
            Opcode::OP_INVALIDOPCODE => {
                return Err(ScriptError::InvalidOpcode);
            }

            // Already handled above
            Opcode::OP_PUSHBYTES_1
            | Opcode::OP_PUSHBYTES_2
            | Opcode::OP_PUSHBYTES_3
            | Opcode::OP_PUSHBYTES_4
            | Opcode::OP_PUSHBYTES_5
            | Opcode::OP_PUSHBYTES_6
            | Opcode::OP_PUSHBYTES_7
            | Opcode::OP_PUSHBYTES_8
            | Opcode::OP_PUSHBYTES_9
            | Opcode::OP_PUSHBYTES_10
            | Opcode::OP_PUSHBYTES_11
            | Opcode::OP_PUSHBYTES_12
            | Opcode::OP_PUSHBYTES_13
            | Opcode::OP_PUSHBYTES_14
            | Opcode::OP_PUSHBYTES_15
            | Opcode::OP_PUSHBYTES_16
            | Opcode::OP_PUSHBYTES_17
            | Opcode::OP_PUSHBYTES_18
            | Opcode::OP_PUSHBYTES_19
            | Opcode::OP_PUSHBYTES_20
            | Opcode::OP_PUSHBYTES_21
            | Opcode::OP_PUSHBYTES_22
            | Opcode::OP_PUSHBYTES_23
            | Opcode::OP_PUSHBYTES_24
            | Opcode::OP_PUSHBYTES_25
            | Opcode::OP_PUSHBYTES_26
            | Opcode::OP_PUSHBYTES_27
            | Opcode::OP_PUSHBYTES_28
            | Opcode::OP_PUSHBYTES_29
            | Opcode::OP_PUSHBYTES_30
            | Opcode::OP_PUSHBYTES_31
            | Opcode::OP_PUSHBYTES_32
            | Opcode::OP_PUSHBYTES_33
            | Opcode::OP_PUSHBYTES_34
            | Opcode::OP_PUSHBYTES_35
            | Opcode::OP_PUSHBYTES_36
            | Opcode::OP_PUSHBYTES_37
            | Opcode::OP_PUSHBYTES_38
            | Opcode::OP_PUSHBYTES_39
            | Opcode::OP_PUSHBYTES_40
            | Opcode::OP_PUSHBYTES_41
            | Opcode::OP_PUSHBYTES_42
            | Opcode::OP_PUSHBYTES_43
            | Opcode::OP_PUSHBYTES_44
            | Opcode::OP_PUSHBYTES_45
            | Opcode::OP_PUSHBYTES_46
            | Opcode::OP_PUSHBYTES_47
            | Opcode::OP_PUSHBYTES_48
            | Opcode::OP_PUSHBYTES_49
            | Opcode::OP_PUSHBYTES_50
            | Opcode::OP_PUSHBYTES_51
            | Opcode::OP_PUSHBYTES_52
            | Opcode::OP_PUSHBYTES_53
            | Opcode::OP_PUSHBYTES_54
            | Opcode::OP_PUSHBYTES_55
            | Opcode::OP_PUSHBYTES_56
            | Opcode::OP_PUSHBYTES_57
            | Opcode::OP_PUSHBYTES_58
            | Opcode::OP_PUSHBYTES_59
            | Opcode::OP_PUSHBYTES_60
            | Opcode::OP_PUSHBYTES_61
            | Opcode::OP_PUSHBYTES_62
            | Opcode::OP_PUSHBYTES_63
            | Opcode::OP_PUSHBYTES_64
            | Opcode::OP_PUSHBYTES_65
            | Opcode::OP_PUSHBYTES_66
            | Opcode::OP_PUSHBYTES_67
            | Opcode::OP_PUSHBYTES_68
            | Opcode::OP_PUSHBYTES_69
            | Opcode::OP_PUSHBYTES_70
            | Opcode::OP_PUSHBYTES_71
            | Opcode::OP_PUSHBYTES_72
            | Opcode::OP_PUSHBYTES_73
            | Opcode::OP_PUSHBYTES_74
            | Opcode::OP_PUSHBYTES_75
            | Opcode::OP_PUSHDATA1
            | Opcode::OP_PUSHDATA2
            | Opcode::OP_PUSHDATA4 => {
                // These are handled at the start of the loop
                unreachable!()
            }

            // Disabled opcodes
            Opcode::OP_CAT
            | Opcode::OP_SUBSTR
            | Opcode::OP_LEFT
            | Opcode::OP_RIGHT
            | Opcode::OP_INVERT
            | Opcode::OP_AND
            | Opcode::OP_OR
            | Opcode::OP_XOR
            | Opcode::OP_2MUL
            | Opcode::OP_2DIV
            | Opcode::OP_MUL
            | Opcode::OP_DIV
            | Opcode::OP_MOD
            | Opcode::OP_LSHIFT
            | Opcode::OP_RSHIFT => {
                // These are caught by is_disabled() above
                unreachable!()
            }

            // Always illegal
            Opcode::OP_VERIF | Opcode::OP_VERNOTIF => {
                // Caught above
                unreachable!()
            }
        }
    }

    if !ctx.exec_stack.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }

    Ok(())
}

/// Evaluate a script with the given stack, flags, and signature checker.
///
/// This is a public wrapper around the internal evaluation function.
pub fn eval_script(
    stack: &mut Stack,
    script: &[u8],
    flags: &ScriptFlags,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
) -> Result<(), ScriptError> {
    let mut ctx = ExecContext::with_stack(
        std::mem::take(stack),
        flags,
        checker,
        sig_version,
    );

    let result = eval_script_internal(&mut ctx, script, script);

    *stack = ctx.stack;
    result
}

/// Evaluate a tapscript leaf (BIP-342) — same as `eval_script` but with
/// the tapleaf hash + annex needed for ext_flag=1 sighash computation
/// inside OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD.
///
/// `validation_weight_left` is the BIP-342 sigop budget seeded at the
/// tapscript entry point — Core's
/// `m_validation_weight_left = ::GetSerializeSize(witness.stack) +
/// VALIDATION_WEIGHT_OFFSET (50)` (interpreter.cpp:1981). The script
/// will abort with `TapscriptValidationWeight` if more non-empty
/// CHECKSIG / CHECKSIGADD operations are executed than the budget
/// can pay for at 50 weight units each.
pub fn eval_script_tapscript(
    stack: &mut Stack,
    script: &[u8],
    flags: &ScriptFlags,
    checker: &dyn SignatureChecker,
    tapscript: TapscriptCtx<'_>,
    validation_weight_left: i64,
) -> Result<(), ScriptError> {
    let mut ctx = ExecContext::with_stack_tapscript(
        std::mem::take(stack),
        flags,
        checker,
        tapscript,
        validation_weight_left,
    );

    let result = eval_script_internal(&mut ctx, script, script);

    *stack = ctx.stack;
    result
}

/// Compute the byte length of a Bitcoin compact-size encoding for `n`.
/// Mirrors Core's `GetSizeOfCompactSize` (serialize.h):
/// `< 0xfd` → 1, `<= 0xffff` → 3, `<= 0xffffffff` → 5, else 9.
pub fn compact_size_len(n: u64) -> u64 {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffffffff {
        5
    } else {
        9
    }
}

/// Compute the on-the-wire serialized size of a witness stack the way
/// Core's `::GetSerializeSize(witness.stack)` does it: a compact-size
/// item count followed by, for each item, its compact-size length
/// prefix and the bytes themselves. Used to seed the BIP-342 tapscript
/// validation-weight budget at the leaf entry point.
pub fn get_serialize_size_of_witness_stack(items: &[Vec<u8>]) -> u64 {
    let mut n = compact_size_len(items.len() as u64);
    for it in items {
        n += compact_size_len(it.len() as u64) + it.len() as u64;
    }
    n
}

/// Check if a script is P2SH: OP_HASH160 <20 bytes> OP_EQUAL
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

/// Check if a script is P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
pub fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76  // OP_DUP
        && script[1] == 0xa9  // OP_HASH160
        && script[2] == 0x14  // Push 20 bytes
        && script[23] == 0x88 // OP_EQUALVERIFY
        && script[24] == 0xac // OP_CHECKSIG
}

/// Check if a script is P2WPKH: OP_0 <20 bytes>
pub fn is_p2wpkh(script: &[u8]) -> bool {
    script.len() == 22 && script[0] == 0x00 && script[1] == 0x14
}

/// Check if a script is P2WSH: OP_0 <32 bytes>
pub fn is_p2wsh(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x00 && script[1] == 0x20
}

/// Check if a script is P2TR: OP_1 <32 bytes>
pub fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// Check if a script is Pay-to-Anchor (P2A): OP_1 <0x4e73>
///
/// P2A is a special anyone-can-spend output used for CPFP fee bumping
/// in Lightning and similar protocols. The script is exactly 4 bytes:
/// - OP_1 (0x51) - witness version 1
/// - PUSHBYTES_2 (0x02) - push 2 bytes
/// - 0x4e 0x73 - the anchor program ("Ns" in ASCII)
///
/// P2A outputs are exempt from dust thresholds and require an empty witness.
pub fn is_p2a(script: &[u8]) -> bool {
    script.len() == 4 && script[0] == 0x51 && script[1] == 0x02 && script[2] == 0x4e && script[3] == 0x73
}

/// Check if a witness program is Pay-to-Anchor (P2A).
///
/// Given a parsed witness version and program, checks if it matches
/// the P2A format (version 1, 2-byte program "4e73").
pub fn is_p2a_program(version: u8, program: &[u8]) -> bool {
    version == 1 && program.len() == 2 && program[0] == 0x4e && program[1] == 0x73
}

/// Parse a witness program from a scriptPubKey.
///
/// Format: OP_n <2-to-40 bytes>
/// where OP_n is OP_0 (0x00) or OP_1..OP_16 (0x51..0x60)
///
/// Returns (version, program) if valid, None otherwise.
pub fn parse_witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }

    let version_opcode = script[0];
    let version = if version_opcode == 0x00 {
        0
    } else if (0x51..=0x60).contains(&version_opcode) {
        version_opcode - 0x50
    } else {
        return None;
    };

    // Next byte is the push length
    let program_len = script[1] as usize;

    // Must be a direct push (not PUSHDATA1/2/4)
    if script[1] < 0x02 || script[1] > 0x28 {
        // 2-40 bytes
        return None;
    }

    // Script must be exactly version + push_len + program
    if script.len() != 2 + program_len {
        return None;
    }

    Some((version, &script[2..]))
}

/// Check if a public key is compressed (33 bytes, starting with 0x02 or 0x03).
///
/// Compressed public keys encode only the x-coordinate plus a parity bit.
/// BIP-141 requires all public keys in witness v0 programs to be compressed.
fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Check if scriptSig is push-only (required for P2SH and SegWit).
pub fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];

        if opcode > 0x60 {
            // > OP_16: not a push
            return false;
        }

        // Calculate how many bytes to skip
        if (0x01..=0x4b).contains(&opcode) {
            pc += 1 + opcode as usize;
        } else if opcode == 0x4c {
            // OP_PUSHDATA1
            if pc + 1 >= script.len() {
                return false;
            }
            let len = script[pc + 1] as usize;
            pc += 2 + len;
        } else if opcode == 0x4d {
            // OP_PUSHDATA2
            if pc + 2 >= script.len() {
                return false;
            }
            let len = u16::from_le_bytes([script[pc + 1], script[pc + 2]]) as usize;
            pc += 3 + len;
        } else if opcode == 0x4e {
            // OP_PUSHDATA4
            if pc + 4 >= script.len() {
                return false;
            }
            let len = u32::from_le_bytes([
                script[pc + 1],
                script[pc + 2],
                script[pc + 3],
                script[pc + 4],
            ]) as usize;
            pc += 5 + len;
        } else {
            // OP_0 or OP_1NEGATE or OP_1..OP_16
            pc += 1;
        }
    }
    true
}

/// High-level script verification: runs scriptSig, then scriptPubKey,
/// then P2SH redeem script, then witness program as needed.
///
/// # Arguments
/// * `script_sig` - The unlocking script (from transaction input)
/// * `script_pubkey` - The locking script (from previous output)
/// * `witness` - The witness data (for SegWit inputs)
/// * `flags` - Verification flags
/// * `checker` - Signature verification implementation
pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: &ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    // Check scriptSig is push-only if required
    if flags.verify_sigpushonly && !is_push_only(script_sig) {
        return Err(ScriptError::SigPushOnly);
    }

    // 1. Evaluate scriptSig to populate the stack
    let mut stack = Stack::new();
    eval_script(&mut stack, script_sig, flags, checker, SigVersion::Base)?;
    let stack_copy = stack.clone(); // Save for P2SH

    // 2. Evaluate scriptPubKey with the resulting stack
    eval_script(&mut stack, script_pubkey, flags, checker, SigVersion::Base)?;

    // 3. Check that the stack is non-empty and top is true
    if stack.is_empty() || !stack_bool(stack.last().unwrap()) {
        return Err(ScriptError::VerifyFailed);
    }

    // 4. P2SH evaluation (BIP-16)
    if flags.verify_p2sh && is_p2sh(script_pubkey) {
        // scriptSig must be push-only for P2SH
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushOnly);
        }

        // The serialized redeem script is the last element pushed by scriptSig
        if stack_copy.is_empty() {
            return Err(ScriptError::VerifyFailed);
        }
        let redeem_script = &stack_copy[stack_copy.len() - 1];

        // Start with the remaining stack (everything except the redeem script)
        let mut p2sh_stack: Stack = stack_copy[..stack_copy.len() - 1].to_vec();

        // Check for P2SH-wrapped SegWit
        if flags.verify_witness {
            if let Some((version, program)) = parse_witness_program(redeem_script) {
                verify_witness_program(
                    witness,
                    version,
                    program,
                    flags,
                    checker,
                )?;

                // For P2SH-SegWit, the p2sh_stack should be empty after redeem script
                // The witness provides the actual execution
                if !p2sh_stack.is_empty() {
                    return Err(ScriptError::WitnessMalleated);
                }

                // After successful witness execution, we're done
                return Ok(());
            }
        }

        // Regular P2SH: evaluate the redeem script
        eval_script(&mut p2sh_stack, redeem_script, flags, checker, SigVersion::Base)?;

        if p2sh_stack.is_empty() || !stack_bool(p2sh_stack.last().unwrap()) {
            return Err(ScriptError::VerifyFailed);
        }

        // Clean stack check for P2SH
        if flags.verify_cleanstack && p2sh_stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }

        // P2SH successful and no witness expected
        if flags.verify_witness && !witness.is_empty() {
            return Err(ScriptError::WitnessUnexpected);
        }

        return Ok(());
    }

    // 5. Native SegWit (BIP-141)
    if flags.verify_witness {
        if let Some((version, program)) = parse_witness_program(script_pubkey) {
            // For native SegWit, scriptSig must be empty
            if !script_sig.is_empty() {
                return Err(ScriptError::WitnessMalleated);
            }

            verify_witness_program(witness, version, program, flags, checker)?;

            // Clean stack already handled by witness verification
            return Ok(());
        }
    }

    // 6. Clean stack check (non-SegWit, non-P2SH)
    if flags.verify_cleanstack && stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }

    // 7. No witness should be present for non-SegWit scripts
    if flags.verify_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }

    Ok(())
}

/// Verify a witness program.
fn verify_witness_program(
    witness: &[Vec<u8>],
    version: u8,
    program: &[u8],
    flags: &ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    match version {
        0 => {
            // SegWit v0
            if program.len() == 20 {
                // P2WPKH
                if witness.len() != 2 {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // Construct the implicit P2PKH script
                let mut script = Vec::with_capacity(25);
                script.push(0x76); // OP_DUP
                script.push(0xa9); // OP_HASH160
                script.push(0x14); // Push 20 bytes
                script.extend_from_slice(program);
                script.push(0x88); // OP_EQUALVERIFY
                script.push(0xac); // OP_CHECKSIG

                // Stack: [sig, pubkey] - but witness is bottom-to-top on wire
                // We need to reverse for execution
                let mut stack: Stack = witness.to_vec();

                eval_script(&mut stack, &script, flags, checker, SigVersion::WitnessV0)?;

                // Witness scripts implicitly require cleanstack: exactly one element
                // This check comes FIRST per Bitcoin Core's ExecuteWitnessScript
                if stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
                }

                // The single remaining element must be true
                if !stack_bool(&stack[0]) {
                    return Err(ScriptError::EvalFalse);
                }

                Ok(())
            } else if program.len() == 32 {
                // P2WSH
                if witness.is_empty() {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // Last witness item is the witness script
                let witness_script = &witness[witness.len() - 1];

                // Verify SHA256(witness_script) == program
                let script_hash = sha256(witness_script);
                if script_hash != program {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // Stack is everything except the witness script
                // Witness items are bottom-to-top: index 0 = bottom, last = top
                let mut stack: Stack = witness[..witness.len() - 1].to_vec();

                eval_script(&mut stack, witness_script, flags, checker, SigVersion::WitnessV0)?;

                // Witness scripts implicitly require cleanstack: exactly one element
                // This check comes FIRST per Bitcoin Core's ExecuteWitnessScript
                if stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
                }

                // The single remaining element must be true
                if !stack_bool(&stack[0]) {
                    return Err(ScriptError::EvalFalse);
                }

                Ok(())
            } else {
                Err(ScriptError::WitnessProgramLength)
            }
        }
        1 => {
            // SegWit v1 (Taproot / BIP-341)
            if flags.verify_taproot && program.len() == 32 {
                if witness.is_empty() {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // Check for annex (last witness item starting with 0x50)
                let has_annex = witness.len() >= 2 && !witness.last().unwrap().is_empty()
                    && witness.last().unwrap()[0] == 0x50;
                let effective_witness = if has_annex {
                    &witness[..witness.len() - 1]
                } else {
                    witness
                };

                if effective_witness.len() == 1 {
                    // Key-path spending: single witness element is the signature.
                    // BIP-341: signature is verified against the witness program
                    // (the tweaked output key Q) directly — no on-the-fly tweak
                    // computation needed by the verifier.
                    let sig = &effective_witness[0];
                    let mut xonly_pubkey = [0u8; 32];
                    xonly_pubkey.copy_from_slice(program);

                    // Annex (if present) is the *original* last witness element,
                    // including the leading 0x50 prefix byte.
                    let annex = if has_annex {
                        Some(witness.last().unwrap().as_slice())
                    } else {
                        None
                    };

                    if checker.check_schnorr_sig(sig, &xonly_pubkey, annex) {
                        Ok(())
                    } else {
                        Err(ScriptError::EvalFalse)
                    }
                } else if effective_witness.len() >= 2 {
                    // Script-path spending
                    // Last element = control block, second-to-last = script
                    let control_block = &effective_witness[effective_witness.len() - 1];
                    let tap_script = &effective_witness[effective_witness.len() - 2];

                    if control_block.is_empty() {
                        return Err(ScriptError::WitnessProgramMismatch);
                    }

                    let leaf_version = control_block[0] & 0xfe;

                    // Control block: 1 byte version+parity, 32 bytes internal key,
                    // then 0..N 32-byte merkle path nodes
                    if control_block.len() < 33 || (control_block.len() - 33) % 32 != 0 {
                        return Err(ScriptError::WitnessProgramMismatch);
                    }

                    let internal_key = &control_block[1..33];

                    // Compute tapleaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)
                    let tapleaf_hash = {
                        use sha2::{Sha256, Digest};
                        let tag = Sha256::digest(b"TapLeaf");
                        let mut data = Vec::new();
                        data.push(leaf_version);
                        // compact_size encoding of script length
                        let slen = tap_script.len();
                        if slen < 0xfd {
                            data.push(slen as u8);
                        } else if slen <= 0xffff {
                            data.push(0xfd);
                            data.push((slen & 0xff) as u8);
                            data.push(((slen >> 8) & 0xff) as u8);
                        } else {
                            data.push(0xfe);
                            data.push((slen & 0xff) as u8);
                            data.push(((slen >> 8) & 0xff) as u8);
                            data.push(((slen >> 16) & 0xff) as u8);
                            data.push(((slen >> 24) & 0xff) as u8);
                        }
                        data.extend_from_slice(tap_script);
                        let mut hasher = Sha256::new();
                        hasher.update(tag);
                        hasher.update(tag);
                        hasher.update(&data);
                        let result: [u8; 32] = hasher.finalize().into();
                        result
                    };

                    // Compute merkle root from tapleaf hash and merkle path
                    let merkle_path_len = (control_block.len() - 33) / 32;
                    let mut k = tapleaf_hash;
                    for j in 0..merkle_path_len {
                        let node = &control_block[33 + j * 32..33 + (j + 1) * 32];
                        use sha2::{Sha256, Digest};
                        let tag = Sha256::digest(b"TapBranch");
                        let mut hasher = Sha256::new();
                        hasher.update(tag);
                        hasher.update(tag);
                        // Sort: lexicographically smaller one first
                        if k < *<&[u8; 32]>::try_from(node).unwrap() {
                            hasher.update(k);
                            hasher.update(node);
                        } else {
                            hasher.update(node);
                            hasher.update(k);
                        }
                        k = hasher.finalize().into();
                    }

                    // Compute tweaked output key and verify against program
                    let secp = secp256k1::Secp256k1::new();
                    let internal_xonly = match secp256k1::XOnlyPublicKey::from_slice(internal_key) {
                        Ok(k) => k,
                        Err(_) => return Err(ScriptError::WitnessProgramMismatch),
                    };

                    // TapTweak = tagged_hash("TapTweak", internal_key || merkle_root)
                    let tweak_hash = {
                        use sha2::{Sha256, Digest};
                        let tag = Sha256::digest(b"TapTweak");
                        let mut hasher = Sha256::new();
                        hasher.update(tag);
                        hasher.update(tag);
                        hasher.update(internal_key);
                        hasher.update(k);
                        let result: [u8; 32] = hasher.finalize().into();
                        result
                    };

                    let tweak_scalar = match secp256k1::Scalar::from_be_bytes(tweak_hash) {
                        Ok(s) => s,
                        Err(_) => return Err(ScriptError::WitnessProgramMismatch),
                    };

                    let (output_key, output_parity) = internal_xonly
                        .add_tweak(&secp, &tweak_scalar)
                        .map_err(|_| ScriptError::WitnessProgramMismatch)?;

                    // Verify the tweaked key matches the witness program
                    if output_key.serialize() != program {
                        return Err(ScriptError::WitnessProgramMismatch);
                    }

                    // Verify parity matches control block
                    let expected_parity = control_block[0] & 0x01;
                    let actual_parity: u8 = match output_parity {
                        secp256k1::Parity::Even => 0,
                        secp256k1::Parity::Odd => 1,
                    };
                    if expected_parity != actual_parity {
                        return Err(ScriptError::WitnessProgramMismatch);
                    }

                    // Only execute leaf version 0xc0 (tapscript)
                    if leaf_version == 0xc0 {
                        // Execute the tapscript
                        // Stack = all witness items except script and control block
                        let mut stack: Stack = effective_witness[..effective_witness.len() - 2].to_vec();

                        // Annex (if present) is the *original* last witness item,
                        // including the leading 0x50 prefix byte. Used by BIP-341
                        // sighash inside OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD.
                        let annex = if has_annex {
                            Some(witness.last().unwrap().as_slice())
                        } else {
                            None
                        };
                        let tapscript_ctx = TapscriptCtx {
                            tapleaf_hash: &tapleaf_hash,
                            annex,
                        };
                        // BIP-342 validation-weight budget: seeded from the
                        // ORIGINAL pre-pop witness (annex + control + script
                        // + args all counted), which is exactly what Core
                        // passes to `::GetSerializeSize(witness.stack)` at
                        // interpreter.cpp:1981.
                        let validation_weight_left =
                            get_serialize_size_of_witness_stack(witness) as i64 + 50;
                        eval_script_tapscript(
                            &mut stack,
                            tap_script,
                            flags,
                            checker,
                            tapscript_ctx,
                            validation_weight_left,
                        )?;

                        // Cleanstack: exactly one element
                        if stack.len() != 1 {
                            return Err(ScriptError::CleanStack);
                        }

                        // Must be true
                        if !stack_bool(&stack[0]) {
                            return Err(ScriptError::EvalFalse);
                        }
                    }
                    // Other leaf versions: anyone-can-spend (soft-fork safe)

                    Ok(())
                } else {
                    Err(ScriptError::WitnessProgramMismatch)
                }
            } else if program.len() == 2 && program[0] == 0x4e && program[1] == 0x73 {
                // BIP-444 Pay-to-Anchor (P2A): OP_1 <0x4e73>. Always spendable;
                // the relay DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM flag does NOT
                // apply (Core script/interpreter.cpp:1990 returns true
                // unconditionally for P2A).
                Ok(())
            } else {
                // v1 + non-32 (non-P2A) or taproot inactive: anyone-can-spend
                // per BIP-141 forward soft-fork compatibility, with optional
                // relay-only DISCOURAGE flag.
                if flags.verify_discourage_upgradable_witness_program {
                    return Err(ScriptError::WitnessProgramLength);
                }
                Ok(())
            }
        }
        2..=16 => {
            // Future SegWit versions
            if flags.verify_discourage_upgradable_witness_program {
                return Err(ScriptError::WitnessProgramLength);
            }
            // Unknown versions succeed (soft-fork safe)
            Ok(())
        }
        _ => Err(ScriptError::BadOpcode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_empty_script() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        assert!(eval_script(&mut stack, &[], &flags, &checker, SigVersion::Base).is_ok());
        assert!(stack.is_empty());
    }

    #[test]
    fn eval_op_1() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        let script = [0x51]; // OP_1
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        assert!(stack_bool(&stack[0]));
    }

    #[test]
    fn eval_op_0() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        let script = [0x00]; // OP_0
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        assert!(!stack_bool(&stack[0]));
    }

    #[test]
    fn eval_add() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_1 OP_1 OP_ADD -> 2
        let script = [0x51, 0x51, 0x93];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        let result = decode_script_num(&stack[0], false, 4).unwrap();
        assert_eq!(result, 2);
    }

    #[test]
    fn eval_sub() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_5 OP_3 OP_SUB -> 2
        let script = [0x55, 0x53, 0x94];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        let result = decode_script_num(&stack[0], false, 4).unwrap();
        assert_eq!(result, 2);
    }

    #[test]
    fn eval_equal() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_1 OP_1 OP_EQUAL -> true
        let script = [0x51, 0x51, 0x87];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        assert!(stack_bool(&stack[0]));
    }

    #[test]
    fn eval_not_equal() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_1 OP_2 OP_EQUAL -> false
        let script = [0x51, 0x52, 0x87];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        assert!(!stack_bool(&stack[0]));
    }

    #[test]
    fn eval_dup() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_1 OP_DUP -> [1, 1]
        let script = [0x51, 0x76];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn eval_hash160() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // Push some data, then HASH160
        let script = [0x01, 0x42, 0xa9]; // Push 0x42, OP_HASH160
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20);
    }

    #[test]
    fn eval_if_true_branch() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = [0x51, 0x63, 0x52, 0x67, 0x53, 0x68];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        let result = decode_script_num(&stack[0], false, 4).unwrap();
        assert_eq!(result, 2);
    }

    #[test]
    fn eval_if_false_branch() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = [0x00, 0x63, 0x52, 0x67, 0x53, 0x68];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        let result = decode_script_num(&stack[0], false, 4).unwrap();
        assert_eq!(result, 3);
    }

    #[test]
    fn eval_op_return() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        let script = [0x6a]; // OP_RETURN
        assert!(matches!(
            eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base),
            Err(ScriptError::OpReturn)
        ));
    }

    #[test]
    fn eval_op_return_in_false_branch() {
        // OP_RETURN in non-executing branch should NOT fail
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // OP_0 OP_IF OP_RETURN OP_ENDIF OP_1
        let script = [0x00, 0x63, 0x6a, 0x68, 0x51];
        assert!(eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base).is_ok());
        assert_eq!(stack.len(), 1);
        assert!(stack_bool(&stack[0]));
    }

    #[test]
    fn eval_disabled_opcode() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        let script = [0x7e]; // OP_CAT (disabled)
        assert!(matches!(
            eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base),
            Err(ScriptError::DisabledOpcode)
        ));
    }

    #[test]
    fn eval_stack_overflow() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // Push 1001 elements
        let mut script = Vec::new();
        for _ in 0..1001 {
            script.push(0x51); // OP_1
        }
        assert!(matches!(
            eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base),
            Err(ScriptError::StackOverflow)
        ));
    }

    #[test]
    fn eval_op_count_limit() {
        let mut stack = Stack::new();
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // 202 NOPs should fail
        let script = vec![0x61; 202]; // OP_NOP
        assert!(matches!(
            eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base),
            Err(ScriptError::OpCount)
        ));
    }

    #[test]
    fn is_p2sh_detection() {
        // Valid P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        let p2sh = [
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20 bytes
            0x87, // OP_EQUAL
        ];
        assert!(is_p2sh(&p2sh));

        // Not P2SH - wrong length
        let not_p2sh = [0xa9, 0x14, 0x00, 0x87];
        assert!(!is_p2sh(&not_p2sh));
    }

    #[test]
    fn is_p2pkh_detection() {
        let p2pkh = [
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20 bytes
            0x88, // OP_EQUALVERIFY
            0xac, // OP_CHECKSIG
        ];
        assert!(is_p2pkh(&p2pkh));
    }

    #[test]
    fn is_p2wpkh_detection() {
        let p2wpkh = [
            0x00, // OP_0
            0x14, // Push 20 bytes
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20 bytes
        ];
        assert!(is_p2wpkh(&p2wpkh));
    }

    #[test]
    fn is_p2wsh_detection() {
        let p2wsh = [
            0x00, // OP_0
            0x20, // Push 32 bytes
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // 32 bytes
        ];
        assert!(is_p2wsh(&p2wsh));
    }

    #[test]
    fn is_p2a_detection() {
        // Valid P2A: OP_1 PUSHBYTES_2 0x4e 0x73
        let p2a = [0x51, 0x02, 0x4e, 0x73];
        assert!(is_p2a(&p2a));

        // Also verify via is_p2a_program
        let (version, program) = parse_witness_program(&p2a).unwrap();
        assert_eq!(version, 1);
        assert_eq!(program, &[0x4e, 0x73]);
        assert!(is_p2a_program(version, program));

        // Not P2A - wrong program bytes
        let wrong_program = [0x51, 0x02, 0x00, 0x00];
        assert!(!is_p2a(&wrong_program));
        let (v, p) = parse_witness_program(&wrong_program).unwrap();
        assert!(!is_p2a_program(v, p));

        // Not P2A - wrong length
        let too_short = [0x51, 0x02, 0x4e];
        assert!(!is_p2a(&too_short));

        // Not P2A - P2TR (32 bytes, not 2)
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend([0u8; 32]);
        assert!(!is_p2a(&p2tr));

        // Not P2A - wrong version (OP_0 instead of OP_1)
        let wrong_version = [0x00, 0x02, 0x4e, 0x73];
        assert!(!is_p2a(&wrong_version));
    }

    #[test]
    fn p2a_anchor_script_bytes() {
        // Verify the exact P2A script as defined in Bitcoin Core
        // Script: OP_1 (0x51), PUSHBYTES_2 (0x02), 0x4e, 0x73
        // The bytes "Ns" in ASCII are 0x4e 0x73
        let p2a_script = [0x51, 0x02, 0x4e, 0x73];

        // Should be recognized as P2A
        assert!(is_p2a(&p2a_script));

        // Should parse as witness v1 program with 2 bytes
        let parsed = parse_witness_program(&p2a_script);
        assert!(parsed.is_some());
        let (version, program) = parsed.unwrap();
        assert_eq!(version, 1);
        assert_eq!(program.len(), 2);
        assert_eq!(program, &[0x4e, 0x73]);
    }

    #[test]
    fn parse_witness_program_v0() {
        let p2wpkh = [0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        let result = parse_witness_program(&p2wpkh);
        assert!(result.is_some());
        let (version, program) = result.unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 20);
    }

    #[test]
    fn parse_witness_program_v1() {
        let mut p2tr = vec![0x51, 0x20]; // OP_1, push 32 bytes
        p2tr.extend([0u8; 32]);
        let result = parse_witness_program(&p2tr);
        assert!(result.is_some());
        let (version, program) = result.unwrap();
        assert_eq!(version, 1);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn is_push_only_valid() {
        // Only push operations
        let script = [0x00, 0x51, 0x52, 0x01, 0xff];
        assert!(is_push_only(&script));
    }

    #[test]
    fn is_push_only_invalid() {
        // Contains OP_DUP (not a push)
        let script = [0x51, 0x76];
        assert!(!is_push_only(&script));
    }

    #[test]
    fn verify_simple_true() {
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        // scriptSig pushes 1, scriptPubKey checks if true
        let script_sig = [0x51]; // OP_1
        let script_pubkey = []; // Empty (will just check stack)
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_simple_false() {
        let flags = ScriptFlags::default();
        let checker = DummyChecker;
        let script_sig = [0x00]; // OP_0
        let script_pubkey = [];
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    // =========================
    // NULLFAIL (BIP-146) tests
    // =========================

    #[test]
    fn nullfail_checksig_empty_sig_allowed() {
        // With NULLFAIL enabled, an empty signature that fails verification is OK
        let mut stack = vec![
            vec![],                          // Empty signature (OK for NULLFAIL)
            vec![0x02; 33],                  // Fake pubkey
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_nullfail = true;
        let checker = DummyChecker;

        // OP_CHECKSIG
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        // Should succeed (empty sig is allowed even though verification fails)
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert!(!stack_bool(&stack[0])); // Result is false but no error
    }

    #[test]
    fn nullfail_checksig_nonempty_sig_rejected() {
        // With NULLFAIL enabled, a non-empty signature that fails verification is rejected
        let mut stack = vec![
            vec![0x30, 0x06, 0x01],          // Non-empty invalid signature
            vec![0x02; 33],                  // Fake pubkey
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_nullfail = true;
        let checker = DummyChecker;

        // OP_CHECKSIG
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        assert!(matches!(result, Err(ScriptError::NullFail)));
    }

    #[test]
    fn nullfail_disabled_nonempty_sig_allowed() {
        // Without NULLFAIL, a non-empty failing signature is allowed
        let mut stack = vec![
            vec![0x30, 0x06, 0x01],          // Non-empty invalid signature
            vec![0x02; 33],                  // Fake pubkey
        ];
        let flags = ScriptFlags::default(); // NULLFAIL is false by default
        let checker = DummyChecker;

        // OP_CHECKSIG
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        // Should succeed (NULLFAIL not enforced)
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert!(!stack_bool(&stack[0])); // Result is false
    }

    #[test]
    fn nullfail_checksigverify_nonempty_sig_rejected() {
        // With NULLFAIL enabled, CHECKSIGVERIFY with non-empty failing sig is rejected
        let mut stack = vec![
            vec![0x30, 0x06, 0x01],          // Non-empty invalid signature
            vec![0x02; 33],                  // Fake pubkey
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_nullfail = true;
        let checker = DummyChecker;

        // OP_CHECKSIGVERIFY
        let script = [0xad];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        // NULLFAIL error takes precedence over CHECKSIGVERIFY failure
        assert!(matches!(result, Err(ScriptError::NullFail)));
    }

    #[test]
    fn nullfail_checkmultisig_empty_sigs_allowed() {
        // With NULLFAIL enabled, empty signatures that fail verification are OK
        // Stack layout (bottom to top): dummy, sig1, nSigs, pubkey1, nKeys
        // Pop order: nKeys(1), pubkey(1), nSigs(1), sig(1), dummy
        let mut stack = vec![
            vec![],                          // Dummy element (bottom of stack, popped last)
            vec![],                          // Empty signature 1 (OK for NULLFAIL)
            vec![1],                         // nSigs = 1
            vec![0x02; 33],                  // Pubkey 1
            vec![1],                         // nKeys = 1 (TOP of stack, popped first)
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_nullfail = true;
        let checker = DummyChecker;

        // OP_CHECKMULTISIG
        let script = [0xae];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        // Should succeed (empty sigs allowed, even though verification fails)
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert!(!stack_bool(&stack[0])); // Result is false but no error
    }

    #[test]
    fn nullfail_checkmultisig_nonempty_sig_rejected() {
        // With NULLFAIL enabled, non-empty failing signatures are rejected
        let mut stack = vec![
            vec![],                          // Dummy element
            vec![0x30, 0x06, 0x01],          // Non-empty invalid signature
            vec![1],                         // nSigs = 1
            vec![0x02; 33],                  // Pubkey 1
            vec![1],                         // nKeys = 1
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_nullfail = true;
        let checker = DummyChecker;

        // OP_CHECKMULTISIG
        let script = [0xae];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        assert!(matches!(result, Err(ScriptError::NullFail)));
    }

    #[test]
    fn nullfail_consensus_flags_segwit_height() {
        // Verify NULLFAIL is enabled at segwit activation height (mainnet)
        let flags = ScriptFlags::consensus_flags(481_824, false);
        assert!(flags.verify_nullfail);
        assert!(flags.verify_witness);
        assert!(flags.verify_nulldummy);
    }

    #[test]
    fn nullfail_consensus_flags_before_segwit() {
        // Verify NULLFAIL is NOT enabled before segwit activation
        let flags = ScriptFlags::consensus_flags(481_823, false);
        assert!(!flags.verify_nullfail);
        assert!(!flags.verify_witness);
    }

    #[test]
    fn nullfail_consensus_flags_testnet4() {
        // Testnet4 has all soft forks active from block 1
        let flags = ScriptFlags::consensus_flags(1, true);
        assert!(flags.verify_nullfail);
        assert!(flags.verify_witness);
    }

    // =================================
    // WITNESS_PUBKEYTYPE (BIP-141) tests
    // =================================

    #[test]
    fn witness_pubkeytype_compressed_key_accepted() {
        // A compressed pubkey (33 bytes, 0x02 or 0x03 prefix) should be accepted
        let compressed_pubkey = {
            let mut key = vec![0x02];
            key.extend([0x42u8; 32]);
            key
        };
        let mut stack = vec![
            vec![],              // Empty signature (will fail verification, but that's ok)
            compressed_pubkey,   // Compressed pubkey (33 bytes, 0x02 prefix)
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        // OP_CHECKSIG in WitnessV0 mode
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        // Should succeed (signature fails, but pubkey is valid)
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert!(!stack_bool(&stack[0])); // False because sig verification failed
    }

    #[test]
    fn witness_pubkeytype_compressed_key_03_accepted() {
        // A compressed pubkey with 0x03 prefix should also be accepted
        let compressed_pubkey = {
            let mut key = vec![0x03];
            key.extend([0x42u8; 32]);
            key
        };
        let mut stack = vec![
            vec![],              // Empty signature
            compressed_pubkey,   // Compressed pubkey (33 bytes, 0x03 prefix)
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        // OP_CHECKSIG in WitnessV0 mode
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(result.is_ok());
    }

    #[test]
    fn witness_pubkeytype_uncompressed_key_rejected() {
        // An uncompressed pubkey (65 bytes, 0x04 prefix) should be rejected in witness v0
        let uncompressed_pubkey = {
            let mut key = vec![0x04];
            key.extend([0x42u8; 64]);
            key
        };
        let mut stack = vec![
            vec![],                // Empty signature
            uncompressed_pubkey,   // Uncompressed pubkey (65 bytes, 0x04 prefix)
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        // OP_CHECKSIG in WitnessV0 mode
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn witness_pubkeytype_wrong_length_rejected() {
        // A key with wrong length (not 33 bytes) should be rejected
        let bad_pubkey = vec![0x02, 0x42, 0x42]; // Only 3 bytes, not 33
        let mut stack = vec![
            vec![],
            bad_pubkey,
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        let script = [0xac]; // OP_CHECKSIG
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn witness_pubkeytype_wrong_prefix_rejected() {
        // A 33-byte key with wrong prefix (not 0x02 or 0x03) should be rejected
        let bad_pubkey = {
            let mut key = vec![0x04]; // Wrong prefix for 33-byte key
            key.extend([0x42u8; 32]);
            key
        };
        let mut stack = vec![
            vec![],
            bad_pubkey,
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        let script = [0xac]; // OP_CHECKSIG
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn witness_pubkeytype_legacy_mode_uncompressed_allowed() {
        // In legacy mode (SigVersion::Base), uncompressed keys should still be allowed
        let uncompressed_pubkey = {
            let mut key = vec![0x04];
            key.extend([0x42u8; 64]);
            key
        };
        let mut stack = vec![
            vec![],                // Empty signature
            uncompressed_pubkey,   // Uncompressed pubkey
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true; // Flag is set, but not in witness mode
        let checker = DummyChecker;

        // OP_CHECKSIG in Base (legacy) mode - uncompressed keys allowed
        let script = [0xac];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        // Should succeed (pubkey type check only applies to WitnessV0)
        assert!(result.is_ok());
    }

    #[test]
    fn witness_pubkeytype_flag_disabled_uncompressed_allowed() {
        // With the flag disabled, uncompressed keys should be allowed even in witness v0
        let uncompressed_pubkey = {
            let mut key = vec![0x04];
            key.extend([0x42u8; 64]);
            key
        };
        let mut stack = vec![
            vec![],
            uncompressed_pubkey,
        ];
        let flags = ScriptFlags::default(); // verify_witness_pubkeytype is false
        let checker = DummyChecker;

        let script = [0xac]; // OP_CHECKSIG
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        // Should succeed (flag not set)
        assert!(result.is_ok());
    }

    #[test]
    fn witness_pubkeytype_checksigverify_uncompressed_rejected() {
        // OP_CHECKSIGVERIFY should also reject uncompressed keys
        let uncompressed_pubkey = {
            let mut key = vec![0x04];
            key.extend([0x42u8; 64]);
            key
        };
        let mut stack = vec![
            vec![],
            uncompressed_pubkey,
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        let script = [0xad]; // OP_CHECKSIGVERIFY
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn witness_pubkeytype_checkmultisig_uncompressed_rejected() {
        // OP_CHECKMULTISIG should reject uncompressed keys in witness v0
        let uncompressed_pubkey = {
            let mut key = vec![0x04];
            key.extend([0x42u8; 64]);
            key
        };
        // Stack layout for 1-of-1 multisig (bottom to top):
        // dummy, sig, nSigs, pubkey, nKeys
        let mut stack = vec![
            vec![],                // Dummy element
            vec![0x30, 0x06, 0x01], // Non-empty signature
            vec![1],               // nSigs = 1
            uncompressed_pubkey,   // Uncompressed pubkey
            vec![1],               // nKeys = 1
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        let script = [0xae]; // OP_CHECKMULTISIG
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn witness_pubkeytype_checkmultisig_compressed_accepted() {
        // OP_CHECKMULTISIG should accept compressed keys in witness v0
        let compressed_pubkey = {
            let mut key = vec![0x02];
            key.extend([0x42u8; 32]);
            key
        };
        // Stack layout for 1-of-1 multisig with empty sig (will fail but pubkey check passes)
        let mut stack = vec![
            vec![],              // Dummy element
            vec![],              // Empty signature
            vec![1],             // nSigs = 1
            compressed_pubkey,   // Compressed pubkey
            vec![1],             // nKeys = 1
        ];
        let mut flags = ScriptFlags::default();
        flags.verify_witness_pubkeytype = true;
        let checker = DummyChecker;

        let script = [0xae]; // OP_CHECKMULTISIG
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        // Should succeed (pubkey is valid, sig verification fails but that's expected)
        assert!(result.is_ok());
        assert!(!stack_bool(&stack[0])); // Result is false (sig failed)
    }

    #[test]
    fn witness_pubkeytype_consensus_flags_enabled_at_segwit() {
        // Verify WITNESS_PUBKEYTYPE is enabled at segwit activation height (mainnet)
        let flags = ScriptFlags::consensus_flags(481_824, false);
        assert!(flags.verify_witness_pubkeytype);
        assert!(flags.verify_witness);
    }

    #[test]
    fn witness_pubkeytype_consensus_flags_disabled_before_segwit() {
        // Verify WITNESS_PUBKEYTYPE is NOT enabled before segwit activation
        let flags = ScriptFlags::consensus_flags(481_823, false);
        assert!(!flags.verify_witness_pubkeytype);
    }

    #[test]
    fn witness_pubkeytype_consensus_flags_testnet4() {
        // Testnet4 has all soft forks active from block 1
        let flags = ScriptFlags::consensus_flags(1, true);
        assert!(flags.verify_witness_pubkeytype);
        assert!(flags.verify_witness);
    }

    // ==================== Witness cleanstack tests ====================

    #[test]
    fn witness_cleanstack_p2wpkh_single_element_success() {
        // P2WPKH with valid execution leaving exactly 1 true element should succeed
        // We can't fully test this without real signatures, but we verify the structure
        let program = [0u8; 20]; // Dummy 20-byte program
        let witness = vec![
            vec![0x30], // Dummy signature
            vec![0x02; 33], // Dummy compressed pubkey
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        // This will fail at signature verification, but the cleanstack logic is correct
        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        // Expect failure due to signature check, not cleanstack
        assert!(result.is_err());
    }

    #[test]
    fn witness_cleanstack_p2wsh_extra_stack_items() {
        // P2WSH script that leaves extra items on the stack should fail with CleanStack
        // Script: OP_1 OP_1 (pushes two 1s, leaving 2 items on stack)
        let witness_script = vec![0x51, 0x51]; // OP_1 OP_1
        let program = sha256(&witness_script);

        let witness = vec![
            witness_script, // The witness script itself
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn witness_cleanstack_p2wsh_empty_stack() {
        // P2WSH script that leaves empty stack should fail with CleanStack
        // Script: OP_1 OP_DROP (pushes 1, then drops it, leaving empty stack)
        let witness_script = vec![0x51, 0x75]; // OP_1 OP_DROP
        let program = sha256(&witness_script);

        let witness = vec![
            witness_script, // The witness script itself
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn witness_cleanstack_p2wsh_single_false() {
        // P2WSH script that leaves single false element should fail with EvalFalse
        // Script: OP_0 (pushes empty/false)
        let witness_script = vec![0x00]; // OP_0
        let program = sha256(&witness_script);

        let witness = vec![
            witness_script, // The witness script itself
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::EvalFalse)));
    }

    #[test]
    fn witness_cleanstack_p2wsh_single_true() {
        // P2WSH script that leaves single true element should succeed
        // Script: OP_1 (pushes 1)
        let witness_script = vec![0x51]; // OP_1
        let program = sha256(&witness_script);

        let witness = vec![
            witness_script, // The witness script itself
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(result.is_ok());
    }

    #[test]
    fn witness_cleanstack_not_flag_gated() {
        // Witness cleanstack is NOT controlled by verify_cleanstack flag
        // It's always enforced for witness programs
        let witness_script = vec![0x51, 0x51]; // OP_1 OP_1 (leaves 2 items)
        let program = sha256(&witness_script);

        let witness = vec![
            witness_script,
        ];
        // Create flags with verify_cleanstack = false
        let flags = ScriptFlags::default();
        assert!(!flags.verify_cleanstack); // Confirm flag is off
        let checker = DummyChecker;

        // Should still fail with CleanStack because witness cleanstack is implicit
        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn witness_cleanstack_p2wsh_with_stack_items() {
        // P2WSH with initial stack items that leaves more than 1 item fails
        // Script: OP_1 (just pushes 1, but we have an item already on stack)
        let witness_script = vec![0x51]; // OP_1
        let program = sha256(&witness_script);

        // Witness: [stack_item, witness_script]
        // Stack after script: [stack_item, 1] - 2 items
        let witness = vec![
            vec![0x42], // Extra stack item
            witness_script,
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn witness_cleanstack_order_cleanstack_before_eval_false() {
        // When stack has multiple items AND top is false, should return CleanStack (not EvalFalse)
        // Script: OP_1 OP_0 (pushes 1, then 0 - two items, top is false)
        let witness_script = vec![0x51, 0x00]; // OP_1 OP_0
        let program = sha256(&witness_script);

        let witness = vec![
            witness_script,
        ];
        let flags = ScriptFlags::standard_flags();
        let checker = DummyChecker;

        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        // Should be CleanStack because len != 1, not EvalFalse
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    // ==================== P2SH push-only tests ====================

    #[test]
    fn p2sh_push_only_valid_scriptsig() {
        // P2SH with a push-only scriptSig should succeed
        // scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL
        // scriptSig: <push redeem_script> where redeem_script = OP_1
        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        // Build P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL
        let mut script_pubkey = vec![0xa9, 0x14]; // OP_HASH160, push 20 bytes
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87); // OP_EQUAL

        // scriptSig: just push the redeem script (1 byte length + script)
        let mut script_sig = vec![redeem_script.len() as u8];
        script_sig.extend_from_slice(&redeem_script);

        let mut flags = ScriptFlags::default();
        flags.verify_p2sh = true;
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(result.is_ok(), "P2SH with push-only scriptSig should succeed: {:?}", result);
    }

    #[test]
    fn p2sh_push_only_scriptsig_with_op_dup_fails() {
        // P2SH with a scriptSig containing OP_DUP (non-push) must fail
        // This is the BIP-16 consensus rule: scriptSig must be push-only for P2SH
        //
        // We need a scriptSig that:
        // 1. Executes successfully (no stack underflow)
        // 2. Contains a non-push opcode
        // 3. Leaves the correct redeem script on top of stack
        //
        // scriptSig: <push redeem_script> OP_DUP
        // This pushes the redeem script, then duplicates it (leaving two copies)
        // The scriptPubKey (OP_HASH160 <hash> OP_EQUAL) will consume top, leaving one copy
        // The P2SH logic will then use that copy as the redeem script
        // But this fails the push-only check!

        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        // Build P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL
        let mut script_pubkey = vec![0xa9, 0x14]; // OP_HASH160, push 20 bytes
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87); // OP_EQUAL

        // scriptSig: <push redeem_script> OP_DUP
        // This pushes the script then dups it - stack will have two copies
        let mut script_sig = vec![redeem_script.len() as u8];
        script_sig.extend_from_slice(&redeem_script);
        script_sig.push(0x76); // OP_DUP

        let mut flags = ScriptFlags::default();
        flags.verify_p2sh = true;
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(
            matches!(result, Err(ScriptError::SigPushOnly)),
            "P2SH with non-push-only scriptSig (OP_DUP) must fail with SigPushOnly: {:?}",
            result
        );
    }

    #[test]
    fn p2sh_push_only_scriptsig_with_op_add_fails() {
        // P2SH scriptSig with OP_ADD (arithmetic op) must fail
        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87);

        // scriptSig: <push 1> <push 1> OP_ADD <push redeem_script>
        // This would leave "2" and redeem_script on stack, but it's non-push-only
        let mut script_sig = vec![0x51, 0x51, 0x93]; // OP_1 OP_1 OP_ADD
        script_sig.push(redeem_script.len() as u8);
        script_sig.extend_from_slice(&redeem_script);

        let mut flags = ScriptFlags::default();
        flags.verify_p2sh = true;
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(
            matches!(result, Err(ScriptError::SigPushOnly)),
            "P2SH with non-push-only scriptSig (OP_ADD) must fail: {:?}",
            result
        );
    }

    #[test]
    fn p2sh_push_only_not_enforced_without_p2sh_flag() {
        // When verify_p2sh is false, the push-only check should NOT apply
        // (This represents pre-BIP16 behavior)
        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87);

        // scriptSig with OP_DUP - would fail if P2SH is enforced
        // But without P2SH flag, this is treated as a regular script
        // OP_DUP <push 20 bytes (redeem_hash)> - this will make hash160(redeem_hash) != redeem_hash
        // Let's use a scriptSig that would pass the OP_HASH160 check without P2SH semantics
        // Actually, for this test we just need to verify that the push-only check
        // doesn't trigger when verify_p2sh is false.

        // Use a non-P2SH interpretation: scriptSig: <push hash>, scriptPubKey: OP_HASH160 <hash> OP_EQUAL
        // This should verify as: HASH160(hash) == hash (which will fail, but not with SigPushOnly)

        // Simpler approach: use a scriptSig with OP_1 OP_DROP <push redeem_script>
        // With P2SH disabled, this is just: execute scriptSig, then scriptPubKey
        // Actually this won't work. Let's just verify the check doesn't trigger.

        // The simplest test: P2SH-looking scriptPubKey with non-push scriptSig
        // Without verify_p2sh, the P2SH special handling is skipped entirely
        let mut script_sig = vec![0x76]; // Just OP_DUP
        script_sig.push(0x14); // Push 20 bytes
        script_sig.extend_from_slice(redeem_hash.as_bytes());

        let flags = ScriptFlags::default(); // verify_p2sh is false
        assert!(!flags.verify_p2sh);
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        // Should NOT fail with SigPushOnly (P2SH disabled)
        // It will fail for other reasons (hash mismatch) but not push-only
        assert!(
            !matches!(result, Err(ScriptError::SigPushOnly)),
            "Without P2SH flag, push-only check should not apply: {:?}",
            result
        );
    }

    #[test]
    fn p2sh_push_only_with_op_nop_fails() {
        // Even OP_NOP in scriptSig fails the push-only check
        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87);

        // scriptSig: OP_NOP <push redeem_script>
        let mut script_sig = vec![0x61]; // OP_NOP
        script_sig.push(redeem_script.len() as u8);
        script_sig.extend_from_slice(&redeem_script);

        let mut flags = ScriptFlags::default();
        flags.verify_p2sh = true;
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(
            matches!(result, Err(ScriptError::SigPushOnly)),
            "P2SH with OP_NOP in scriptSig must fail: {:?}",
            result
        );
    }

    #[test]
    fn p2sh_push_only_with_pushdata_ops_succeeds() {
        // PUSHDATA1/2/4 are valid push operations
        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87);

        // scriptSig using PUSHDATA1: 0x4c <len> <data>
        let mut script_sig = vec![0x4c, redeem_script.len() as u8];
        script_sig.extend_from_slice(&redeem_script);

        let mut flags = ScriptFlags::default();
        flags.verify_p2sh = true;
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey, &witness, &flags, &checker);
        assert!(result.is_ok(), "PUSHDATA1 should be valid in scriptSig: {:?}", result);
    }

    #[test]
    fn p2sh_push_only_op_1negate_succeeds() {
        // OP_1NEGATE is a valid push operation (pushes -1)
        let redeem_script = vec![0x51]; // OP_1
        let redeem_hash = hash160(&redeem_script);

        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(redeem_hash.as_bytes());
        script_pubkey.push(0x87);

        // scriptSig: OP_1NEGATE OP_DROP <push redeem_script>
        // Wait, OP_DROP is not push-only. Let's use a different redeem script.

        // Use a redeem script that consumes the extra stack item: OP_DROP OP_1
        let redeem_script2 = vec![0x75, 0x51]; // OP_DROP OP_1
        let redeem_hash2 = hash160(&redeem_script2);

        let mut script_pubkey2 = vec![0xa9, 0x14];
        script_pubkey2.extend_from_slice(redeem_hash2.as_bytes());
        script_pubkey2.push(0x87);

        // scriptSig: OP_1NEGATE <push redeem_script>
        // This pushes -1 onto the stack, then the redeem script drops it and pushes 1
        let mut script_sig = vec![0x4f]; // OP_1NEGATE
        script_sig.push(redeem_script2.len() as u8);
        script_sig.extend_from_slice(&redeem_script2);

        let mut flags = ScriptFlags::default();
        flags.verify_p2sh = true;
        let checker = DummyChecker;
        let witness = vec![];

        let result = verify_script(&script_sig, &script_pubkey2, &witness, &flags, &checker);
        assert!(result.is_ok(), "OP_1NEGATE should be valid push in scriptSig: {:?}", result);
    }

    #[test]
    fn p2sh_push_only_consensus_flags_enabled() {
        // Verify that P2SH is enabled at the correct activation height (mainnet)
        let flags = ScriptFlags::consensus_flags(173_805, false);
        assert!(flags.verify_p2sh);

        // Before activation
        let flags_before = ScriptFlags::consensus_flags(173_804, false);
        assert!(!flags_before.verify_p2sh);
    }

    #[test]
    fn p2sh_push_only_testnet4_always_enabled() {
        // Testnet4 has P2SH active from block 1
        let flags = ScriptFlags::consensus_flags(1, true);
        assert!(flags.verify_p2sh);
    }

    // ==================== MINIMALIF tests ====================

    #[test]
    fn minimalif_witness_v0_0x02_rejected() {
        // OP_IF with [0x02] on stack fails MINIMALIF in witness v0
        // Script: <0x02> OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
        // The [0x02] is truthy but not minimal (only [0x01] is allowed)
        let mut stack = vec![vec![0x02]]; // Push 0x02 (truthy but non-minimal)
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        // OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn minimalif_witness_v0_0x01_accepted() {
        // OP_IF with [0x01] on stack passes MINIMALIF in witness v0
        let mut stack = vec![vec![0x01]]; // Exactly [0x01] - the only valid true
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        // OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(result.is_ok());
        // Should have taken true branch, pushed 1
        assert_eq!(stack.len(), 1);
        assert_eq!(decode_script_num(&stack[0], false, 4).unwrap(), 1);
    }

    #[test]
    fn minimalif_witness_v0_empty_takes_else_branch() {
        // OP_IF with [] (empty) on stack takes else branch
        let mut stack = vec![vec![]]; // Empty vector - valid false
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        // OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(result.is_ok());
        // Should have taken false branch (else), pushed 2
        assert_eq!(stack.len(), 1);
        assert_eq!(decode_script_num(&stack[0], false, 4).unwrap(), 2);
    }

    #[test]
    fn minimalif_witness_v0_0x00_rejected() {
        // OP_IF with [0x00] on stack fails MINIMALIF
        // [0x00] is falsy but NOT the minimal false (empty vector is)
        let mut stack = vec![vec![0x00]];
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn minimalif_witness_v0_multi_byte_rejected() {
        // OP_IF with [0x01, 0x00] on stack fails MINIMALIF (multi-byte)
        let mut stack = vec![vec![0x01, 0x00]];
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn minimalif_op_notif_0x02_rejected() {
        // OP_NOTIF with [0x02] on stack fails MINIMALIF
        let mut stack = vec![vec![0x02]];
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        // OP_NOTIF OP_1 OP_ELSE OP_2 OP_ENDIF
        let script = [0x64, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn minimalif_op_notif_0x01_takes_else_branch() {
        // OP_NOTIF with [0x01] takes else branch (because NOT true = false)
        let mut stack = vec![vec![0x01]];
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        // OP_NOTIF OP_1 OP_ELSE OP_2 OP_ENDIF
        let script = [0x64, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(result.is_ok());
        // NOTIF with true input takes else branch (NOT true = false)
        assert_eq!(decode_script_num(&stack[0], false, 4).unwrap(), 2);
    }

    #[test]
    fn minimalif_op_notif_empty_takes_true_branch() {
        // OP_NOTIF with [] takes the true branch (because NOT false = true)
        let mut stack = vec![vec![]];
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true;
        let checker = DummyChecker;

        // OP_NOTIF OP_1 OP_ELSE OP_2 OP_ENDIF
        let script = [0x64, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(result.is_ok());
        // NOTIF with false input takes main branch (NOT false = true)
        assert_eq!(decode_script_num(&stack[0], false, 4).unwrap(), 1);
    }

    #[test]
    fn minimalif_tapscript_unconditional() {
        // Tapscript enforces MINIMALIF unconditionally (no flag needed)
        let mut stack = vec![vec![0x02]];
        let flags = ScriptFlags::default(); // verify_minimalif is false
        let checker = DummyChecker;

        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Tapscript);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn minimalif_legacy_not_enforced() {
        // Legacy scripts do NOT enforce MINIMALIF (even with flag)
        let mut stack = vec![vec![0x02]];
        let mut flags = ScriptFlags::default();
        flags.verify_minimalif = true; // Flag is set but should be ignored for legacy
        let checker = DummyChecker;

        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::Base);
        // Should succeed - legacy doesn't enforce MINIMALIF
        assert!(result.is_ok());
        assert_eq!(decode_script_num(&stack[0], false, 4).unwrap(), 1);
    }

    #[test]
    fn minimalif_witness_v0_flag_required() {
        // Witness v0 requires the flag to enforce MINIMALIF (it's policy, not consensus)
        let mut stack = vec![vec![0x02]];
        let flags = ScriptFlags::default(); // verify_minimalif is false
        let checker = DummyChecker;

        let script = [0x63, 0x51, 0x67, 0x52, 0x68];
        let result = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        // Should succeed - flag not set
        assert!(result.is_ok());
    }

    // ==================================================================
    // BIP-342 tapscript validation-weight budget (interpreter.cpp:362)
    // ==================================================================

    /// Always-true Schnorr checker so we can drive CHECKSIG / CHECKSIGADD
    /// to "success" in tests without real BIP-340 cryptography. Tapscript
    /// only sees `check_schnorr_sig_tapscript`; the legacy ECDSA path is
    /// not exercised here.
    struct AlwaysTrueSchnorrChecker;
    impl SignatureChecker for AlwaysTrueSchnorrChecker {
        fn check_sig(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool { true }
        fn check_locktime(&self, _: i64) -> bool { true }
        fn check_sequence(&self, _: i64) -> bool { true }
        fn check_schnorr_sig_tapscript(
            &self,
            _sig: &[u8],
            _xonly_pubkey: &[u8; 32],
            _tapleaf_hash: &[u8; 32],
            _codesep_pos: u32,
            _annex: Option<&[u8]>,
        ) -> bool { true }
    }

    #[test]
    fn compact_size_len_matches_core() {
        assert_eq!(compact_size_len(0), 1);
        assert_eq!(compact_size_len(0xfc), 1);
        assert_eq!(compact_size_len(0xfd), 3);
        assert_eq!(compact_size_len(0xffff), 3);
        assert_eq!(compact_size_len(0x10000), 5);
        assert_eq!(compact_size_len(0xffffffff), 5);
        assert_eq!(compact_size_len(0x1_0000_0000), 9);
    }

    #[test]
    fn get_serialize_size_of_witness_stack_matches_core() {
        // Empty stack: just the count compact-size = 1 byte.
        assert_eq!(get_serialize_size_of_witness_stack(&[]), 1);
        // One 64-byte item: 1 (count) + 1 (item len prefix) + 64 (bytes).
        assert_eq!(get_serialize_size_of_witness_stack(&[vec![0u8; 64]]), 66);
        // Two items, 100 + 33 bytes:
        assert_eq!(
            get_serialize_size_of_witness_stack(&[vec![0u8; 100], vec![0u8; 33]]),
            1 + (1 + 100) + (1 + 33),
        );
    }

    #[test]
    fn tapscript_budget_exhausted_aborts_checksig() {
        // OP_CHECKSIG with a 32-byte pubkey and a 64-byte non-empty sig
        // and budget = 49 must trip TAPSCRIPT_VALIDATION_WEIGHT.
        // Stack (top-down): pubkey, sig.
        let pubkey = vec![0x02u8; 32];
        let sig = vec![0x42u8; 64];
        let mut stack: Stack = vec![sig, pubkey];
        let flags = ScriptFlags::default();
        let checker = AlwaysTrueSchnorrChecker;
        let tapleaf = [0u8; 32];
        let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
        let script = [0xac]; // OP_CHECKSIG
        let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 49);
        assert!(matches!(res, Err(ScriptError::TapscriptValidationWeight)));
    }

    #[test]
    fn tapscript_budget_sufficient_succeeds_checksig() {
        // Same setup, but budget = 50: 50 - 50 = 0 (not negative). Pass.
        let pubkey = vec![0x02u8; 32];
        let sig = vec![0x42u8; 64];
        let mut stack: Stack = vec![sig, pubkey];
        let flags = ScriptFlags::default();
        let checker = AlwaysTrueSchnorrChecker;
        let tapleaf = [0u8; 32];
        let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
        let script = [0xac]; // OP_CHECKSIG
        let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 50);
        assert!(res.is_ok(), "with budget 50, single CHECKSIG must succeed: {res:?}");
        // Result is `true` on stack.
        assert!(stack_bool(&stack[0]));
    }

    #[test]
    fn tapscript_empty_sig_consumes_no_budget_checksig() {
        // Empty sig + 32-byte pubkey: pushes false, MUST NOT decrement.
        // Budget = 0 must succeed (single OP_CHECKSIG).
        let pubkey = vec![0x02u8; 32];
        let mut stack: Stack = vec![vec![], pubkey];
        let flags = ScriptFlags::default();
        let checker = AlwaysTrueSchnorrChecker;
        let tapleaf = [0u8; 32];
        let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
        let script = [0xac]; // OP_CHECKSIG
        let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 0);
        assert!(res.is_ok(), "empty sig MUST NOT consume budget: {res:?}");
        assert!(!stack_bool(&stack[0]));
    }

    #[test]
    fn tapscript_budget_exhausted_aborts_checksigadd() {
        // OP_CHECKSIGADD with a 32-byte pubkey and a 64-byte non-empty sig
        // and budget = 0 must trip TAPSCRIPT_VALIDATION_WEIGHT.
        // Stack (top-down): pubkey, num, sig.
        let pubkey = vec![0x02u8; 32];
        let sig = vec![0x42u8; 64];
        let mut stack: Stack = vec![sig, vec![] /* num=0 */, pubkey];
        let flags = ScriptFlags::default();
        let checker = AlwaysTrueSchnorrChecker;
        let tapleaf = [0u8; 32];
        let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
        let script = [0xba]; // OP_CHECKSIGADD
        let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 0);
        assert!(matches!(res, Err(ScriptError::TapscriptValidationWeight)));
    }

    #[test]
    fn tapscript_budget_unknown_pubkey_also_consumes() {
        // Per Core's comment: "Passing with an upgradable public key
        // version is also counted." A non-32-byte pubkey on the
        // CHECKSIG path with a non-empty sig MUST decrement the budget.
        // Budget = 0 + non-empty sig + 33-byte pubkey → exhaust.
        let pubkey = vec![0x02u8; 33]; // unknown pubkey type (not 32)
        let sig = vec![0x42u8; 64];
        let mut stack: Stack = vec![sig, pubkey];
        let flags = ScriptFlags::default();
        let checker = AlwaysTrueSchnorrChecker;
        let tapleaf = [0u8; 32];
        let ts = TapscriptCtx { tapleaf_hash: &tapleaf, annex: None };
        let script = [0xac]; // OP_CHECKSIG
        let res = eval_script_tapscript(&mut stack, &script, &flags, &checker, ts, 0);
        assert!(matches!(res, Err(ScriptError::TapscriptValidationWeight)));
    }

    #[test]
    fn legacy_checksig_unaffected_by_budget() {
        // SegWit-v0 / legacy paths must NOT touch the budget. Construct
        // a checksig that decoder-fails (forces NULLFAIL off) and verify
        // that with `eval_script` (non-tapscript), no budget assertion
        // fires.
        // <empty sig> <pubkey> CHECKSIG → push false (legacy path).
        let pubkey = vec![0x02u8; 33];
        let mut stack: Stack = vec![vec![], pubkey];
        let mut flags = ScriptFlags::default();
        flags.verify_nullfail = false;
        let checker = DummyChecker;
        let script = [0xac]; // OP_CHECKSIG
        let res = eval_script(&mut stack, &script, &flags, &checker, SigVersion::WitnessV0);
        assert!(res.is_ok(), "legacy CHECKSIG with empty sig should push false: {res:?}");
        assert!(!stack_bool(&stack[0]));
    }

    // Regression test for the 945,394 P2A wedge (would have hit on next IBD
    // attempt past height 944,183). Pre-fix, verify_witness_program rejected
    // every v1 program with length != 32 as `WitnessProgramWrongLength`,
    // even when verify_taproot was on. Per BIP-141 / Core
    // script/interpreter.cpp:1947-1998 only v0 with bad length is a
    // consensus failure; v1 + non-32 (and v2-v16) are anyone-can-spend, with
    // P2A explicitly recognized. Mainnet block 945,394 tx 26b9fa21bb16d8fb...
    // input 0 spends a P2A output with prevout 0x51024e73.

    #[test]
    fn verify_witness_program_p2a_succeeds() {
        // BIP-444 P2A: v1 + 0x4e73 + empty witness must succeed regardless
        // of verify_taproot.
        let program = [0x4eu8, 0x73];
        let witness: Vec<Vec<u8>> = vec![];
        let mut flags = ScriptFlags::default();
        flags.verify_taproot = true;
        flags.verify_witness = true;
        let checker = DummyChecker;
        let result = verify_witness_program(&witness, 1, &program, &flags, &checker);
        assert!(result.is_ok(), "P2A spend should succeed: {result:?}");
    }

    #[test]
    fn verify_witness_program_p2a_unconditional_vs_discourage() {
        // P2A is unconditionally valid (Core line 1990 returns true regardless
        // of DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM).
        let program = [0x4eu8, 0x73];
        let witness: Vec<Vec<u8>> = vec![];
        let mut flags = ScriptFlags::default();
        flags.verify_taproot = true;
        flags.verify_witness = true;
        flags.verify_discourage_upgradable_witness_program = true;
        let checker = DummyChecker;
        let result = verify_witness_program(&witness, 1, &program, &flags, &checker);
        assert!(result.is_ok(), "P2A must bypass DISCOURAGE flag: {result:?}");
    }

    #[test]
    fn verify_witness_program_v1_unknown_length_succeeds() {
        // v1 + non-32, non-P2A program: anyone-can-spend (forward soft fork).
        let program = [0x00u8; 4];
        let witness: Vec<Vec<u8>> = vec![];
        let mut flags = ScriptFlags::default();
        flags.verify_taproot = true;
        flags.verify_witness = true;
        let checker = DummyChecker;
        let result = verify_witness_program(&witness, 1, &program, &flags, &checker);
        assert!(result.is_ok(), "v1 + 4-byte program must succeed: {result:?}");
    }

    #[test]
    fn verify_witness_program_v1_unknown_length_with_discourage_fails() {
        // Relay-only DISCOURAGE flag rejects unknown v1 lengths.
        let program = [0u8; 30];
        let witness: Vec<Vec<u8>> = vec![];
        let mut flags = ScriptFlags::default();
        flags.verify_taproot = true;
        flags.verify_witness = true;
        flags.verify_discourage_upgradable_witness_program = true;
        let checker = DummyChecker;
        let result = verify_witness_program(&witness, 1, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::WitnessProgramLength)),
            "DISCOURAGE flag must reject v1+30-byte: {result:?}");
    }

    #[test]
    fn verify_witness_program_v0_wrong_length_still_consensus_fails() {
        // Regression: the v0 length check is consensus per BIP141 and must
        // NOT have been weakened by the v1 forward-compat fix.
        // (Rustoshi uses `WitnessProgramLength` for the v0 path; the buggy
        // v1 path that this commit replaced was the only one using
        // `WitnessProgramWrongLength`.)
        let program = [0u8; 16]; // v0 + 16 bytes (not 20, not 32)
        let witness: Vec<Vec<u8>> = vec![];
        let mut flags = ScriptFlags::default();
        flags.verify_witness = true;
        let checker = DummyChecker;
        let result = verify_witness_program(&witness, 0, &program, &flags, &checker);
        assert!(matches!(result, Err(ScriptError::WitnessProgramLength)),
            "v0 + non-20/non-32 must still fail wrong-length: {result:?}");
    }
}
