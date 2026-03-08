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
//! **CRITICAL**: Only 7 flags are consensus-enforced during block validation:
//! - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT
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
/// - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT
///
/// Policy flags should only be used for mempool validation.
#[derive(Clone, Debug, Default)]
pub struct ScriptFlags {
    /// BIP-16: Pay-to-Script-Hash
    pub verify_p2sh: bool,
    /// BIP-66: Strict DER signature encoding (consensus)
    pub verify_dersig: bool,
    /// BIP-65: OP_CHECKLOCKTIMEVERIFY (consensus)
    pub verify_checklocktimeverify: bool,
    /// BIP-68/112/113: OP_CHECKSEQUENCEVERIFY (consensus)
    pub verify_checksequenceverify: bool,
    /// BIP-141: Segregated Witness (consensus)
    pub verify_witness: bool,
    /// BIP-147: NULLDUMMY - dummy element must be empty (consensus)
    pub verify_nulldummy: bool,
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
    /// Failed signature must be empty
    pub verify_nullfail: bool,
    /// Witness pubkeys must be compressed
    pub verify_witness_pubkeytype: bool,
    /// Fail on upgradable taproot versions
    pub verify_discourage_upgradable_taproot_version: bool,
    /// Fail on OP_SUCCESS opcodes
    pub verify_discourage_op_success: bool,
    /// Fail on upgradable pubkey types
    pub verify_discourage_upgradable_pubkeytype: bool,
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
        }
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
    /// * `sig` - The signature bytes (without sighash type for checksig ops)
    /// * `pubkey` - The public key bytes
    /// * `script_code` - The script being signed (for sighash computation)
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

/// The stack type used by the script interpreter.
pub type Stack = Vec<Vec<u8>>;

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
        }
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
            if executing {
                let data = script[pc..pc + len].to_vec();
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
            if executing {
                let data = script[pc..pc + len].to_vec();
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
            if executing {
                let data = script[pc..pc + len].to_vec();
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
            if executing {
                let data = script[pc..pc + len].to_vec();
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
                let cond = if ctx.stack.is_empty() {
                    false
                } else {
                    let val = ctx.pop()?;
                    if ctx.flags.verify_minimalif && val.len() > 1 {
                        return Err(ScriptError::MinimalIf);
                    }
                    if ctx.flags.verify_minimalif && val.len() == 1 && val[0] != 0 && val[0] != 1 {
                        return Err(ScriptError::MinimalIf);
                    }
                    stack_bool(&val)
                };
                ctx.exec_stack.push(cond);
            }
            Opcode::OP_NOTIF => {
                let cond = if ctx.stack.is_empty() {
                    true
                } else {
                    let val = ctx.pop()?;
                    if ctx.flags.verify_minimalif && val.len() > 1 {
                        return Err(ScriptError::MinimalIf);
                    }
                    if ctx.flags.verify_minimalif && val.len() == 1 && val[0] != 0 && val[0] != 1 {
                        return Err(ScriptError::MinimalIf);
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
                // Update the position for signature hashing
                // pc is now pointing past the CODESEPARATOR
                ctx.codesep_pos = (pc - 1) as u32;
            }
            Opcode::OP_CHECKSIG => {
                // Pop pubkey first (top), then signature (deeper)
                // This order is CRITICAL - swapping breaks all signature verification
                let pubkey = ctx.pop()?;
                let sig = ctx.pop()?;

                let success = if sig.is_empty() {
                    false
                } else {
                    // The last byte of sig is the sighash type
                    let sig_bytes = &sig[..sig.len() - 1];
                    ctx.checker.check_sig(sig_bytes, &pubkey, full_script, ctx.sig_version)
                };

                // NULLFAIL: failed sig must be empty
                if !success && ctx.flags.verify_nullfail && !sig.is_empty() {
                    return Err(ScriptError::NullFail);
                }

                ctx.push(bool_to_stack(success))?;
            }
            Opcode::OP_CHECKSIGVERIFY => {
                let pubkey = ctx.pop()?;
                let sig = ctx.pop()?;

                let success = if sig.is_empty() {
                    false
                } else {
                    let sig_bytes = &sig[..sig.len() - 1];
                    ctx.checker.check_sig(sig_bytes, &pubkey, full_script, ctx.sig_version)
                };

                if !success && ctx.flags.verify_nullfail && !sig.is_empty() {
                    return Err(ScriptError::NullFail);
                }

                if !success {
                    return Err(ScriptError::CheckSigVerifyFailed);
                }
            }
            Opcode::OP_CHECKMULTISIG => {
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
                    pubkeys.push(ctx.pop()?);
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
                    sigs.push(ctx.pop()?);
                }

                // Pop the dummy element (CHECKMULTISIG bug)
                let dummy = ctx.pop()?;
                if ctx.flags.verify_nulldummy && !dummy.is_empty() {
                    return Err(ScriptError::NullDummy);
                }

                // Verify signatures in order
                // Each signature must match a pubkey, and pubkeys are consumed left-to-right
                let mut key_idx = 0;
                let mut success = true;
                for sig in sigs.iter() {
                    if sig.is_empty() {
                        // Empty signature always fails
                        success = false;
                        break;
                    }

                    let sig_bytes = &sig[..sig.len() - 1];
                    let mut found = false;

                    while key_idx < n_keys {
                        let pubkey = &pubkeys[key_idx];
                        key_idx += 1;

                        if ctx.checker.check_sig(sig_bytes, pubkey, full_script, ctx.sig_version) {
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        success = false;
                        break;
                    }
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
                    pubkeys.push(ctx.pop()?);
                }

                let n_sigs_data = ctx.pop()?;
                let n_sigs = decode_script_num(&n_sigs_data, ctx.flags.verify_minimaldata, DEFAULT_MAX_NUM_SIZE)?;
                if n_sigs < 0 || n_sigs > n_keys as i64 {
                    return Err(ScriptError::SigCount);
                }
                let n_sigs = n_sigs as usize;

                let mut sigs = Vec::with_capacity(n_sigs);
                for _ in 0..n_sigs {
                    sigs.push(ctx.pop()?);
                }

                let dummy = ctx.pop()?;
                if ctx.flags.verify_nulldummy && !dummy.is_empty() {
                    return Err(ScriptError::NullDummy);
                }

                let mut key_idx = 0;
                let mut success = true;
                for sig in sigs.iter() {
                    if sig.is_empty() {
                        success = false;
                        break;
                    }

                    let sig_bytes = &sig[..sig.len() - 1];
                    let mut found = false;

                    while key_idx < n_keys {
                        let pubkey = &pubkeys[key_idx];
                        key_idx += 1;

                        if ctx.checker.check_sig(sig_bytes, pubkey, full_script, ctx.sig_version) {
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        success = false;
                        break;
                    }
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
                    return Err(ScriptError::BadOpcode);
                }
            }
            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                if !ctx.flags.verify_checklocktimeverify {
                    // Pre-BIP-65: treat as NOP
                    if ctx.flags.verify_discourage_upgradable_nops {
                        return Err(ScriptError::BadOpcode);
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
                        return Err(ScriptError::BadOpcode);
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
                    return Err(ScriptError::BadOpcode);
                }
            }

            // ==================== Tapscript ====================
            Opcode::OP_CHECKSIGADD => {
                // Only valid in tapscript
                if ctx.sig_version != SigVersion::Tapscript {
                    return Err(ScriptError::BadOpcode);
                }
                // Not implementing full tapscript yet
                return Err(ScriptError::BadOpcode);
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

                if stack.is_empty() || !stack_bool(stack.last().unwrap()) {
                    return Err(ScriptError::VerifyFailed);
                }

                // Clean stack: must have exactly one element
                if stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
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
                // Witness items are bottom-to-top on wire, must reverse
                let mut stack: Stack = witness[..witness.len() - 1].iter().rev().cloned().collect();

                eval_script(&mut stack, witness_script, flags, checker, SigVersion::WitnessV0)?;

                if stack.is_empty() || !stack_bool(stack.last().unwrap()) {
                    return Err(ScriptError::VerifyFailed);
                }

                if stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
                }

                Ok(())
            } else {
                Err(ScriptError::WitnessProgramLength)
            }
        }
        1 => {
            // SegWit v1 (Taproot)
            if !flags.verify_taproot {
                // Taproot not active, treat as anyone-can-spend
                return Ok(());
            }

            if program.len() != 32 {
                return Err(ScriptError::WitnessProgramLength);
            }

            // Taproot verification would go here
            // For now, reject (we haven't implemented Taproot yet)
            if flags.verify_discourage_upgradable_witness_program {
                return Err(ScriptError::BadOpcode);
            }

            Ok(())
        }
        2..=16 => {
            // Future SegWit versions
            if flags.verify_discourage_upgradable_witness_program {
                return Err(ScriptError::BadOpcode);
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
}
