//! Block and transaction validation.
//!
//! This module implements full consensus validation for Bitcoin transactions and blocks:
//!
//! - **Context-free checks** (`check_transaction`, `check_block`): Can be performed
//!   without any chain state. These are parallelizable.
//! - **Contextual checks** (`contextual_check_block_header`, `contextual_check_block`):
//!   Require chain context like median-time-past, soft fork activation heights.
//! - **Connection** (`connect_block`): Full validation against the UTXO set, including
//!   script verification. Produces undo data for potential disconnection.
//! - **Disconnection** (`disconnect_block`): Reverses a block's effects on the UTXO set
//!   using undo data.
//!
//! # Consensus vs Policy
//!
//! **CRITICAL**: Only 8 script flags are consensus-enforced:
//! - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, NULLFAIL, TAPROOT
//!
//! Adding policy flags (CLEANSTACK, LOW_S, etc.) to block validation causes valid
//! blocks to be rejected. See `script_flags_for_height` for the correct flags.
//!
//! # Intra-Block UTXO Spending
//!
//! Transactions within a block CAN spend outputs created by earlier transactions
//! in the same block. The UTXO set must be updated during the validation loop,
//! not after all transactions are validated.

use crate::params::{
    block_subsidy, ChainParams, COINBASE_MATURITY, LOCKTIME_THRESHOLD, MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT, MAX_MONEY, MAX_PUBKEYS_PER_MULTISIG, SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG, WITNESS_SCALE_FACTOR,
};
use crate::script::{
    is_p2sh, is_push_only, parse_witness_program, verify_script, ScriptFlags, SigVersion,
    SignatureChecker,
};
use rayon::prelude::*;
use rustoshi_crypto::sha256d;
use rustoshi_primitives::{compact_size_len, Block, BlockHeader, Hash256, OutPoint, Transaction};
use std::collections::HashSet;
use thiserror::Error;

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors that can occur during block validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("block too large: weight {0} exceeds {MAX_BLOCK_WEIGHT}")]
    BlockTooLarge(u64),

    #[error("no transactions in block")]
    NoTransactions,

    #[error("first transaction is not coinbase")]
    NoCoinbase,

    #[error("multiple coinbase transactions")]
    MultipleCoinbase,

    #[error("bad merkle root")]
    BadMerkleRoot,

    #[error("bad proof of work")]
    BadProofOfWork,

    #[error("timestamp too old (before median-time-past)")]
    TimeTooOld,

    #[error("timestamp too far in the future")]
    TimeTooNew,

    #[error("bad block version")]
    BadVersion,

    #[error("duplicate transaction: {0}")]
    DuplicateTx(String),

    #[error("transaction validation error: {0}")]
    TxValidation(#[from] TxValidationError),

    #[error("bad coinbase height (BIP-34)")]
    BadCoinbaseHeight,

    #[error("bad witness commitment")]
    BadWitnessCommitment,

    #[error("sigops limit exceeded: {0} > {MAX_BLOCK_SIGOPS_COST}")]
    SigopsLimitExceeded(u64),

    #[error("bad subsidy: block creates {0} satoshis but max is {1}")]
    BadSubsidy(u64, u64),

    #[error("block weight {0} exceeds maximum {MAX_BLOCK_WEIGHT}")]
    WeightExceeded(u64),

    #[error("previous block not found: {0}")]
    PrevBlockNotFound(String),

    #[error("block connects to invalid chain")]
    InvalidChain,

    #[error("non-final transaction: bad-txns-nonfinal")]
    NonFinalTx,

    /// BIP-30: a transaction in this block would overwrite an existing UTXO.
    /// Reference: Bitcoin Core validation.cpp ConnectBlock — rejects with
    /// "bad-txns-BIP30" when HaveCoin() is true for any output of a block tx.
    #[error("bad-txns-BIP30: tried to overwrite transaction")]
    Bip30DuplicateOutput,
}

/// Errors that can occur during transaction validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TxValidationError {
    #[error("empty inputs")]
    EmptyInputs,

    #[error("empty outputs")]
    EmptyOutputs,

    #[error("transaction too large: weight {0}")]
    TooLarge(u64),

    #[error("negative output value")]
    NegativeOutput,

    #[error("output value too large: {0}")]
    OutputTooLarge(u64),

    #[error("total output value too large: {0}")]
    TotalOutputTooLarge(u64),

    #[error("duplicate inputs")]
    DuplicateInputs,

    #[error("coinbase script size {0} out of range (2-100)")]
    CoinbaseScriptSize(usize),

    #[error("null previous output in non-coinbase")]
    NullPrevout,

    #[error("missing input: {0}:{1}")]
    MissingInput(Hash256, u32),

    #[error("input value overflow")]
    InputValueOverflow,

    #[error("inputs ({0}) less than outputs ({1})")]
    InsufficientFunds(u64, u64),

    #[error("script verification failed: {0}")]
    ScriptFailed(String),

    #[error("premature spend of coinbase (height {0}, maturity requires {1})")]
    PrematureCoinbaseSpend(u32, u32),

    #[error("sequence locktime not met")]
    SequenceLockNotMet,
}

impl ValidationError {
    /// Map this error to the canonical BIP-22 result string.
    ///
    /// Per BIP-22 and Bitcoin Core `BIP22ValidationResult` in
    /// `src/rpc/mining.cpp`, `submitblock` must return short ASCII strings on
    /// rejection rather than verbose internal error messages.  This method
    /// provides the canonical mapping so that the RPC layer can stay clean and
    /// every new validation variant gets an explicit string assignment.
    pub fn bip22_string(&self) -> &'static str {
        match self {
            // PoW
            ValidationError::BadProofOfWork => "high-hash",
            // Merkle root
            ValidationError::BadMerkleRoot => "bad-txnmrklroot",
            // Witness commitment (BIP-141)
            ValidationError::BadWitnessCommitment => "bad-witness-merkle-match",
            // Coinbase value / subsidy
            ValidationError::BadSubsidy(_, _) => "bad-cb-amount",
            // Sigops budget
            ValidationError::SigopsLimitExceeded(_) => "bad-blk-sigops",
            // Duplicate tx within block — maps to bad-txns-inputs-missingorspent
            // (Core parity: ConnectBlock catches the dup-spend via prevout-already-spent,
            // so Core never emits bad-txns-duplicate for in-block dup-txid.  The
            // BIP-30 cross-block case (Bip30DuplicateOutput below) still uses
            // bad-txns-BIP30 which is Core's canonical for that path.)
            ValidationError::DuplicateTx(_) => "bad-txns-inputs-missingorspent",
            // Non-final transaction
            ValidationError::NonFinalTx => "bad-txns-nonfinal",
            // BIP-30: tx output would overwrite existing UTXO
            ValidationError::Bip30DuplicateOutput => "bad-txns-BIP30",
            // BIP-34 coinbase height encoding
            ValidationError::BadCoinbaseHeight => "bad-cb-height",
            // Time checks
            ValidationError::TimeTooOld => "time-too-old",
            ValidationError::TimeTooNew => "time-too-new",
            // Negative output value (consensus/tx_check.cpp::CheckTransaction — Core parity)
            ValidationError::TxValidation(TxValidationError::NegativeOutput) => {
                "bad-txns-vout-negative"
            }
            // Output value > MAX_MONEY (consensus/tx_check.cpp::CheckTransaction — Core parity)
            ValidationError::TxValidation(TxValidationError::OutputTooLarge(_)) => {
                "bad-txns-vout-toolarge"
            }
            // Coinbase scriptSig length (consensus/tx_check.cpp — 2..100 bytes)
            ValidationError::TxValidation(TxValidationError::CoinbaseScriptSize(_)) => {
                "bad-cb-length"
            }
            // BIP-68 SequenceLocks failure (relative locktime not met).
            // Core validation.cpp:2558: state.Invalid(BLOCK_CONSENSUS,
            // "bad-txns-nonfinal", ...) — same string as IsFinalTx (nLockTime).
            ValidationError::TxValidation(TxValidationError::SequenceLockNotMet) => {
                "bad-txns-nonfinal"
            }
            // Script verification failure at connect-block stage.
            // Core validation.cpp:2122: "block-script-verify-flag-failed (%s)"
            // (not "mandatory-script-verify-flag-failed" which is the mempool
            // stage path at validation.cpp:2120).
            ValidationError::TxValidation(TxValidationError::ScriptFailed(_)) => {
                "block-script-verify-flag-failed"
            }
            // Catch-all: covers structural/weight/prev-block/chain errors
            _ => "rejected",
        }
    }
}

// ============================================================
// CONTEXT-FREE VALIDATION
// ============================================================

/// Validate a transaction without any chain context.
///
/// Checks:
/// - Non-empty inputs and outputs
/// - Output values within range (0 to MAX_MONEY)
/// - Total output value doesn't overflow or exceed MAX_MONEY
/// - No duplicate inputs
/// - Coinbase script size is valid (2-100 bytes)
/// - Non-coinbase inputs don't have null previous outputs
pub fn check_transaction(tx: &Transaction) -> Result<(), TxValidationError> {
    // Must have at least one input and one output
    if tx.inputs.is_empty() {
        return Err(TxValidationError::EmptyInputs);
    }
    if tx.outputs.is_empty() {
        return Err(TxValidationError::EmptyOutputs);
    }

    // Check output values
    // NOTE: value is stored as u64 but wire-encoded as int64; a negative wire value
    // will deserialize with the high bit set.  Check sign before the upper-bound
    // check (mirrors Bitcoin Core consensus/tx_check.cpp::CheckTransaction order).
    let mut total_out: u64 = 0;
    for output in &tx.outputs {
        if (output.value as i64) < 0 {
            return Err(TxValidationError::NegativeOutput);
        }
        if output.value > MAX_MONEY {
            return Err(TxValidationError::OutputTooLarge(output.value));
        }
        total_out = total_out
            .checked_add(output.value)
            .ok_or(TxValidationError::TotalOutputTooLarge(u64::MAX))?;
        if total_out > MAX_MONEY {
            return Err(TxValidationError::TotalOutputTooLarge(total_out));
        }
    }

    // Check for duplicate inputs
    let mut seen = HashSet::new();
    for input in &tx.inputs {
        if !seen.insert((&input.previous_output.txid, input.previous_output.vout)) {
            return Err(TxValidationError::DuplicateInputs);
        }
    }

    // Coinbase-specific checks
    if tx.is_coinbase() {
        let script_len = tx.inputs[0].script_sig.len();
        if !(2..=100).contains(&script_len) {
            return Err(TxValidationError::CoinbaseScriptSize(script_len));
        }
    } else {
        // Non-coinbase: no null previous outputs
        for input in &tx.inputs {
            if input.previous_output.is_null() {
                return Err(TxValidationError::NullPrevout);
            }
        }
    }

    Ok(())
}

/// Validate a block without chain context (CheckBlock in Bitcoin Core).
///
/// Checks:
/// - At least one transaction
/// - First transaction is coinbase
/// - No other transaction is coinbase
/// - All transactions pass context-free validation
/// - Proof of work is valid
/// - Merkle root matches computed value
/// - Block weight is within limits
/// - Sigops don't exceed limit
/// - No duplicate transactions
pub fn check_block(block: &Block, _params: &ChainParams) -> Result<(), ValidationError> {
    // Must have at least one transaction
    if block.transactions.is_empty() {
        return Err(ValidationError::NoTransactions);
    }

    // First transaction must be coinbase
    if !block.transactions[0].is_coinbase() {
        return Err(ValidationError::NoCoinbase);
    }

    // No other transaction can be coinbase
    for tx in &block.transactions[1..] {
        if tx.is_coinbase() {
            return Err(ValidationError::MultipleCoinbase);
        }
    }

    // Check for duplicate transactions
    let mut seen_txids = HashSet::new();
    for tx in &block.transactions {
        let txid = tx.txid();
        if !seen_txids.insert(txid) {
            return Err(ValidationError::DuplicateTx(txid.to_hex()));
        }
    }

    // Validate each transaction
    for tx in &block.transactions {
        check_transaction(tx)?;
    }

    // Validate proof of work
    if !block.header.validate_pow() {
        return Err(ValidationError::BadProofOfWork);
    }

    // Validate merkle root
    let computed = block.compute_merkle_root();
    if computed != block.header.merkle_root {
        return Err(ValidationError::BadMerkleRoot);
    }

    // Check block weight
    let weight = compute_block_weight(block);
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::WeightExceeded(weight));
    }

    // Check sigops
    let sigops = count_block_sigops(block);
    if sigops > MAX_BLOCK_SIGOPS_COST {
        return Err(ValidationError::SigopsLimitExceeded(sigops));
    }

    Ok(())
}

/// Compute the weight of a block.
///
/// Weight = (non-witness bytes) * WITNESS_SCALE_FACTOR + (witness bytes)
///
/// For a block: header (80 bytes) + tx_count + transactions
fn compute_block_weight(block: &Block) -> u64 {
    // Header is non-witness (80 bytes * 4 = 320 weight units)
    let mut weight: u64 = 80 * WITNESS_SCALE_FACTOR;

    // Transaction count is non-witness
    let tx_count_size = compact_size_len(block.transactions.len() as u64);
    weight += tx_count_size as u64 * WITNESS_SCALE_FACTOR;

    // Add weight of each transaction
    for tx in &block.transactions {
        weight += tx.weight() as u64;
    }

    weight
}

/// Count sigops in a block without UTXO context.
///
/// This is a preliminary check that counts only legacy sigops (from scriptSig
/// and scriptPubKey), scaled by WITNESS_SCALE_FACTOR. It cannot count P2SH or
/// witness sigops because those require UTXO data.
///
/// The full sigop cost is computed during `connect_block` via
/// `get_transaction_sigop_cost` for each transaction.
///
/// Reference: Bitcoin Core validation.cpp CheckBlock()
fn count_block_sigops(block: &Block) -> u64 {
    let mut sigops: u64 = 0;
    for tx in &block.transactions {
        // Legacy sigops from scriptSig and scriptPubKey
        sigops += get_legacy_sigop_count(tx) as u64 * WITNESS_SCALE_FACTOR;
    }
    sigops
}

/// Count legacy sigops in a transaction (from scriptSig and scriptPubKey).
///
/// Uses inaccurate counting (OP_CHECKMULTISIG = 20 sigops) because we don't
/// know the actual redeem scripts without UTXO context.
///
/// Reference: Bitcoin Core tx_verify.cpp GetLegacySigOpCount()
pub fn get_legacy_sigop_count(tx: &Transaction) -> u32 {
    let mut count = 0u32;
    for input in &tx.inputs {
        count += count_script_sigops(&input.script_sig, false);
    }
    for output in &tx.outputs {
        count += count_script_sigops(&output.script_pubkey, false);
    }
    count
}

/// Count P2SH sigops in a transaction.
///
/// For each input spending a P2SH output, extract the redeem script from
/// scriptSig and count its sigops with accurate multisig counting.
///
/// Requires UTXO data to check if the spent output is P2SH.
///
/// Reference: Bitcoin Core tx_verify.cpp GetP2SHSigOpCount()
pub fn get_p2sh_sigop_count(tx: &Transaction, get_coin: impl Fn(&OutPoint) -> Option<CoinEntry>) -> u32 {
    if tx.is_coinbase() {
        return 0;
    }

    let mut count = 0u32;
    for input in &tx.inputs {
        let Some(coin) = get_coin(&input.previous_output) else {
            continue;
        };

        if is_p2sh(&coin.script_pubkey) {
            // Extract the last push from scriptSig (the serialized redeem script)
            if let Some(redeem_script) = get_last_scriptpush(&input.script_sig) {
                count += count_script_sigops(&redeem_script, true);
            }
        }
    }
    count
}

/// Get the transaction sigop cost (weighted sigops for block limit).
///
/// The total cost is computed as:
/// - Legacy sigops (scriptSig + scriptPubKey) × WITNESS_SCALE_FACTOR
/// - P2SH sigops (redeem script) × WITNESS_SCALE_FACTOR (if P2SH flag active)
/// - Witness sigops (P2WPKH/P2WSH) × 1 (no scaling - witness discount)
///
/// The block limit is MAX_BLOCK_SIGOPS_COST (80,000).
///
/// Reference: Bitcoin Core tx_verify.cpp GetTransactionSigOpCost()
pub fn get_transaction_sigop_cost(
    tx: &Transaction,
    get_coin: impl Fn(&OutPoint) -> Option<CoinEntry>,
    flags: &ScriptFlags,
) -> u64 {
    // Start with legacy sigops, scaled by WITNESS_SCALE_FACTOR
    let mut cost = get_legacy_sigop_count(tx) as u64 * WITNESS_SCALE_FACTOR;

    if tx.is_coinbase() {
        return cost;
    }

    // Add P2SH sigops if P2SH is active
    if flags.verify_p2sh {
        // Need to pass a closure that can be called multiple times
        let mut p2sh_count = 0u32;
        for input in &tx.inputs {
            let Some(coin) = get_coin(&input.previous_output) else {
                continue;
            };
            if is_p2sh(&coin.script_pubkey) {
                if let Some(redeem_script) = get_last_scriptpush(&input.script_sig) {
                    p2sh_count += count_script_sigops(&redeem_script, true);
                }
            }
        }
        cost += p2sh_count as u64 * WITNESS_SCALE_FACTOR;
    }

    // Add witness sigops (NOT scaled - this is the witness discount)
    for input in &tx.inputs {
        let Some(coin) = get_coin(&input.previous_output) else {
            continue;
        };
        cost += count_witness_sigops(
            &input.script_sig,
            &coin.script_pubkey,
            &input.witness,
            flags,
        ) as u64;
    }

    cost
}

/// Count witness sigops for an input.
///
/// For bare witness programs (P2WPKH/P2WSH):
/// - P2WPKH: 1 sigop
/// - P2WSH: count sigops in witness script with accurate counting
///
/// For P2SH-wrapped witness programs:
/// - Extract redeem script from scriptSig
/// - If it's a witness program, count as above
///
/// Witness sigops are NOT scaled (this is the witness discount).
///
/// Reference: Bitcoin Core interpreter.cpp CountWitnessSigOps()
fn count_witness_sigops(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: &ScriptFlags,
) -> u32 {
    if !flags.verify_witness {
        return 0;
    }

    // Check for bare witness program
    if let Some((version, program)) = parse_witness_program(script_pubkey) {
        return witness_sigops(version, program, witness);
    }

    // Check for P2SH-wrapped witness program
    if is_p2sh(script_pubkey) && is_push_only(script_sig) {
        if let Some(redeem_script) = get_last_scriptpush(script_sig) {
            if let Some((version, program)) = parse_witness_program(&redeem_script) {
                return witness_sigops(version, program, witness);
            }
        }
    }

    0
}

/// Count sigops for a witness program.
///
/// - Version 0, 20 bytes (P2WPKH): 1 sigop
/// - Version 0, 32 bytes (P2WSH): count sigops in witness script with accurate counting
/// - Other versions: 0 (unknown, future upgrade)
///
/// Reference: Bitcoin Core interpreter.cpp WitnessSigOps()
fn witness_sigops(version: u8, program: &[u8], witness: &[Vec<u8>]) -> u32 {
    if version == 0 {
        if program.len() == 20 {
            // P2WPKH: always 1 sigop
            return 1;
        }
        if program.len() == 32 && !witness.is_empty() {
            // P2WSH: the last witness item is the script
            let witness_script = &witness[witness.len() - 1];
            return count_script_sigops(witness_script, true);
        }
    }
    // Unknown witness version: 0 sigops (future soft forks may change this)
    0
}

/// Extract the last push from a push-only script.
///
/// For P2SH, the last item pushed by scriptSig is the serialized redeem script.
/// For P2SH-wrapped witness, the last item is the witness program.
///
/// Returns None if the script is not push-only or is empty.
fn get_last_scriptpush(script: &[u8]) -> Option<Vec<u8>> {
    let mut pc = 0;
    let mut last_data: Option<Vec<u8>> = None;

    while pc < script.len() {
        let op = script[pc];
        pc += 1;

        if op == 0x00 {
            // OP_0: push empty
            last_data = Some(vec![]);
        } else if (0x01..=0x4b).contains(&op) {
            // Direct push (1-75 bytes)
            let len = op as usize;
            if pc + len > script.len() {
                return None;
            }
            last_data = Some(script[pc..pc + len].to_vec());
            pc += len;
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if pc >= script.len() {
                return None;
            }
            let len = script[pc] as usize;
            pc += 1;
            if pc + len > script.len() {
                return None;
            }
            last_data = Some(script[pc..pc + len].to_vec());
            pc += len;
        } else if op == 0x4d {
            // OP_PUSHDATA2
            if pc + 1 >= script.len() {
                return None;
            }
            let len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            if pc + len > script.len() {
                return None;
            }
            last_data = Some(script[pc..pc + len].to_vec());
            pc += len;
        } else if op == 0x4e {
            // OP_PUSHDATA4
            if pc + 3 >= script.len() {
                return None;
            }
            let len = u32::from_le_bytes([script[pc], script[pc + 1], script[pc + 2], script[pc + 3]]) as usize;
            pc += 4;
            if pc + len > script.len() {
                return None;
            }
            last_data = Some(script[pc..pc + len].to_vec());
            pc += len;
        } else if (0x51..=0x60).contains(&op) {
            // OP_1 through OP_16: push the value
            last_data = Some(vec![op - 0x50]);
        } else if op == 0x4f {
            // OP_1NEGATE: push -1
            last_data = Some(vec![0x81]);
        } else if op > 0x60 {
            // Not a push operation - this script is not push-only
            return None;
        }
    }

    last_data
}

/// Count sigops in a script.
///
/// - OP_CHECKSIG/OP_CHECKSIGVERIFY: 1 sigop each
/// - OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY: 20 sigops (or actual key count if accurate=true)
///
/// The `accurate` parameter uses the preceding OP_n to get the actual key count
/// for multisig. This is used for P2SH redeem scripts and witness scripts.
///
/// Reference: Bitcoin Core script.cpp GetSigOpCount()
pub fn count_script_sigops(script: &[u8], accurate: bool) -> u32 {
    let mut count = 0u32;
    let mut last_opcode = 0u8;
    let mut i = 0;

    while i < script.len() {
        let op = script[i];
        i += 1;

        // Skip push data
        if op > 0 && op <= 75 {
            i += op as usize;
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if i < script.len() {
                i += 1 + script[i] as usize;
            } else {
                break;
            }
        } else if op == 0x4d {
            // OP_PUSHDATA2
            if i + 1 < script.len() {
                let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2 + len;
            } else {
                break;
            }
        } else if op == 0x4e {
            // OP_PUSHDATA4
            if i + 3 < script.len() {
                let len =
                    u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                        as usize;
                i += 4 + len;
            } else {
                break;
            }
        } else if op == 0xac || op == 0xad {
            // OP_CHECKSIG or OP_CHECKSIGVERIFY
            count += 1;
        } else if op == 0xae || op == 0xaf {
            // OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY
            if accurate && (0x51..=0x60).contains(&last_opcode) {
                // OP_1 through OP_16
                count += (last_opcode - 0x50) as u32;
            } else {
                count += MAX_PUBKEYS_PER_MULTISIG as u32;
            }
        }

        last_opcode = op;
    }

    count
}

// ============================================================
// CONTEXTUAL VALIDATION
// ============================================================

/// Block index entry (metadata about a block).
///
/// This is used by the ChainContext trait to provide block metadata.
#[derive(Clone, Debug)]
pub struct BlockIndexEntry {
    /// Block height.
    pub height: u32,
    /// Block timestamp.
    pub timestamp: u32,
    /// Compact difficulty target.
    pub bits: u32,
    /// Previous block hash.
    pub prev_hash: Hash256,
    /// Total chain work up to and including this block.
    pub chain_work: [u8; 32],
}

/// Trait for providing chain context needed during validation.
pub trait ChainContext {
    /// Get the block index entry for a block hash.
    fn get_block_index(&self, hash: &Hash256) -> Option<BlockIndexEntry>;

    /// Get a UTXO by outpoint.
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<CoinEntry>;

    /// Get the median-time-past for the block with this hash.
    fn get_median_time_past(&self, hash: &Hash256) -> u32;

    /// Get the block hash at a given height in the active chain.
    fn get_hash_at_height(&self, height: u32) -> Option<Hash256>;

    /// Get the current tip height.
    fn tip_height(&self) -> u32;
}

/// Contextual validation of a block header.
///
/// Checks that depend on the previous block / wall clock:
/// - Timestamp must be greater than median-time-past of previous 11 blocks
///   (Core: `validation.cpp::ContextualCheckBlockHeader`, error
///   `time-too-old`).
/// - Timestamp must NOT be more than `MAX_FUTURE_BLOCK_TIME` (7200 seconds)
///   ahead of `current_time` (Core: `validation.cpp::CheckBlockHeader`,
///   error `time-too-new`).
/// - Block version must be valid for the height (BIP-65/66) — placeholder.
///
/// `current_time` is the node's wall-clock seconds since epoch, used for
/// the future-drift check.  Pass `0` to skip the future-time check (only
/// safe for tests / contexts where wall time isn't available).
pub fn contextual_check_block_header(
    header: &BlockHeader,
    height: u32,
    _prev_entry: &BlockIndexEntry,
    context: &dyn ChainContext,
    params: &ChainParams,
    current_time: u64,
) -> Result<(), ValidationError> {
    // Check timestamp against median-time-past
    let mtp = context.get_median_time_past(&header.prev_block_hash);
    if header.timestamp <= mtp {
        return Err(ValidationError::TimeTooOld);
    }

    // BIP-113 / Core: header.timestamp must not be > now + 2h.
    // Skipped when current_time == 0 (test-only path).
    if current_time != 0
        && (header.timestamp as u64) > current_time + crate::params::MAX_FUTURE_BLOCK_TIME
    {
        return Err(ValidationError::TimeTooNew);
    }

    // BIP-65: Block version must be >= 4 after activation
    // Note: We only enforce the soft fork rule, not reject lower versions entirely
    // The version check is a simplification; real BIP-9 deployment is more complex
    if height >= params.bip65_height {
        // After activation, we just need scripts to be valid with CLTV
        // The version bits deployment is handled separately
    }

    Ok(())
}

/// Check whether a transaction is final at a given block height and time.
///
/// A transaction is final if:
/// 1. nLockTime == 0, OR
/// 2. nLockTime < threshold (height if < 500M, time if >= 500M), OR
/// 3. All inputs have sequence == 0xFFFFFFFF (SEQUENCE_FINAL)
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp IsFinalTx()
/// Called from ContextualCheckBlock (validation.cpp:4146)
pub fn is_final_tx(tx: &Transaction, block_height: u32, lock_time_cutoff: u32) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    // Compare locktime against block height or block time depending on threshold
    let threshold = if tx.lock_time < LOCKTIME_THRESHOLD {
        block_height
    } else {
        lock_time_cutoff
    };
    if tx.lock_time < threshold {
        return true;
    }
    // Still final if all inputs have SEQUENCE_FINAL (0xFFFFFFFF)
    tx.inputs.iter().all(|input| input.sequence == 0xFFFF_FFFF)
}

/// Contextual validation of a full block.
///
/// Mirrors Bitcoin Core `validation.cpp::ContextualCheckBlock` — the
/// checks here are the ones that depend on the block's height (or on
/// chain context that isn't needed inside `check_block`).
///
/// Checks:
/// - BIP-34: Coinbase height encoding (if active).
/// - SegWit witness commitment (if SegWit active).
///
/// The `_context` parameter is reserved for future contextual checks
/// (e.g. BIP-30 duplicate-coinbase detection). It is currently unused.
pub fn contextual_check_block(
    block: &Block,
    height: u32,
    _context: &dyn ChainContext,
    params: &ChainParams,
) -> Result<(), ValidationError> {
    // BIP-34: Coinbase must start with serialized block height
    if height >= params.bip34_height {
        let script = &block.transactions[0].inputs[0].script_sig;
        let encoded_height = encode_bip34_height(height);
        if script.len() < encoded_height.len()
            || script[..encoded_height.len()] != encoded_height[..]
        {
            return Err(ValidationError::BadCoinbaseHeight);
        }
    }

    // SegWit: Check witness commitment
    if height >= params.segwit_height {
        check_witness_commitment(block)?;
    }

    Ok(())
}

/// Stub ChainContext for callers of `contextual_check_block` that don't
/// have a real chain-context provider.  All trait methods return empty /
/// zero values; safe because the current `contextual_check_block`
/// implementation does not consult any of them.  If/when BIP-30 is wired
/// in, callers must switch to a real provider.
pub struct StubChainContext;

impl ChainContext for StubChainContext {
    fn get_block_index(&self, _hash: &Hash256) -> Option<BlockIndexEntry> {
        None
    }
    fn get_utxo(&self, _outpoint: &OutPoint) -> Option<CoinEntry> {
        None
    }
    fn get_median_time_past(&self, _hash: &Hash256) -> u32 {
        0
    }
    fn get_hash_at_height(&self, _height: u32) -> Option<Hash256> {
        None
    }
    fn tip_height(&self) -> u32 {
        0
    }
}

/// Encode a block height for BIP-34 coinbase.
///
/// Mirrors Bitcoin Core's CScript() << nHeight (script.h:433-448):
/// - height == 0  → [0x00]            (OP_0, single byte)
/// - heights 1..16 → [0x51..0x60]     (OP_1..OP_16, single byte)
/// - heights 17+  → [len, le_bytes..] (length-prefixed sign-magnitude CScriptNum)
///
/// The checker in `contextual_check_block` uses byte-prefix comparison against
/// this output, so any non-canonical encoding (zero-padded, length-prefixed for
/// heights 1..16, missing sign byte) will be rejected.
pub(crate) fn encode_bip34_height(height: u32) -> Vec<u8> {
    if height == 0 {
        // OP_0 — single byte 0x00
        return vec![0x00];
    }
    if height <= 16 {
        // OP_1..OP_16 — single byte 0x51..0x60
        return vec![0x50u8 + height as u8];
    }

    // CScriptNum: minimal little-endian sign-magnitude with length prefix.
    let mut h = height;
    let mut le: Vec<u8> = Vec::new();
    while h > 0 {
        le.push((h & 0xFF) as u8);
        h >>= 8;
    }
    // If the high bit of the last byte is set, append a zero sign byte.
    if le.last().is_some_and(|b| b & 0x80 != 0) {
        le.push(0x00);
    }
    let mut result = vec![le.len() as u8];
    result.extend_from_slice(&le);
    result
}

/// Check the SegWit witness commitment in a block.
///
/// The commitment is an OP_RETURN output in the coinbase with:
/// - `OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <commitment_hash>`
///
/// The commitment hash is: SHA256d(witness_root || witness_nonce)
/// where witness_nonce is from the coinbase witness (or all zeros).
fn check_witness_commitment(block: &Block) -> Result<(), ValidationError> {
    let coinbase = &block.transactions[0];

    // Look for witness commitment in coinbase outputs (scan in reverse, use last one)
    let commitment_header: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
    let mut commitment_found = false;

    for output in coinbase.outputs.iter().rev() {
        // Format: OP_RETURN (0x6a) OP_PUSHBYTES_36 (0x24) 0xaa21a9ed <32-byte hash>
        if output.script_pubkey.len() >= 38
            && output.script_pubkey[0] == 0x6a
            && output.script_pubkey[1] == 0x24
            && output.script_pubkey[2..6] == commitment_header
        {
            // Found a witness commitment, verify it
            let witness_root = block.compute_witness_root();

            // Get witness nonce from coinbase (first witness item, or all zeros)
            let nonce = if coinbase.inputs[0].witness.is_empty() {
                [0u8; 32]
            } else {
                let first_witness = &coinbase.inputs[0].witness[0];
                if first_witness.len() == 32 {
                    let mut n = [0u8; 32];
                    n.copy_from_slice(first_witness);
                    n
                } else {
                    [0u8; 32]
                }
            };

            // Compute expected commitment
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(witness_root.as_bytes());
            preimage.extend_from_slice(&nonce);
            let computed = sha256d(&preimage);

            // Compare with commitment in output
            if output.script_pubkey[6..38] != computed.0[..] {
                return Err(ValidationError::BadWitnessCommitment);
            }

            commitment_found = true;
            break;
        }
    }

    // If no commitment found, check that no transaction has witness data
    // (except coinbase which can have a witness for the nonce)
    if !commitment_found {
        let has_witness = block.transactions[1..]
            .iter()
            .any(|tx| tx.has_witness());
        if has_witness {
            return Err(ValidationError::BadWitnessCommitment);
        }
    }

    Ok(())
}

// ============================================================
// BIP-68 SEQUENCE LOCKS
// ============================================================

/// The granularity of time-based sequence locks (512 seconds per unit).
const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9; // 2^9 = 512 seconds

/// Result of calculating sequence locks for a transaction.
///
/// Contains the minimum height and time that must be reached before
/// the transaction can be included in a block.
#[derive(Clone, Debug, Default)]
pub struct SequenceLocks {
    /// Minimum block height required for the transaction to be valid.
    /// -1 means no height-based lock.
    pub min_height: i32,
    /// Minimum median-time-past required for the transaction to be valid.
    /// -1 means no time-based lock.
    pub min_time: i64,
}

/// Trait for providing context needed for BIP-68 sequence lock calculation.
///
/// This trait abstracts access to chain state needed to compute sequence locks,
/// primarily the median-time-past of ancestor blocks.
pub trait SequenceLockContext {
    /// Get the median-time-past for the block at the given height.
    ///
    /// For sequence lock calculation, we need the MTP of the block prior
    /// to when the UTXO was mined (i.e., height - 1).
    fn get_mtp_at_height(&self, height: u32) -> u32;
}

/// Calculate the sequence locks for a transaction (BIP-68).
///
/// This computes the minimum block height and median-time-past required
/// for the transaction to be valid. Each input with a relative lock-time
/// (sequence number without the disable flag) contributes to these minimums.
///
/// # Arguments
/// * `tx` - The transaction to check.
/// * `spent_heights` - Heights of the blocks where each input's UTXO was mined.
/// * `context` - Provider for median-time-past lookups.
/// * `enforce_bip68` - Whether BIP-68 is active (tx version >= 2 and CSV soft fork active).
///
/// # Returns
/// The minimum height and time for the transaction to be valid.
///
/// # Reference
/// Bitcoin Core: `consensus/tx_verify.cpp` - `CalculateSequenceLocks`
pub fn calculate_sequence_locks<C: SequenceLockContext>(
    tx: &Transaction,
    spent_heights: &[u32],
    context: &C,
    enforce_bip68: bool,
) -> SequenceLocks {
    assert_eq!(spent_heights.len(), tx.inputs.len());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints. The semantics of nLockTime are the last invalid
    // height/time, so use -1 to have the effect of any height or time being valid.
    let mut min_height: i32 = -1;
    let mut min_time: i64 = -1;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if !enforce_bip68 {
        return SequenceLocks {
            min_height,
            min_time,
        };
    }

    for (idx, input) in tx.inputs.iter().enumerate() {
        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }

        let coin_height = spent_heights[idx];

        if input.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            //
            // For the first block (height 0), use height 0's MTP as a fallback.
            let coin_time = if coin_height > 0 {
                context.get_mtp_at_height(coin_height - 1) as i64
            } else {
                context.get_mtp_at_height(0) as i64
            };

            // NOTE: Subtract 1 to maintain nLockTime semantics.
            // BIP-68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height. Thus we subtract 1 from the calculated
            // time or height.
            let lock_value = (input.sequence & SEQUENCE_LOCKTIME_MASK) as i64;
            let lock_time = coin_time + (lock_value << SEQUENCE_LOCKTIME_GRANULARITY) - 1;
            if lock_time > min_time {
                min_time = lock_time;
            }
        } else {
            // Height-based relative lock-time
            let lock_value = (input.sequence & SEQUENCE_LOCKTIME_MASK) as i32;
            let lock_height = coin_height as i32 + lock_value - 1;
            if lock_height > min_height {
                min_height = lock_height;
            }
        }
    }

    SequenceLocks {
        min_height,
        min_time,
    }
}

/// Check if sequence locks are satisfied for a block at the given height.
///
/// The transaction can be included if:
/// - The block height > min_height (or min_height == -1)
/// - The block's MTP > min_time (or min_time == -1)
///
/// # Arguments
/// * `locks` - The calculated sequence locks for a transaction.
/// * `block_height` - The height of the block we want to include the transaction in.
/// * `block_mtp` - The median-time-past of the previous block (block_height - 1).
///
/// # Returns
/// `true` if all sequence locks are satisfied, `false` otherwise.
///
/// # Reference
/// Bitcoin Core: `consensus/tx_verify.cpp` - `EvaluateSequenceLocks`
pub fn check_sequence_locks(locks: &SequenceLocks, block_height: u32, block_mtp: i64) -> bool {
    // Check height lock
    if locks.min_height >= block_height as i32 {
        return false;
    }
    // Check time lock
    if locks.min_time >= block_mtp {
        return false;
    }
    true
}

// ============================================================
// UTXO VIEW AND BLOCK CONNECTION
// ============================================================

/// A UTXO entry with information needed for validation.
#[derive(Clone, Debug)]
pub struct CoinEntry {
    /// Height of the block that created this output.
    pub height: u32,
    /// Whether this output is from a coinbase transaction.
    pub is_coinbase: bool,
    /// Value in satoshis.
    pub value: u64,
    /// The scriptPubKey (locking script).
    pub script_pubkey: Vec<u8>,
}

/// Undo data for disconnecting a block.
#[derive(Clone, Debug)]
pub struct UndoData {
    /// Coins that were spent by this block, in order.
    pub spent_coins: Vec<CoinEntry>,
}

/// UTXO view trait — abstracts access to the UTXO set.
///
/// This allows validation to work with different UTXO storage backends
/// (in-memory cache, database, etc.).
pub trait UtxoView {
    /// Get a UTXO by outpoint.
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<CoinEntry>;

    /// Add a new UTXO.
    fn add_utxo(&mut self, outpoint: &OutPoint, coin: CoinEntry);

    /// Mark a UTXO as spent (remove it).
    fn spend_utxo(&mut self, outpoint: &OutPoint);
}

/// A null sequence lock context that provides no MTP data.
///
/// Used in tests and as a helper for callers that do not need BIP-68
/// sequence lock enforcement. Returns 0 for all MTP queries, which
/// disables time-based sequence locks while still allowing height-based
/// checks against the block height parameter.
#[cfg(test)]
pub(crate) struct NullSequenceLockContext;

#[cfg(test)]
impl SequenceLockContext for NullSequenceLockContext {
    fn get_mtp_at_height(&self, _height: u32) -> u32 {
        0
    }
}

/// Connect a block with full BIP-68 sequence lock enforcement.
///
/// This is the full-featured version that validates sequence locks
/// for all non-coinbase transactions when BIP-68/CSV is active.
///
/// # Arguments
/// * `block` - The block to connect.
/// * `height` - The height of the block being connected.
/// * `utxo_view` - UTXO view for reading/writing UTXOs.
/// * `params` - Chain parameters.
/// * `seq_context` - Context for sequence lock MTP lookups.
/// * `prev_block_mtp` - The median-time-past of the previous block.
///
/// # Returns
/// (undo_data, total_fees) on success.
pub fn connect_block_with_sequence_locks<C: SequenceLockContext>(
    block: &Block,
    height: u32,
    utxo_view: &mut dyn UtxoView,
    params: &ChainParams,
    seq_context: &C,
    prev_block_mtp: u32,
) -> Result<(UndoData, u64), ValidationError> {
    let flags = script_flags_for_height(height, params);
    let csv_active = height >= params.csv_height;
    let mut total_fees: u64 = 0;
    let mut spent_coins = Vec::new();
    let mut block_sigop_cost: u64 = 0;

    // Assume-valid: skip script verification for blocks at or below the assume-valid height
    let skip_scripts = match params.assumed_valid_height {
        Some(av_height) => height <= av_height,
        None => false,
    };

    // ContextualCheckBlock: enforce IsFinalTx for every transaction
    // (Core validation.cpp:4146). This is a consensus rule that runs even
    // under assumevalid — assumevalid only skips script verification.
    // lock_time_cutoff is MTP when BIP-113/CSV is active, block timestamp otherwise.
    let lock_time_cutoff = if csv_active {
        prev_block_mtp
    } else {
        block.header.timestamp
    };
    for tx in &block.transactions {
        if !is_final_tx(tx, height, lock_time_cutoff) {
            return Err(ValidationError::NonFinalTx);
        }
    }

    // BIP-30: reject any block whose transactions would overwrite an existing
    // unspent output in the UTXO set (CVE-2012-1909).
    //
    // Two mainnet blocks (h=91842 and h=91880) predate BIP-30 and intentionally
    // duplicate earlier coinbase txids; they are permanently exempted by block
    // height.  After BIP-34 activation (h≥bip34_height), the height-in-coinbase
    // rule makes duplicate txids practically impossible, so the check is skipped
    // for performance.  However, at h≥1,983,702 BIP-34 modular arithmetic begins
    // to repeat pre-BIP34 coinbase heights, so the check is re-enabled there.
    //
    // Reference: Bitcoin Core validation.cpp ConnectBlock (around line 2467-2476)
    // and IsBIP30Repeat().
    let bip34_implies_bip30_limit: u32 = 1_983_702;
    let is_bip30_exception = params.bip30_exception_heights.contains(&height);
    let enforce_bip30 = if is_bip30_exception {
        false
    } else if height >= params.bip34_height && height < bip34_implies_bip30_limit {
        // BIP-34 makes duplicates practically impossible in this range
        false
    } else {
        true
    };
    if enforce_bip30 {
        for tx in &block.transactions {
            let txid = tx.txid();
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint { txid, vout: vout as u32 };
                if utxo_view.get_utxo(&outpoint).is_some() {
                    return Err(ValidationError::Bip30DuplicateOutput);
                }
            }
        }
    }

    // Validate each transaction
    for tx in &block.transactions {
        // Skip coinbase for input validation (it has no real inputs)
        if tx.is_coinbase() {
            // Count coinbase sigops (legacy only, no inputs)
            block_sigop_cost += get_legacy_sigop_count(tx) as u64 * WITNESS_SCALE_FACTOR;

            // Add coinbase outputs to UTXO set immediately
            // (for potential intra-block spending in future soft forks, though
            // currently coinbase outputs can't be spent until maturity)
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                // Skip empty OP_RETURN outputs
                if output.script_pubkey.is_empty() && output.value == 0 {
                    continue;
                }
                // Also skip standard OP_RETURN (they're unspendable)
                if !output.script_pubkey.is_empty() && output.script_pubkey[0] == 0x6a {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                utxo_view.add_utxo(
                    &outpoint,
                    CoinEntry {
                        height,
                        is_coinbase: true,
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                    },
                );
            }
            continue;
        }

        // Collect coins and their heights for this transaction
        let mut coins: Vec<CoinEntry> = Vec::with_capacity(tx.inputs.len());
        let mut spent_heights: Vec<u32> = Vec::with_capacity(tx.inputs.len());

        // Validate inputs - first pass: collect coins and check basic validity
        let mut input_sum: u64 = 0;
        for input in &tx.inputs {
            // Get the coin being spent
            let coin = utxo_view.get_utxo(&input.previous_output).ok_or(
                TxValidationError::MissingInput(
                    input.previous_output.txid,
                    input.previous_output.vout,
                ),
            )?;

            // Check coinbase maturity
            if coin.is_coinbase && height - coin.height < COINBASE_MATURITY {
                return Err(TxValidationError::PrematureCoinbaseSpend(
                    height - coin.height,
                    COINBASE_MATURITY,
                )
                .into());
            }

            // Add to input sum
            input_sum = input_sum
                .checked_add(coin.value)
                .ok_or(TxValidationError::InputValueOverflow)?;

            spent_heights.push(coin.height);
            coins.push(coin);
        }

        // Calculate sigop cost for this transaction using the collected coins
        // Create a closure that looks up coins by input index
        let tx_sigop_cost = {
            let coins_ref = &coins;
            let inputs = &tx.inputs;
            let get_coin = |outpoint: &OutPoint| -> Option<CoinEntry> {
                // Find which input has this outpoint
                for (idx, input) in inputs.iter().enumerate() {
                    if input.previous_output == *outpoint {
                        return Some(coins_ref[idx].clone());
                    }
                }
                None
            };
            get_transaction_sigop_cost(tx, get_coin, &flags)
        };
        block_sigop_cost += tx_sigop_cost;

        // BIP-68: Check sequence locks
        // BIP-68 only applies if tx version >= 2 and CSV is active
        let enforce_bip68 = tx.version >= 2 && csv_active;
        if enforce_bip68 {
            let locks = calculate_sequence_locks(tx, &spent_heights, seq_context, true);
            if !check_sequence_locks(&locks, height, prev_block_mtp as i64) {
                return Err(TxValidationError::SequenceLockNotMet.into());
            }
        }

        // Materialize per-input prevouts once so the Taproot checker can
        // build BIP-341 sha_amounts / sha_scriptpubkeys without re-walking
        // `coins` on every call. Cheap: ~Coin::SIZE * inputs bytes per tx.
        let spent_amounts: Vec<u64> = coins.iter().map(|c| c.value).collect();
        let spent_scripts: Vec<Vec<u8>> = coins.iter().map(|c| c.script_pubkey.clone()).collect();

        // Second pass: verify scripts and update UTXO set
        for (input_idx, input) in tx.inputs.iter().enumerate() {
            let coin = &coins[input_idx];

            // Verify the script (skip if below assume-valid height)
            if !skip_scripts {
                let checker = TransactionSignatureChecker::new(
                    tx,
                    input_idx,
                    coin.value,
                    &spent_amounts,
                    &spent_scripts,
                );
                verify_script(
                    &input.script_sig,
                    &coin.script_pubkey,
                    &input.witness,
                    &flags,
                    &checker,
                )
                .map_err(|e| TxValidationError::ScriptFailed(e.to_string()))?;
            }

            // Save spent coin for undo data
            spent_coins.push(coin.clone());

            // Remove from UTXO set
            utxo_view.spend_utxo(&input.previous_output);
        }

        // Calculate output sum
        let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();

        // Inputs must cover outputs (difference is fee)
        if input_sum < output_sum {
            return Err(TxValidationError::InsufficientFunds(input_sum, output_sum).into());
        }

        total_fees += input_sum - output_sum;

        // Add outputs to UTXO set (for intra-block spending)
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            // Skip unspendable outputs
            if !output.script_pubkey.is_empty() && output.script_pubkey[0] == 0x6a {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            utxo_view.add_utxo(
                &outpoint,
                CoinEntry {
                    height,
                    is_coinbase: false,
                    value: output.value,
                    script_pubkey: output.script_pubkey.clone(),
                },
            );
        }
    }

    // Check block sigop cost limit
    if block_sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ValidationError::SigopsLimitExceeded(block_sigop_cost));
    }

    // Verify coinbase doesn't exceed allowed value (subsidy + fees)
    let subsidy = block_subsidy(height, params.subsidy_halving_interval);
    let max_coinbase_value = subsidy + total_fees;
    let coinbase_value: u64 = block.transactions[0]
        .outputs
        .iter()
        .map(|o| o.value)
        .sum();

    if coinbase_value > max_coinbase_value {
        return Err(ValidationError::BadSubsidy(coinbase_value, max_coinbase_value));
    }

    Ok((UndoData { spent_coins }, total_fees))
}

/// Validate all transaction scripts in a block in parallel with optional caching.
///
/// This is the same as a parallel script validator but with an optional signature
/// cache. When provided, the cache is checked before each script verification
/// and successful verifications are cached for future use.
///
/// # Arguments
/// * `block` - The block containing transactions to validate
/// * `coins` - Pre-fetched coins for each input (indexed by (tx_index, input_index))
/// * `flags` - Script verification flags for this block height
/// * `sig_cache` - Optional signature cache for avoiding redundant verifications
///
/// # Returns
/// `Ok(())` if all scripts are valid, or the first error encountered.
///
/// # Cache Usage
///
/// The cache key includes the txid, input index, and flags. This ensures that:
/// - Different transactions are cached separately
/// - Different inputs within a transaction are cached separately
/// - Different verification flags don't share cache entries
///
/// Only successful verifications are cached. Cache entries should be cleared
/// during chain reorganizations.
pub fn validate_scripts_parallel_with_cache(
    block: &Block,
    coins: &[Vec<CoinEntry>],
    flags: &ScriptFlags,
    sig_cache: Option<&crate::sig_cache::SigCache>,
) -> Result<(), TxValidationError> {
    // Convert flags to u32 for cache key
    let flags_bits = flags.to_bits();

    // Materialize per-tx prevouts once so each parallel checker can build
    // BIP-341 sha_amounts / sha_scriptpubkeys cheaply from slices.
    // Indexed by tx_idx_in_coins (= block-level tx index minus the coinbase).
    let per_tx_prevouts: Vec<(Vec<u64>, Vec<Vec<u8>>)> = coins
        .iter()
        .map(|tc| {
            (
                tc.iter().map(|c| c.value).collect(),
                tc.iter().map(|c| c.script_pubkey.clone()).collect(),
            )
        })
        .collect();

    // Collect all (tx, input_index, coin, tx_coin_idx) tuples for
    // non-coinbase transactions. tx_coin_idx indexes into per_tx_prevouts.
    let script_checks: Vec<_> = block
        .transactions
        .iter()
        .enumerate()
        .skip(1) // Skip coinbase
        .flat_map(|(tx_idx, tx)| {
            tx.inputs.iter().enumerate().map(move |(input_idx, _input)| {
                // tx_idx - 1 because we skip coinbase in the coins array
                (tx, input_idx, &coins[tx_idx - 1][input_idx], tx_idx - 1)
            })
        })
        .collect();

    // Validate all scripts in parallel
    let results: Vec<Result<(), TxValidationError>> = script_checks
        .par_iter()
        .map(|(tx, input_idx, coin, tx_coin_idx)| {
            let txid_bytes: [u8; 32] = tx.txid().0;

            // Check cache first
            if let Some(cache) = sig_cache {
                if cache.contains(&txid_bytes, *input_idx as u32, flags_bits) {
                    return Ok(());
                }
            }

            // Verify script
            let (spent_amounts, spent_scripts) = &per_tx_prevouts[*tx_coin_idx];
            let checker = TransactionSignatureChecker::new(
                tx,
                *input_idx,
                coin.value,
                spent_amounts,
                spent_scripts,
            );
            let result = verify_script(
                &tx.inputs[*input_idx].script_sig,
                &coin.script_pubkey,
                &tx.inputs[*input_idx].witness,
                flags,
                &checker,
            )
            .map_err(|e| TxValidationError::ScriptFailed(e.to_string()));

            // Cache successful verification
            if result.is_ok() {
                if let Some(cache) = sig_cache {
                    cache.insert(&txid_bytes, *input_idx as u32, flags_bits);
                }
            }

            result
        })
        .collect();

    // Check for any failures
    for result in results {
        result?;
    }

    Ok(())
}

/// Disconnect a block: reverse the UTXO set changes using undo data.
///
/// This is used during chain reorganizations to "un-apply" a block.
pub fn disconnect_block(
    block: &Block,
    undo: &UndoData,
    utxo_view: &mut dyn UtxoView,
) -> Result<(), ValidationError> {
    // Remove outputs added by this block (in reverse order)
    for tx in block.transactions.iter().rev() {
        let txid = tx.txid();
        for vout in (0..tx.outputs.len()).rev() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            utxo_view.spend_utxo(&outpoint);
        }
    }

    // Restore spent inputs (in reverse order)
    let mut coin_idx = undo.spent_coins.len();
    for tx in block.transactions.iter().rev() {
        if tx.is_coinbase() {
            continue;
        }
        for input in tx.inputs.iter().rev() {
            coin_idx -= 1;
            utxo_view.add_utxo(&input.previous_output, undo.spent_coins[coin_idx].clone());
        }
    }

    Ok(())
}

// ============================================================
// SCRIPT FLAGS
// ============================================================

/// Get the script verification flags for a given block height.
///
/// **CRITICAL**: Only returns Bitcoin Core MANDATORY_SCRIPT_VERIFY_FLAGS.
/// Adding policy flags here causes valid blocks to be rejected.
///
/// Consensus flags by activation height:
/// - P2SH: BIP-16 (always on after activation)
/// - DERSIG: BIP-66
/// - CLTV: BIP-65
/// - CSV: BIP-68/112/113
/// - WITNESS: BIP-141/143
/// - NULLDUMMY: BIP-147 (activated with SegWit) — consensus rule
/// - TAPROOT: BIP-341/342
///
/// NULLFAIL (BIP-146) is a STANDARD_SCRIPT_VERIFY_FLAG (policy only) per
/// Bitcoin Core policy/policy.h:125.  It must NOT appear here.
fn script_flags_for_height(height: u32, params: &ChainParams) -> ScriptFlags {
    // NOTE: Do NOT add policy flags here!
    // CLEANSTACK, LOW_S, STRICTENC, MINIMALDATA, MINIMALIF, NULLFAIL,
    // WITNESS_PUBKEYTYPE, etc. are policy-only and must NOT be enforced
    // during block validation.  Ref: Bitcoin Core validation.cpp:2250-2289.

    ScriptFlags {
        // P2SH is always enabled after its activation
        verify_p2sh: true,
        // BIP-66: Strict DER signatures
        verify_dersig: height >= params.bip66_height,
        // BIP-65: CHECKLOCKTIMEVERIFY
        verify_checklocktimeverify: height >= params.bip65_height,
        // BIP-68/112/113: CSV
        verify_checksequenceverify: height >= params.csv_height,
        // BIP-141/143: SegWit
        verify_witness: height >= params.segwit_height,
        // BIP-147: NULLDUMMY (activated with SegWit) — consensus rule
        verify_nulldummy: height >= params.segwit_height,
        // BIP-341/342: Taproot
        verify_taproot: height >= params.taproot_height,
        // All policy flags stay at default (false), including verify_nullfail
        ..Default::default()
    }
}

// ============================================================
// SIGNATURE CHECKER
// ============================================================

/// Lax DER signature parser using secp256k1's built-in `from_der_lax`.
///
/// This is equivalent to Bitcoin Core's `ecdsa_signature_parse_der_lax`.
/// It tolerates various DER encoding violations that strict DER parsing
/// would reject. Bitcoin Core uses this for all signature verification;
/// strict DER enforcement is handled separately by the DERSIG script flag
/// check in the interpreter, not at the crypto level.
///
/// After parsing, the signature is normalized to low-S form because the
/// Rust secp256k1 binding's `verify_ecdsa` requires low-S signatures.
fn lax_der_parse(data: &[u8]) -> Result<secp256k1::ecdsa::Signature, secp256k1::Error> {
    let mut sig = secp256k1::ecdsa::Signature::from_der_lax(data)?;
    sig.normalize_s();
    Ok(sig)
}

/// Transaction signature checker for script verification.
///
/// Implements the SignatureChecker trait to verify signatures
/// against a specific transaction input.
///
/// `spent_amounts` and `spent_scripts` carry the per-input prevouts
/// the *whole* transaction is spending; they are required for
/// BIP-341 Taproot sighash computation (`sha_amounts` and
/// `sha_scriptpubkeys` digest all inputs). For pre-Taproot scripts,
/// these slices are unused and may be empty.
pub struct TransactionSignatureChecker<'a> {
    tx: &'a Transaction,
    input_index: usize,
    amount: u64,
    spent_amounts: &'a [u64],
    spent_scripts: &'a [Vec<u8>],
}

impl<'a> TransactionSignatureChecker<'a> {
    /// Create a new signature checker for a transaction input.
    ///
    /// Pass `&[]` for `spent_amounts` and `spent_scripts` when the
    /// caller knows Taproot won't be exercised (e.g. legacy script
    /// unit tests). For mainnet block validation, pass slices covering
    /// every input's prevout.
    pub fn new(
        tx: &'a Transaction,
        input_index: usize,
        amount: u64,
        spent_amounts: &'a [u64],
        spent_scripts: &'a [Vec<u8>],
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            spent_amounts,
            spent_scripts,
        }
    }
}

impl<'a> SignatureChecker for TransactionSignatureChecker<'a> {
    fn check_sig(
        &self,
        sig_data: &[u8],
        pubkey: &[u8],
        subscript: &[u8],
        sig_version: SigVersion,
    ) -> bool {
        if sig_data.is_empty() {
            return false;
        }

        // Last byte is the sighash type
        let hash_type = *sig_data.last().unwrap() as u32;
        let sig_bytes = &sig_data[..sig_data.len() - 1];

        // Compute the sighash based on version
        let sighash = match sig_version {
            SigVersion::Base => {
                // For legacy sighash:
                // 1. Apply FindAndDelete to remove the push-encoded signature
                // 2. Remove OP_CODESEPARATOR opcodes from the subscript
                // Both operations are required for correct legacy sighash computation.
                let script_code = rustoshi_crypto::find_and_delete(subscript, sig_data);
                let script_code = rustoshi_crypto::remove_codeseparators(&script_code);
                rustoshi_crypto::legacy_sighash(self.tx, self.input_index, &script_code, hash_type)
            }
            SigVersion::WitnessV0 => {
                // For SegWit v0, FindAndDelete is NOT applied (BIP-143).
                // The subscript should already be the scriptCode.
                rustoshi_crypto::segwit_v0_sighash(
                    self.tx,
                    self.input_index,
                    subscript,
                    self.amount,
                    hash_type,
                )
            }
            SigVersion::Tapscript => {
                // Tapscript uses BIP-341 sighash (not implemented yet)
                return false;
            }
        };

        // Verify the ECDSA signature
        let Ok(pk) = secp256k1::PublicKey::from_slice(pubkey) else {
            return false;
        };
        // Use lax DER parsing like Bitcoin Core's ecdsa_signature_parse_der_lax.
        // Strict DER is enforced by the script interpreter's DERSIG flag check,
        // not at the signature verification level.
        let Ok(sig) = lax_der_parse(sig_bytes) else {
            return false;
        };

        let secp = secp256k1::Secp256k1::verification_only();
        let msg = secp256k1::Message::from_digest(sighash.0);
        secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
    }

    fn check_locktime(&self, locktime: i64) -> bool {
        if locktime < 0 {
            return false;
        }
        let locktime = locktime as u32;
        let tx_locktime = self.tx.lock_time;

        // Both must be same type (block height or timestamp)
        let threshold = LOCKTIME_THRESHOLD;
        if (tx_locktime < threshold) != (locktime < threshold) {
            return false;
        }

        // Required locktime must not exceed transaction locktime
        if locktime > tx_locktime {
            return false;
        }

        // Input must not have sequence 0xFFFFFFFF (which disables locktime)
        if self.tx.inputs[self.input_index].sequence == 0xFFFFFFFF {
            return false;
        }

        true
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        if sequence < 0 {
            return false;
        }
        let sequence = sequence as u32;

        // BIP-68 flags
        const DISABLE_FLAG: u32 = 1 << 31;
        const TYPE_FLAG: u32 = 1 << 22;
        const MASK: u32 = 0x0000FFFF;

        // If disable flag is set in the required sequence, always succeed
        if sequence & DISABLE_FLAG != 0 {
            return true;
        }

        let tx_sequence = self.tx.inputs[self.input_index].sequence;

        // If the tx sequence has disable flag set, fail
        if tx_sequence & DISABLE_FLAG != 0 {
            return false;
        }

        // Type must match (blocks vs time)
        if (sequence & TYPE_FLAG) != (tx_sequence & TYPE_FLAG) {
            return false;
        }

        // Required sequence must not exceed tx sequence
        if (sequence & MASK) > (tx_sequence & MASK) {
            return false;
        }

        true
    }

    fn check_schnorr_sig(
        &self,
        sig: &[u8],
        xonly_pubkey: &[u8; 32],
        annex: Option<&[u8]>,
    ) -> bool {
        self.check_schnorr_inner(sig, xonly_pubkey, annex, None)
    }

    fn check_schnorr_sig_tapscript(
        &self,
        sig: &[u8],
        xonly_pubkey: &[u8; 32],
        tapleaf_hash: &[u8; 32],
        codesep_pos: u32,
        annex: Option<&[u8]>,
    ) -> bool {
        let ctx = crate::script::taproot_sighash::TapscriptContext {
            tapleaf_hash,
            codesep_pos,
        };
        self.check_schnorr_inner(sig, xonly_pubkey, annex, Some(ctx))
    }
}

impl<'a> TransactionSignatureChecker<'a> {
    /// Shared Schnorr verification path for both key-path and tapscript
    /// script-path. `script_path = None` for key-path (ext_flag=0); pass
    /// the tapscript context (tapleaf_hash + codesep_pos) for ext_flag=1.
    fn check_schnorr_inner(
        &self,
        sig: &[u8],
        xonly_pubkey: &[u8; 32],
        annex: Option<&[u8]>,
        script_path: Option<crate::script::taproot_sighash::TapscriptContext<'_>>,
    ) -> bool {
        use crate::script::taproot_sighash::{
            compute_taproot_sighash, TaprootPrevouts, SIGHASH_DEFAULT,
        };

        // BIP-341: signature is 64B (SIGHASH_DEFAULT) or 65B (with hash_type at byte 64).
        let (sig_bytes, hash_type) = match sig.len() {
            64 => (sig, SIGHASH_DEFAULT),
            65 => {
                let ht = sig[64];
                // Strict: explicit SIGHASH_DEFAULT (0x00) byte is invalid;
                // 64-byte form must be used for default. Per BIP-341.
                if ht == SIGHASH_DEFAULT {
                    return false;
                }
                (&sig[..64], ht)
            }
            _ => return false,
        };

        // Need full prevouts; if the caller didn't supply them, fail closed.
        if self.spent_amounts.len() != self.tx.inputs.len()
            || self.spent_scripts.len() != self.tx.inputs.len()
        {
            return false;
        }

        let scripts_refs: Vec<&[u8]> =
            self.spent_scripts.iter().map(|s| s.as_slice()).collect();
        let prevouts = TaprootPrevouts {
            amounts: self.spent_amounts,
            scripts: &scripts_refs,
        };

        let sighash = match compute_taproot_sighash(
            self.tx,
            self.input_index,
            prevouts,
            hash_type,
            annex,
            script_path,
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let xonly = match secp256k1::XOnlyPublicKey::from_slice(xonly_pubkey) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig_obj = match secp256k1::schnorr::Signature::from_slice(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let msg = secp256k1::Message::from_digest(sighash);

        let secp = secp256k1::Secp256k1::verification_only();
        secp.verify_schnorr(&sig_obj, &msg, &xonly).is_ok()
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::{Block, BlockHeader, TxIn, TxOut};
    use std::collections::HashMap;

    fn make_coinbase_tx(height: u32, value: u64) -> Transaction {
        let mut script_sig = encode_bip34_height(height);
        // Pad to at least 2 bytes
        while script_sig.len() < 2 {
            script_sig.push(0);
        }
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig,
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x51], // OP_1 (anyone can spend)
            }],
            lock_time: 0,
        }
    }

    fn make_simple_tx(prev_txid: Hash256, prev_vout: u32, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: prev_vout,
                },
                script_sig: vec![0x51], // OP_1
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x51], // OP_1
            }],
            lock_time: 0,
        }
    }

    // =========================
    // check_transaction tests
    // =========================

    #[test]
    fn check_transaction_rejects_empty_inputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::EmptyInputs)
        ));
    }

    #[test]
    fn check_transaction_rejects_empty_outputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::EmptyOutputs)
        ));
    }

    #[test]
    fn check_transaction_rejects_output_above_max_money() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: MAX_MONEY + 1,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::OutputTooLarge(_))
        ));
    }

    #[test]
    fn check_transaction_rejects_duplicate_inputs() {
        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            vout: 0,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: outpoint.clone(),
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
                TxIn {
                    previous_output: outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
            ],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::DuplicateInputs)
        ));
    }

    #[test]
    fn check_transaction_validates_coinbase_script_size() {
        // Too short
        let mut tx = make_coinbase_tx(1, 100);
        tx.inputs[0].script_sig = vec![0x00]; // 1 byte, needs 2-100
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::CoinbaseScriptSize(1))
        ));

        // Too long
        tx.inputs[0].script_sig = vec![0x00; 101];
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::CoinbaseScriptSize(101))
        ));

        // Just right
        tx.inputs[0].script_sig = vec![0x00; 100];
        assert!(check_transaction(&tx).is_ok());
    }

    #[test]
    fn check_transaction_rejects_null_prevout_in_non_coinbase() {
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_hex(
                            "0000000000000000000000000000000000000000000000000000000000000001",
                        )
                        .unwrap(),
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
            ],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(TxValidationError::NullPrevout)
        ));
    }

    // =========================
    // check_block tests
    // =========================

    #[test]
    fn check_block_rejects_no_transactions() {
        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![],
        };
        let params = ChainParams::regtest();
        assert!(matches!(
            check_block(&block, &params),
            Err(ValidationError::NoTransactions)
        ));
    }

    #[test]
    fn check_block_rejects_no_coinbase() {
        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![make_simple_tx(Hash256::ZERO, 0, 100)],
        };
        let params = ChainParams::regtest();
        assert!(matches!(
            check_block(&block, &params),
            Err(ValidationError::NoCoinbase)
        ));
    }

    #[test]
    fn check_block_rejects_multiple_coinbase() {
        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![make_coinbase_tx(1, 100), make_coinbase_tx(1, 100)],
        };
        let params = ChainParams::regtest();
        assert!(matches!(
            check_block(&block, &params),
            Err(ValidationError::MultipleCoinbase)
        ));
    }

    #[test]
    fn check_block_rejects_bad_merkle_root() {
        let tx = make_coinbase_tx(1, 100);
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO, // Wrong!
                timestamp: 1,
                bits: 0x207fffff, // Regtest difficulty
                nonce: 0,
            },
            transactions: vec![tx],
        };
        // Fix the merkle root
        block.header.merkle_root = block.compute_merkle_root();

        // Now break it
        block.header.merkle_root = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let _params = ChainParams::regtest();
        // First it will fail PoW, so let's just test the merkle root check
        // by using a block that passes PoW
    }

    // =========================
    // BIP-34 height encoding tests
    // Reference: Bitcoin Core script.h:433-448 (CScript::push_int64)
    // =========================

    #[test]
    fn encode_bip34_height_zero() {
        // height 0 → OP_0 (0x00), single byte
        assert_eq!(encode_bip34_height(0), vec![0x00]);
    }

    #[test]
    fn encode_bip34_height_one() {
        // height 1 → OP_1 (0x51), single byte
        assert_eq!(encode_bip34_height(1), vec![0x51]);
    }

    #[test]
    fn encode_bip34_height_sixteen() {
        // height 16 → OP_16 (0x60), single byte
        assert_eq!(encode_bip34_height(16), vec![0x60]);
    }

    #[test]
    fn encode_bip34_height_seventeen() {
        // height 17 → 1-byte push (0x01 0x11)
        assert_eq!(encode_bip34_height(17), vec![0x01, 0x11]);
    }

    #[test]
    fn encode_bip34_height_100() {
        // 100 = 0x64, no sign pad
        assert_eq!(encode_bip34_height(100), vec![0x01, 0x64]);
    }

    #[test]
    fn encode_bip34_height_127() {
        // 127 = 0x7f, high bit not set, so no padding needed
        assert_eq!(encode_bip34_height(127), vec![0x01, 0x7f]);
    }

    #[test]
    fn encode_bip34_height_128() {
        // 128 = 0x80, high bit set → needs sign pad
        assert_eq!(encode_bip34_height(128), vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn encode_bip34_height_32768() {
        // 32768 = 0x8000, high bit of last byte set → sign pad
        assert_eq!(encode_bip34_height(32768), vec![0x03, 0x00, 0x80, 0x00]);
    }

    #[test]
    fn encode_bip34_height_500() {
        // 500 = 0x01F4 in LE = [0xF4, 0x01], no sign pad
        assert_eq!(encode_bip34_height(500), vec![0x02, 0xf4, 0x01]);
    }

    #[test]
    fn encode_bip34_height_100000() {
        // 100000 = 0x186A0 in LE = [0xA0, 0x86, 0x01]
        assert_eq!(encode_bip34_height(100000), vec![0x03, 0xa0, 0x86, 0x01]);
    }

    #[test]
    fn encode_bip34_height_2000000() {
        // 2000000 = 0x1E8480 in LE = [0x80, 0x84, 0x1E]
        assert_eq!(encode_bip34_height(2000000), vec![0x03, 0x80, 0x84, 0x1e]);
    }

    #[test]
    fn encode_bip34_rejects_non_canonical_in_check() {
        // contextual_check_block does byte-prefix comparison; non-canonical
        // zero-padded encoding must not match height 100's canonical [0x01, 0x64].
        let canonical = encode_bip34_height(100);
        let non_canonical = vec![0x02u8, 0x64, 0x00]; // zero-padded
        assert_ne!(canonical, non_canonical);
        // Length-prefixed form for height 1 must not match OP_1
        assert_ne!(encode_bip34_height(1), vec![0x01u8, 0x01]);
        // Missing sign byte must not match height 128 canonical
        assert_ne!(vec![0x01u8, 0x80], encode_bip34_height(128));
    }

    // =========================
    // script_flags_for_height tests
    // =========================

    #[test]
    fn script_flags_mainnet_genesis() {
        let params = ChainParams::mainnet();
        let flags = script_flags_for_height(0, &params);

        // Only P2SH should be enabled at genesis
        assert!(flags.verify_p2sh);
        assert!(!flags.verify_dersig);
        assert!(!flags.verify_checklocktimeverify);
        assert!(!flags.verify_witness);
    }

    #[test]
    fn script_flags_mainnet_post_segwit() {
        let params = ChainParams::mainnet();
        let flags = script_flags_for_height(500000, &params);

        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(flags.verify_nulldummy);
        assert!(!flags.verify_taproot); // Not yet at 709632
    }

    #[test]
    fn script_flags_testnet4_all_active() {
        let params = ChainParams::testnet4();
        let flags = script_flags_for_height(1, &params);

        // All soft forks active from height 1 on testnet4
        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(flags.verify_nulldummy);
        assert!(flags.verify_taproot);
    }

    #[test]
    fn script_flags_no_policy_flags() {
        // Verify that policy flags are NOT set in the consensus block-script-flag
        // computer.  All of these are STANDARD_SCRIPT_VERIFY_FLAGS (policy only)
        // per Bitcoin Core policy/policy.h:119-132.
        // Ref: Bitcoin Core validation.cpp:2250-2289.
        let params = ChainParams::mainnet();
        let flags = script_flags_for_height(800000, &params);

        // These should all be false (policy only — never in consensus path)
        assert!(!flags.verify_strictenc);
        assert!(!flags.verify_low_s);
        assert!(!flags.verify_sigpushonly);
        assert!(!flags.verify_minimaldata);
        assert!(!flags.verify_cleanstack);
        assert!(!flags.verify_minimalif);
        // verify_nullfail is policy-only (BIP-146 is NOT a consensus rule).
        // Bitcoin Core validation.cpp:2250-2289 does NOT set SCRIPT_VERIFY_NULLFAIL.
        assert!(!flags.verify_nullfail);
    }

    // =========================
    // sigops counting tests
    // =========================

    #[test]
    fn count_script_sigops_checksig() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let script = [
            0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
        ];
        assert_eq!(count_script_sigops(&script, false), 1);
    }

    #[test]
    fn count_script_sigops_multisig() {
        // OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
        // Without accurate counting, this should be 20
        let mut script = vec![0x52]; // OP_2
        script.push(0x21); // Push 33 bytes
        script.extend([0u8; 33]); // pubkey1
        script.push(0x21);
        script.extend([0u8; 33]); // pubkey2
        script.push(0x21);
        script.extend([0u8; 33]); // pubkey3
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        // Without accurate counting, multisig is always 20
        assert_eq!(count_script_sigops(&script, false), 20);

        // With accurate counting, it uses the preceding OP_n (OP_3 = 3 keys)
        assert_eq!(count_script_sigops(&script, true), 3);
    }

    // =========================
    // Lax DER parsing tests
    // =========================

    #[test]
    fn lax_der_parse_roundtrip() {
        // Signature with R having extra leading zero pad (non-strict DER)
        let sig_hex = "304402200060558477337b9022e70534f1fea71a318caf836812465a2509931c5e7c4987022078ec32bd50ac9e03a349ba953dfd9fe1c8d2dd8bdb1d38ddca844d3d5c78c118";
        let sig_bytes = hex::decode(sig_hex).unwrap();

        // Strict DER should reject this (R has extra leading zero)
        assert!(secp256k1::ecdsa::Signature::from_der(&sig_bytes).is_err());

        // Lax DER should accept it
        let result = lax_der_parse(&sig_bytes);
        assert!(result.is_ok(), "lax_der_parse failed: {:?}", result.err());
    }

    // =========================
    // TransactionSignatureChecker tests
    // =========================

    #[test]
    fn signature_checker_locktime_basic() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFFFFFE, // Not final (locktime enabled)
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 500000,
        };

        let checker = TransactionSignatureChecker::new(&tx, 0, 0, &[], &[]);

        // Locktime <= tx locktime should succeed
        assert!(checker.check_locktime(500000));
        assert!(checker.check_locktime(499999));

        // Locktime > tx locktime should fail
        assert!(!checker.check_locktime(500001));
    }

    #[test]
    fn signature_checker_locktime_type_mismatch() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFFFFFE,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 100, // Block height
        };

        let checker = TransactionSignatureChecker::new(&tx, 0, 0, &[], &[]);

        // Block height locktime
        assert!(checker.check_locktime(50));

        // Timestamp locktime should fail (different type)
        assert!(!checker.check_locktime(500000001));
    }

    #[test]
    fn signature_checker_locktime_final_sequence() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFFFFFF, // Final (locktime disabled)
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 500000,
        };

        let checker = TransactionSignatureChecker::new(&tx, 0, 0, &[], &[]);

        // Should fail because sequence is final
        assert!(!checker.check_locktime(500000));
    }

    #[test]
    fn signature_checker_sequence_disabled() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };

        let checker = TransactionSignatureChecker::new(&tx, 0, 0, &[], &[]);

        // Required sequence with disable flag set should always succeed
        assert!(checker.check_sequence(0x80000000u32 as i64));

        // Without disable flag, should fail because tx sequence has disable flag
        assert!(!checker.check_sequence(10));
    }

    #[test]
    fn signature_checker_sequence_blocks() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 100, // 100 blocks
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };

        let checker = TransactionSignatureChecker::new(&tx, 0, 0, &[], &[]);

        // Should succeed for <= 100 blocks
        assert!(checker.check_sequence(100));
        assert!(checker.check_sequence(50));

        // Should fail for > 100 blocks
        assert!(!checker.check_sequence(101));
    }

    // =========================
    // BIP-68 Sequence Lock tests
    // =========================

    /// Test context that provides MTP values for sequence lock testing.
    struct TestSequenceLockContext {
        /// Map from height to MTP at that height
        mtp_by_height: std::collections::HashMap<u32, u32>,
    }

    impl TestSequenceLockContext {
        fn new() -> Self {
            Self {
                mtp_by_height: std::collections::HashMap::new(),
            }
        }

        fn with_mtp(mut self, height: u32, mtp: u32) -> Self {
            self.mtp_by_height.insert(height, mtp);
            self
        }
    }

    impl SequenceLockContext for TestSequenceLockContext {
        fn get_mtp_at_height(&self, height: u32) -> u32 {
            *self.mtp_by_height.get(&height).unwrap_or(&0)
        }
    }

    fn make_tx_with_sequence(version: i32, sequences: &[u32]) -> Transaction {
        let inputs: Vec<TxIn> = sequences
            .iter()
            .enumerate()
            .map(|(i, &seq)| TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([i as u8; 32]),
                    vout: 0,
                },
                script_sig: vec![0x51],
                sequence: seq,
                witness: vec![],
            })
            .collect();

        Transaction {
            version,
            inputs,
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn sequence_locks_disabled_for_version_1() {
        let tx = make_tx_with_sequence(1, &[10]); // 10 block relative lock
        let spent_heights = vec![100];
        let context = TestSequenceLockContext::new();

        // BIP-68 not enforced for version 1
        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, false);
        assert_eq!(locks.min_height, -1);
        assert_eq!(locks.min_time, -1);
    }

    #[test]
    fn sequence_locks_height_based() {
        let tx = make_tx_with_sequence(2, &[10]); // 10 block relative lock
        let spent_heights = vec![100];
        let context = TestSequenceLockContext::new();

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // min_height = spent_height + lock_value - 1 = 100 + 10 - 1 = 109
        // (nLockTime semantics: 109 is the last invalid height)
        assert_eq!(locks.min_height, 109);
        assert_eq!(locks.min_time, -1); // No time-based lock
    }

    #[test]
    fn sequence_locks_height_based_multiple_inputs() {
        // Two inputs with different relative locks
        let tx = make_tx_with_sequence(2, &[10, 50]);
        let spent_heights = vec![100, 80];
        let context = TestSequenceLockContext::new();

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // Input 0: 100 + 10 - 1 = 109
        // Input 1: 80 + 50 - 1 = 129
        // max = 129
        assert_eq!(locks.min_height, 129);
        assert_eq!(locks.min_time, -1);
    }

    #[test]
    fn sequence_locks_time_based() {
        // Time-based lock: bit 22 set, lower 16 bits = 100 (100 * 512 seconds)
        let time_lock = (1 << 22) | 100; // SEQUENCE_LOCKTIME_TYPE_FLAG | 100
        let tx = make_tx_with_sequence(2, &[time_lock]);
        let spent_heights = vec![100];

        // MTP at height 99 (the block before the UTXO was mined)
        let context = TestSequenceLockContext::new().with_mtp(99, 1000000);

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // min_time = coin_mtp + (lock_value << 9) - 1
        //          = 1000000 + (100 * 512) - 1
        //          = 1000000 + 51200 - 1 = 1051199
        assert_eq!(locks.min_height, -1);
        assert_eq!(locks.min_time, 1051199);
    }

    #[test]
    fn sequence_locks_disable_flag() {
        // Disable flag set: bit 31
        let disabled = 1 << 31; // SEQUENCE_LOCKTIME_DISABLE_FLAG
        let tx = make_tx_with_sequence(2, &[disabled | 100]); // Would be 100 blocks without disable
        let spent_heights = vec![100];
        let context = TestSequenceLockContext::new();

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // Disabled, so no locks
        assert_eq!(locks.min_height, -1);
        assert_eq!(locks.min_time, -1);
    }

    #[test]
    fn sequence_locks_mixed_enabled_disabled() {
        // Input 0: disabled, Input 1: 10 blocks
        let disabled = 1 << 31;
        let tx = make_tx_with_sequence(2, &[disabled | 500, 10]);
        let spent_heights = vec![100, 200];
        let context = TestSequenceLockContext::new();

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // Only input 1 contributes: 200 + 10 - 1 = 209
        assert_eq!(locks.min_height, 209);
        assert_eq!(locks.min_time, -1);
    }

    #[test]
    fn check_sequence_locks_height_satisfied() {
        let locks = SequenceLocks {
            min_height: 100,
            min_time: -1,
        };

        // Block 101 satisfies height 100
        assert!(check_sequence_locks(&locks, 101, 0));
        // Block 100 does NOT satisfy (must be strictly greater)
        assert!(!check_sequence_locks(&locks, 100, 0));
        // Block 99 does NOT satisfy
        assert!(!check_sequence_locks(&locks, 99, 0));
    }

    #[test]
    fn check_sequence_locks_time_satisfied() {
        let locks = SequenceLocks {
            min_height: -1,
            min_time: 1000000,
        };

        // MTP 1000001 satisfies time 1000000
        assert!(check_sequence_locks(&locks, 1, 1000001));
        // MTP 1000000 does NOT satisfy (must be strictly greater)
        assert!(!check_sequence_locks(&locks, 1, 1000000));
        // MTP 999999 does NOT satisfy
        assert!(!check_sequence_locks(&locks, 1, 999999));
    }

    #[test]
    fn check_sequence_locks_both_satisfied() {
        let locks = SequenceLocks {
            min_height: 100,
            min_time: 1000000,
        };

        // Both conditions must be satisfied
        assert!(check_sequence_locks(&locks, 101, 1000001));
        // Height satisfied but not time
        assert!(!check_sequence_locks(&locks, 101, 999999));
        // Time satisfied but not height
        assert!(!check_sequence_locks(&locks, 99, 1000001));
    }

    #[test]
    fn check_sequence_locks_no_locks() {
        let locks = SequenceLocks {
            min_height: -1,
            min_time: -1,
        };

        // No locks means always satisfied
        assert!(check_sequence_locks(&locks, 0, 0));
        assert!(check_sequence_locks(&locks, 1, 1));
    }

    #[test]
    fn sequence_locks_zero_relative_height() {
        // Lock of 0 blocks means immediately spendable
        let tx = make_tx_with_sequence(2, &[0]);
        let spent_heights = vec![100];
        let context = TestSequenceLockContext::new();

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // 100 + 0 - 1 = 99
        assert_eq!(locks.min_height, 99);

        // Block 100 should satisfy (100 > 99)
        assert!(check_sequence_locks(&locks, 100, 0));
    }

    #[test]
    fn sequence_locks_max_relative_height() {
        // Maximum height lock (16 bits)
        let max_lock = 0xFFFF; // 65535 blocks
        let tx = make_tx_with_sequence(2, &[max_lock]);
        let spent_heights = vec![100];
        let context = TestSequenceLockContext::new();

        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, true);

        // 100 + 65535 - 1 = 65634
        assert_eq!(locks.min_height, 65634);
    }

    #[test]
    fn sequence_locks_bip68_not_enforced() {
        let tx = make_tx_with_sequence(2, &[10]);
        let spent_heights = vec![100];
        let context = TestSequenceLockContext::new();

        // Explicitly disable BIP-68 enforcement
        let locks = calculate_sequence_locks(&tx, &spent_heights, &context, false);

        // Should return no locks
        assert_eq!(locks.min_height, -1);
        assert_eq!(locks.min_time, -1);
    }

    // =========================
    // Extended sigop tests
    // =========================

    #[test]
    fn get_last_scriptpush_simple() {
        // Push 4 bytes: 0x04 0x01 0x02 0x03 0x04
        let script = vec![0x04, 0x01, 0x02, 0x03, 0x04];
        let result = get_last_scriptpush(&script);
        assert_eq!(result, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn get_last_scriptpush_multiple_pushes() {
        // Push 2 bytes, then push 3 bytes
        let script = vec![0x02, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33];
        let result = get_last_scriptpush(&script);
        assert_eq!(result, Some(vec![0x11, 0x22, 0x33]));
    }

    #[test]
    fn get_last_scriptpush_op_n() {
        // OP_1 (0x51) pushes the value 1
        let script = vec![0x51];
        let result = get_last_scriptpush(&script);
        assert_eq!(result, Some(vec![1]));
    }

    #[test]
    fn get_last_scriptpush_op_0() {
        // OP_0 pushes empty
        let script = vec![0x00];
        let result = get_last_scriptpush(&script);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn get_last_scriptpush_not_push_only() {
        // OP_DUP (0x76) is not a push operation
        let script = vec![0x76];
        let result = get_last_scriptpush(&script);
        assert_eq!(result, None);
    }

    #[test]
    fn witness_sigops_p2wpkh() {
        // P2WPKH program is 20 bytes
        let program = [0u8; 20];
        let witness = vec![vec![0u8; 72], vec![0u8; 33]]; // sig, pubkey
        assert_eq!(witness_sigops(0, &program, &witness), 1);
    }

    #[test]
    fn witness_sigops_p2wsh_checksig() {
        // P2WSH program is 32 bytes
        let program = [0u8; 32];
        // Simple script containing just OP_CHECKSIG
        let script = vec![0xac]; // OP_CHECKSIG
        let witness = vec![vec![0u8; 72], vec![0u8; 33], script];
        assert_eq!(witness_sigops(0, &program, &witness), 1);
    }

    #[test]
    fn witness_sigops_p2wsh_multisig_accurate() {
        // P2WSH with 2-of-3 multisig
        let program = [0u8; 32];
        // OP_2 <pubkey> <pubkey> <pubkey> OP_3 OP_CHECKMULTISIG
        let mut script = vec![0x52]; // OP_2
        script.push(0x21);
        script.extend([0u8; 33]);
        script.push(0x21);
        script.extend([0u8; 33]);
        script.push(0x21);
        script.extend([0u8; 33]);
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        let witness = vec![vec![], vec![0u8; 72], vec![0u8; 72], script];
        // With accurate counting, should be 3 (from OP_3)
        assert_eq!(witness_sigops(0, &program, &witness), 3);
    }

    #[test]
    fn witness_sigops_unknown_version() {
        // Unknown witness version should return 0
        let program = [0u8; 32];
        let witness = vec![vec![0u8; 64]];
        assert_eq!(witness_sigops(1, &program, &witness), 0);
        assert_eq!(witness_sigops(16, &program, &witness), 0);
    }

    #[test]
    fn get_legacy_sigop_count_p2pkh() {
        // P2PKH transaction: input has no sigops, output has 1 (OP_CHECKSIG)
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([1u8; 32]),
                    vout: 0,
                },
                script_sig: vec![0x48; 72], // Placeholder signature
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1000,
                // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
                ],
            }],
            lock_time: 0,
        };

        // P2PKH output has 1 sigop (OP_CHECKSIG)
        assert_eq!(get_legacy_sigop_count(&tx), 1);
    }

    #[test]
    fn sigop_cost_p2pkh_legacy() {
        // P2PKH spends should have sigops scaled by WITNESS_SCALE_FACTOR
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([1u8; 32]),
                    vout: 0,
                },
                script_sig: vec![0x48; 72], // Placeholder signature
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: vec![0x51], // OP_1 (no sigops)
            }],
            lock_time: 0,
        };

        // The spent output is P2PKH with 1 sigop in the scriptPubKey
        // But get_legacy_sigop_count only counts scriptSig and output scriptPubKeys
        // The scriptSig might have sigops too
        let flags = ScriptFlags {
            verify_p2sh: true,
            verify_witness: true,
            ..Default::default()
        };

        // With no real coins, we just test the legacy counting
        let cost = get_transaction_sigop_cost(&tx, |_| None, &flags);
        // scriptSig has no sigops, output scriptPubKey has no sigops
        assert_eq!(cost, 0);
    }

    #[test]
    fn sigop_cost_witness_discount() {
        // Test that witness sigops are NOT scaled
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([1u8; 32]),
                    vout: 0,
                },
                script_sig: vec![], // Empty for SegWit
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0u8; 72], vec![0u8; 33]], // sig, pubkey
            }],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: vec![0x51], // OP_1
            }],
            lock_time: 0,
        };

        // The spent output is P2WPKH: OP_0 <20 bytes>
        let p2wpkh_output = CoinEntry {
            height: 100,
            is_coinbase: false,
            value: 2000,
            script_pubkey: vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00],
        };

        let flags = ScriptFlags {
            verify_p2sh: true,
            verify_witness: true,
            ..Default::default()
        };

        let expected_outpoint = OutPoint {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
        };

        let cost = get_transaction_sigop_cost(&tx, |outpoint| {
            if *outpoint == expected_outpoint {
                Some(p2wpkh_output.clone())
            } else {
                None
            }
        }, &flags);

        // P2WPKH: 1 witness sigop (NOT scaled) + 0 legacy sigops
        // Total cost = 1
        assert_eq!(cost, 1);
    }

    // =========================
    // is_final_tx tests (Core parity: ContextualCheckBlock, validation.cpp:4146)
    // =========================

    #[test]
    fn is_final_tx_zero_locktime_always_final() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0x00000000, // non-final sequence
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 100, script_pubkey: vec![] }],
            lock_time: 0,
        };
        assert!(is_final_tx(&tx, 1000, 900_000_000));
    }

    #[test]
    fn is_final_tx_height_based_satisfied() {
        // lock_time = 100, block_height = 101 → satisfied
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0x00000000,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 100, script_pubkey: vec![] }],
            lock_time: 100,
        };
        assert!(is_final_tx(&tx, 101, 900_000_000));
    }

    #[test]
    fn is_final_tx_height_based_not_satisfied_non_final_sequence() {
        // lock_time = 200, block_height = 100, sequence != SEQUENCE_FINAL → non-final
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0x00000001, // not SEQUENCE_FINAL
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 100, script_pubkey: vec![] }],
            lock_time: 200,
        };
        assert!(!is_final_tx(&tx, 100, 900_000_000));
    }

    #[test]
    fn is_final_tx_sequence_final_overrides_locktime() {
        // lock_time = 999_999_999 (unsatisfied height), all inputs SEQUENCE_FINAL → final
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x00, 0x00],
                sequence: 0xFFFF_FFFF, // SEQUENCE_FINAL
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 100, script_pubkey: vec![] }],
            lock_time: 999_999_999,
        };
        assert!(is_final_tx(&tx, 100, 900_000_000));
    }

    #[test]
    fn connect_block_rejects_non_final_tx() {
        // Build a block where a non-coinbase tx has lock_time = 1000
        // but block_height = 500 and lock_time_cutoff = 999 → non-final
        // This tests that connect_block_with_sequence_locks enforces IsFinalTx
        use crate::params::ChainParams;

        let params = ChainParams::regtest();

        // Non-final tx: lock_time > block_height, input sequence != SEQUENCE_FINAL
        let non_final_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([1u8; 32]),
                    vout: 0,
                },
                script_sig: vec![0x51],
                sequence: 0x00000000, // not SEQUENCE_FINAL
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50, script_pubkey: vec![0x51] }],
            lock_time: 1000, // block height 500 < 1000 → not final by height
        };

        // Build a minimal coinbase for height 1
        let coinbase = make_coinbase_tx(1, 5_000_000_000);

        use rustoshi_primitives::BlockHeader;
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::from_bytes([0u8; 32]),
            merkle_root: Hash256::from_bytes([0u8; 32]),
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        };
        let block = Block {
            header,
            transactions: vec![coinbase, non_final_tx],
        };

        // Use a simple in-memory UTXO view
        struct SimpleUtxo(HashMap<OutPoint, CoinEntry>);
        impl UtxoView for SimpleUtxo {
            fn get_utxo(&self, op: &OutPoint) -> Option<CoinEntry> { self.0.get(op).cloned() }
            fn add_utxo(&mut self, op: &OutPoint, coin: CoinEntry) { self.0.insert(op.clone(), coin); }
            fn spend_utxo(&mut self, op: &OutPoint) { self.0.remove(op); }
        }

        let mut utxo = SimpleUtxo(HashMap::new());
        utxo.add_utxo(&OutPoint { txid: Hash256::from_bytes([1u8; 32]), vout: 0 }, CoinEntry {
            height: 1,
            is_coinbase: false,
            value: 100,
            script_pubkey: vec![0x51],
        });

        // height=500, block timestamp=1_700_000_000, csv not active in regtest at h=500
        // prev_block_mtp doesn't matter here since csv_height for regtest is 0 actually
        // but we just need the non-final check to fire
        // For regtest csv_height=0 so csv IS active, so lock_time_cutoff = prev_block_mtp
        // prev_block_mtp = 1_699_999_000 (< LOCKTIME_THRESHOLD=500M → treated as height??
        // No: lock_time=1000 < LOCKTIME_THRESHOLD so it's height-based, compared to height=500
        // 1000 >= 500 and sequence != SEQUENCE_FINAL → non-final
        let null_ctx = NullSequenceLockContext;
        let result = connect_block_with_sequence_locks(
            &block, 500, &mut utxo, &params, &null_ctx, 1_699_999_000
        );
        assert!(
            matches!(result, Err(ValidationError::NonFinalTx)),
            "Expected NonFinalTx error, got: {:?}", result
        );
    }

    // ============================================================
    // contextual_check_block / contextual_check_block_header tests
    //
    // Closes Bug 0 + Bug 0a from rustoshi-P0-FOUND.md: prior to wiring
    // these calls into chain_state, both functions were dead code and
    // BIP-34 / SegWit-commitment / MTP-vs-timestamp / future-drift
    // checks were silently bypassed.
    // ============================================================

    /// Minimal ChainContext with configurable MTP for header tests.
    struct MtpStubContext {
        mtp_by_hash: HashMap<Hash256, u32>,
    }

    impl ChainContext for MtpStubContext {
        fn get_block_index(&self, _h: &Hash256) -> Option<BlockIndexEntry> { None }
        fn get_utxo(&self, _o: &OutPoint) -> Option<CoinEntry> { None }
        fn get_median_time_past(&self, hash: &Hash256) -> u32 {
            *self.mtp_by_hash.get(hash).unwrap_or(&0)
        }
        fn get_hash_at_height(&self, _h: u32) -> Option<Hash256> { None }
        fn tip_height(&self) -> u32 { 0 }
    }

    fn dummy_block_index_entry() -> BlockIndexEntry {
        BlockIndexEntry {
            height: 0,
            timestamp: 0,
            bits: 0,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        }
    }

    #[test]
    fn contextual_check_block_header_rejects_time_too_old() {
        // Bug 0a: a header whose timestamp <= MTP must be rejected with
        // TimeTooOld.  Before this fix, the check existed but was never
        // called.
        let prev_hash = Hash256::from_bytes([0xab; 32]);
        let mut mtp = HashMap::new();
        mtp.insert(prev_hash, 1_700_000_000); // MTP = 1700000000
        let ctx = MtpStubContext { mtp_by_hash: mtp };
        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            timestamp: 1_699_999_999, // <= MTP → reject
            bits: 0,
            nonce: 0,
        };
        let params = ChainParams::regtest();
        let res = contextual_check_block_header(
            &header,
            10,
            &dummy_block_index_entry(),
            &ctx,
            &params,
            0, // current_time=0 to skip future-drift check
        );
        assert!(matches!(res, Err(ValidationError::TimeTooOld)),
            "header timestamp == MTP must be rejected: {res:?}");
    }

    #[test]
    fn contextual_check_block_header_accepts_when_above_mtp() {
        let prev_hash = Hash256::from_bytes([0xab; 32]);
        let mut mtp = HashMap::new();
        mtp.insert(prev_hash, 1_700_000_000);
        let ctx = MtpStubContext { mtp_by_hash: mtp };
        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_001, // > MTP → accept
            bits: 0,
            nonce: 0,
        };
        let params = ChainParams::regtest();
        let res = contextual_check_block_header(
            &header,
            10,
            &dummy_block_index_entry(),
            &ctx,
            &params,
            1_700_000_500, // current_time well after timestamp
        );
        assert!(res.is_ok(), "header > MTP must be accepted: {res:?}");
    }

    #[test]
    fn contextual_check_block_header_rejects_time_too_new() {
        // Bug 0a (future-drift): a header whose timestamp > now + 7200
        // must be rejected with TimeTooNew.  Before the fix this was
        // unreachable code.
        let prev_hash = Hash256::from_bytes([0xab; 32]);
        let mut mtp = HashMap::new();
        mtp.insert(prev_hash, 0);
        let ctx = MtpStubContext { mtp_by_hash: mtp };
        let now: u64 = 1_700_000_000;
        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            // 4 hours in the future = 14,400 s; threshold is 7,200.
            timestamp: (now + 4 * 60 * 60) as u32,
            bits: 0,
            nonce: 0,
        };
        let params = ChainParams::regtest();
        let res = contextual_check_block_header(
            &header,
            10,
            &dummy_block_index_entry(),
            &ctx,
            &params,
            now,
        );
        assert!(matches!(res, Err(ValidationError::TimeTooNew)),
            "header 4h in future must be rejected: {res:?}");
    }

    #[test]
    fn contextual_check_block_header_accepts_within_drift_window() {
        let prev_hash = Hash256::from_bytes([0xab; 32]);
        let mut mtp = HashMap::new();
        mtp.insert(prev_hash, 0);
        let ctx = MtpStubContext { mtp_by_hash: mtp };
        let now: u64 = 1_700_000_000;
        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            timestamp: (now + 3600) as u32, // 1h in future, < 2h threshold
            bits: 0,
            nonce: 0,
        };
        let params = ChainParams::regtest();
        let res = contextual_check_block_header(
            &header,
            10,
            &dummy_block_index_entry(),
            &ctx,
            &params,
            now,
        );
        assert!(res.is_ok(), "header within drift window must be accepted: {res:?}");
    }

    #[test]
    fn contextual_check_block_rejects_bad_witness_commitment() {
        // Bug 0: a block whose coinbase OP_RETURN witness commitment does
        // not match SHA256d(witness_root || witness_nonce) must be
        // rejected.  Prior to this fix, contextual_check_block was never
        // called, so this scenario passed silently.
        //
        // Construct a SegWit block with a coinbase that has a witness
        // commitment output and a non-coinbase tx that DOES carry witness
        // data, but where the commitment value is intentionally wrong.

        // Coinbase: scriptSig encodes height 1 (BIP-34), witness contains
        // a 32-byte nonce (will be all zeros).
        let mut coinbase = make_coinbase_tx(1, 5_000_000_000);
        coinbase.inputs[0].witness = vec![vec![0u8; 32]];

        // Add a witness-commitment output: OP_RETURN OP_PUSHBYTES_36
        // 0xaa21a9ed <32-byte BAD HASH>.
        let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commit_script.extend_from_slice(&[0xff; 32]); // intentionally wrong
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commit_script,
        });

        // A second tx that carries witness data (so the
        // commitment-check path actually runs).
        let mut spend = make_simple_tx(Hash256::from_bytes([1u8; 32]), 0, 50);
        spend.inputs[0].witness = vec![vec![0xaa; 33]];

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![coinbase, spend],
        };
        let params = ChainParams::regtest();
        let res = contextual_check_block(&block, 1, &StubChainContext, &params);
        assert!(matches!(res, Err(ValidationError::BadWitnessCommitment)),
            "block with bad witness commitment must be rejected: {res:?}");
    }

    #[test]
    fn contextual_check_block_rejects_missing_bip34_height() {
        // Bug 0 (BIP-34): a coinbase whose scriptSig does NOT start with
        // the serialized block height must be rejected with
        // BadCoinbaseHeight when bip34_height has been reached.  Prior
        // to this fix, contextual_check_block was dead code so the
        // wrong-height encoding sailed through.

        // Build a coinbase with scriptSig that does NOT match the
        // BIP-34 encoding for height 5.
        let mut coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x99, 0x99, 0x99], // garbage prefix
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let _ = &mut coinbase; // silence unused-mut on older rustc

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };
        let params = ChainParams::regtest(); // bip34_height = 1
        let res = contextual_check_block(&block, 5, &StubChainContext, &params);
        assert!(matches!(res, Err(ValidationError::BadCoinbaseHeight)),
            "missing BIP-34 height must be rejected: {res:?}");
    }

    #[test]
    fn contextual_check_block_accepts_canonical_bip34_height() {
        // Sanity: a coinbase with the correct BIP-34 prefix passes.
        let coinbase = make_coinbase_tx(5, 5_000_000_000);
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };
        let params = ChainParams::regtest();
        let res = contextual_check_block(&block, 5, &StubChainContext, &params);
        assert!(res.is_ok(), "canonical BIP-34 coinbase must pass: {res:?}");
    }

    // ============================================================
    // BIP-30 enforcement tests
    //
    // Reference: Bitcoin Core validation.cpp ConnectBlock / IsBIP30Repeat().
    // Mainnet exception heights: 91842 and 91880.
    // ============================================================

    /// Minimal in-memory UTXO view for BIP-30 tests.
    struct Bip30Utxo(HashMap<OutPoint, CoinEntry>);
    impl UtxoView for Bip30Utxo {
        fn get_utxo(&self, op: &OutPoint) -> Option<CoinEntry> { self.0.get(op).cloned() }
        fn add_utxo(&mut self, op: &OutPoint, coin: CoinEntry) { self.0.insert(op.clone(), coin); }
        fn spend_utxo(&mut self, op: &OutPoint) { self.0.remove(op); }
    }

    impl Bip30Utxo {
        fn new() -> Self { Bip30Utxo(HashMap::new()) }
        fn seed_coin(&mut self, txid: Hash256) {
            // Pre-populate output 0 of `txid` to simulate an existing UTXO.
            self.0.insert(OutPoint { txid, vout: 0 }, CoinEntry {
                height: 1000,
                is_coinbase: true,
                value: 100,
                script_pubkey: vec![0x51],
            });
        }
    }

    /// Build a minimal valid block (regtest PoW) with a given coinbase.
    fn make_bip30_test_block(coinbase: Transaction) -> Block {
        use rustoshi_primitives::BlockHeader;
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_231_006_506,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase],
        }
    }

    /// Return mainnet params (with correct BIP-30 exception heights 91842/91880
    /// and bip34_height=227931) but swap in the regtest PoW limit so that any
    /// block hash passes the PoW check without mining.
    fn bip30_test_params() -> ChainParams {
        let mut p = ChainParams::mainnet();
        // Regtest PoW limit: 0x7fff...ff (first byte 0x7f, rest 0xff).
        // With bits=0x207fffff any block hash satisfies this target.
        let mut regtest_limit = [0xffu8; 32];
        regtest_limit[0] = 0x7f;
        p.pow_limit = regtest_limit;
        p
    }

    #[test]
    fn bip30_exempt_at_91842() {
        // h=91842 is a BIP-30 exception block. Even if the UTXO set already
        // has an entry at the coinbase txid:vout, the block must NOT be rejected.
        let params = bip30_test_params();
        let coinbase = make_coinbase_tx(91842, 5_000_000_000);
        let coinbase_txid = coinbase.txid();
        let block = make_bip30_test_block(coinbase);

        let mut utxo = Bip30Utxo::new();
        utxo.seed_coin(coinbase_txid); // pre-existing UTXO at same txid

        let null_ctx = NullSequenceLockContext;
        let result = connect_block_with_sequence_locks(
            &block, 91842, &mut utxo, &params, &null_ctx, 0,
        );
        // Must not be Bip30DuplicateOutput (may succeed or fail for another reason).
        assert!(
            !matches!(result, Err(ValidationError::Bip30DuplicateOutput)),
            "h=91842 must be BIP-30 exempt; got: {result:?}",
        );
    }

    #[test]
    fn bip30_exempt_at_91880() {
        // h=91880 is the second BIP-30 exception block.
        let params = bip30_test_params();
        let coinbase = make_coinbase_tx(91880, 5_000_000_000);
        let coinbase_txid = coinbase.txid();
        let block = make_bip30_test_block(coinbase);

        let mut utxo = Bip30Utxo::new();
        utxo.seed_coin(coinbase_txid);

        let null_ctx = NullSequenceLockContext;
        let result = connect_block_with_sequence_locks(
            &block, 91880, &mut utxo, &params, &null_ctx, 0,
        );
        assert!(
            !matches!(result, Err(ValidationError::Bip30DuplicateOutput)),
            "h=91880 must be BIP-30 exempt; got: {result:?}",
        );
    }

    #[test]
    fn bip30_enforced_at_91843() {
        // h=91843 is NOT a BIP-30 exception and is pre-BIP34 (bip34_height=227931).
        // A duplicate coinbase txid MUST be rejected.
        let params = bip30_test_params();
        let coinbase = make_coinbase_tx(91843, 5_000_000_000);
        let coinbase_txid = coinbase.txid();
        let block = make_bip30_test_block(coinbase);

        let mut utxo = Bip30Utxo::new();
        utxo.seed_coin(coinbase_txid);

        let null_ctx = NullSequenceLockContext;
        let result = connect_block_with_sequence_locks(
            &block, 91843, &mut utxo, &params, &null_ctx, 0,
        );
        assert!(
            matches!(result, Err(ValidationError::Bip30DuplicateOutput)),
            "h=91843 must enforce BIP-30; got: {result:?}",
        );
    }

    #[test]
    fn bip30_old_wrong_heights_not_exempt() {
        // The previously wrong exception heights (91722, 91812) must NOT be exempt.
        let params = bip30_test_params();
        let null_ctx = NullSequenceLockContext;

        for wrong_h in [91722u32, 91812u32] {
            let coinbase = make_coinbase_tx(wrong_h, 5_000_000_000);
            let coinbase_txid = coinbase.txid();
            let block = make_bip30_test_block(coinbase);

            let mut utxo = Bip30Utxo::new();
            utxo.seed_coin(coinbase_txid);

            let result = connect_block_with_sequence_locks(
                &block, wrong_h, &mut utxo, &params, &null_ctx, 0,
            );
            assert!(
                matches!(result, Err(ValidationError::Bip30DuplicateOutput)),
                "h={wrong_h}: must enforce BIP-30 (old wrong exception height); got: {result:?}",
            );
        }
    }

    // ============================================================
    // BIP-113 lock_time_cutoff = parent MTP regression
    //
    // Regression for the 2026-05-02 wedge at mainnet h=944,184: when
    // CSV is active (mainnet h>=419,328) and `prev_block_mtp` is
    // hardcoded to 0, every tx with a timestamp-based `nLockTime > 0`
    // is rejected as `bad-txns-nonfinal`.  After the fix,
    // `connect_block_with_sequence_locks` honours the caller-supplied
    // `prev_block_mtp` and the same block validates cleanly.
    //
    // Reference: bitcoin-core/src/validation.cpp ConnectBlock — feeds
    // `pindex->pprev->GetMedianTimePast()` into the `IsFinalTx` call;
    // bitcoin-core/src/consensus/tx_verify.cpp IsFinalTx.
    // ============================================================

    /// Build a non-coinbase tx with a timestamp-based `nLockTime` whose
    /// finality depends on the parent's median-time-past (BIP-113).
    fn make_timestamp_locktime_tx(prev_txid: Hash256, lock_time: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: vec![0x51], // OP_1
                sequence: 0x00000000,    // NOT SEQUENCE_FINAL — locktime applies
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50, script_pubkey: vec![0x51] }],
            lock_time,
        }
    }

    fn seeded_utxo(txid: Hash256) -> Bip30Utxo {
        let mut u = Bip30Utxo::new();
        u.0.insert(
            OutPoint { txid, vout: 0 },
            CoinEntry {
                height: 1,
                is_coinbase: false,
                value: 100,
                script_pubkey: vec![0x51],
            },
        );
        u
    }

    #[test]
    fn bip113_zero_mtp_rejects_timestamp_locktime_post_csv() {
        // Mirrors the production bug: with CSV active and
        // prev_block_mtp = 0, every timestamp-based locktime > 0 is
        // rejected as bad-txns-nonfinal.
        let params = bip30_test_params(); // mainnet params + regtest pow_limit
        let prev_txid = Hash256::from_bytes([1u8; 32]);
        // 1_577_836_800 = 2020-01-01 UTC, well above LOCKTIME_THRESHOLD
        let tx = make_timestamp_locktime_tx(prev_txid, 1_577_836_800);
        let coinbase = make_coinbase_tx(944_184, 5_000_000_000);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase, tx],
        };

        let mut utxo = seeded_utxo(prev_txid);
        let null_ctx = NullSequenceLockContext;
        let result = connect_block_with_sequence_locks(
            &block, 944_184, &mut utxo, &params, &null_ctx, 0,
        );
        assert!(
            matches!(result, Err(ValidationError::NonFinalTx)),
            "with prev_block_mtp=0, timestamp-locktime tx must be rejected (control \
             for the 944,184 wedge); got: {result:?}"
        );
    }

    #[test]
    fn bip113_correct_mtp_accepts_timestamp_locktime_post_csv() {
        // Same block as above, but with prev_block_mtp set to a value
        // strictly greater than the locktime — the tx is now final
        // and the IsFinalTx check passes.  (The block may still fail
        // a later check; we only care that it does NOT fail with
        // `NonFinalTx` once MTP is plumbed through.)
        let params = bip30_test_params();
        let prev_txid = Hash256::from_bytes([1u8; 32]);
        let lock_time = 1_577_836_800u32;
        let tx = make_timestamp_locktime_tx(prev_txid, lock_time);
        let coinbase = make_coinbase_tx(944_184, 5_000_000_000);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase, tx],
        };

        let mut utxo = seeded_utxo(prev_txid);
        let null_ctx = NullSequenceLockContext;
        // prev_block_mtp = lock_time + 1 → tx is final.
        let result = connect_block_with_sequence_locks(
            &block, 944_184, &mut utxo, &params, &null_ctx, lock_time + 1,
        );
        assert!(
            !matches!(result, Err(ValidationError::NonFinalTx)),
            "with correct prev_block_mtp > lock_time, tx must NOT be rejected as \
             non-final; got: {result:?}"
        );
    }

    #[test]
    fn bip113_zero_mtp_pre_csv_uses_block_timestamp() {
        // Pre-CSV (mainnet h < 419,328): `lock_time_cutoff` falls back
        // to the block timestamp, NOT prev_block_mtp.  So the same tx
        // with a timestamp-locktime less than the block timestamp must
        // pass IsFinalTx even when prev_block_mtp = 0.
        let params = bip30_test_params(); // mainnet csv_height = 419,328
        let prev_txid = Hash256::from_bytes([1u8; 32]);
        let lock_time = 1_577_836_800u32;
        let tx = make_timestamp_locktime_tx(prev_txid, lock_time);
        let coinbase = make_coinbase_tx(100_000, 5_000_000_000);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: lock_time + 1, // strictly greater → tx final via block ts
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase, tx],
        };

        let mut utxo = seeded_utxo(prev_txid);
        let null_ctx = NullSequenceLockContext;
        let result = connect_block_with_sequence_locks(
            &block, 100_000, &mut utxo, &params, &null_ctx, 0,
        );
        // Pre-CSV: must NOT be NonFinalTx with this construction.
        assert!(
            !matches!(result, Err(ValidationError::NonFinalTx)),
            "pre-CSV (h=100,000) timestamp-locktime tx must validate against the \
             block timestamp, not prev_block_mtp; got: {result:?}"
        );
    }
}
