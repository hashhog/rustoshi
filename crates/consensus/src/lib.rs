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
//! - `params`: Consensus parameters, chain configuration, genesis blocks, and
//!   soft fork activation heights for all networks.
//! - `validation`: Block and transaction validation, including context-free checks,
//!   contextual checks (BIP-34, witness commitment), and UTXO-based connection.
//! - `chain_state`: UTXO cache and chain state management, including chain tip
//!   tracking, median-time-past computation, and reorganization support.
//!
//! # Consensus vs Policy
//!
//! When validating blocks, only use consensus flags. Adding policy flags
//! (CLEANSTACK, LOW_S, etc.) to block validation will cause valid blocks
//! to be rejected, forking the node from the network.
//!
//! See `ScriptFlags::consensus_flags()` for the correct flags to use during
//! block validation.

pub mod chain_state;
pub mod mempool;
pub mod params;
pub mod script;
pub mod validation;

pub use params::{
    block_subsidy, calculate_next_work_required, compact_to_target, target_to_compact,
    ChainParams, NetworkId, NetworkMagic,
    // Consensus constants
    COINBASE_MATURITY, COIN, DIFFICULTY_ADJUSTMENT_INTERVAL, INITIAL_SUBSIDY,
    LOCKTIME_THRESHOLD, MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT,
    MAX_MONEY, MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG, MAX_SCRIPT_ELEMENT_SIZE,
    MAX_SCRIPT_SIZE, MAX_STACK_SIZE, MAX_TIMESPAN, MEDIAN_TIME_PAST_WINDOW, MIN_TIMESPAN,
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG,
    SUBSIDY_HALVING_INTERVAL, TARGET_BLOCK_TIME, TARGET_TIMESPAN, WITNESS_SCALE_FACTOR,
};
pub use script::{
    eval_script, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, verify_script, DummyChecker,
    Opcode, ScriptError, ScriptFlags, SigVersion, SignatureChecker, Stack,
};
pub use validation::{
    check_block, check_transaction, connect_block, contextual_check_block,
    contextual_check_block_header, disconnect_block, BlockIndexEntry, ChainContext, CoinEntry,
    TransactionSignatureChecker, TxValidationError, UndoData, UtxoView, ValidationError,
};
pub use chain_state::{ChainState, UtxoCache};
pub use mempool::{Mempool, MempoolConfig, MempoolEntry, MempoolError};
