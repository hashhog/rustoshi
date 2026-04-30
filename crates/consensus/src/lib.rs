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

pub mod block_template;
pub mod chain_manager;
pub mod chain_state;
pub mod fee_estimator;
pub mod mempool;
pub mod mempool_persist;
pub mod params;
pub mod pow;
pub mod script;
pub mod sig_cache;
pub mod validation;
pub mod versionbits;

pub use params::{
    block_subsidy, calculate_next_work_required, compact_to_target, target_to_compact,
    AssumeutxoData, AssumeutxoHash, ChainParams, Checkpoints, NetworkId, NetworkMagic,
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
    calculate_sequence_locks, check_block, check_sequence_locks, check_transaction, connect_block,
    connect_block_parallel, connect_block_parallel_with_cache,
    connect_block_parallel_with_cache_and_sequence_locks, connect_block_parallel_with_sequence_locks,
    connect_block_with_sequence_locks, contextual_check_block, contextual_check_block_header,
    disconnect_block, validate_scripts_parallel, validate_scripts_parallel_with_cache,
    BlockIndexEntry, ChainContext, CoinEntry, SequenceLockContext, SequenceLocks,
    TransactionSignatureChecker, TxValidationError, UndoData, UtxoView, ValidationError,
};
pub use chain_state::{ChainState, CompressedScript, UtxoCache};
pub use fee_estimator::{FeeEstimator, RawBucketStats};
pub use mempool::{Mempool, MempoolConfig, MempoolEntry, MempoolError};
pub use mempool_persist::{
    dump_mempool, dump_mempool_with_key, header_size, load_mempool, DumpStats, LoadStats,
    MEMPOOL_DUMP_VERSION, MEMPOOL_DUMP_VERSION_NO_XOR_KEY, OBFUSCATION_KEY_LEN,
};
pub use block_template::{
    build_block_template, is_final_tx, BlockTemplate, BlockTemplateConfig, MAX_SEQUENCE_NONFINAL,
    SEQUENCE_FINAL,
};
pub use pow::{
    get_next_work_required, check_proof_of_work, permitted_difficulty_transition, BlockIndex,
    get_block_proof, ChainWork,
};
pub use versionbits::{
    get_state_for, get_state_statistics, compute_block_version, is_deployment_active,
    get_deployments, BIP9Deployment, BIP9Stats, DeploymentId, ThresholdState,
    VersionbitsBlockInfo, VersionbitsCache, VERSIONBITS_TOP_BITS, VERSIONBITS_TOP_MASK,
    VERSIONBITS_PERIOD, VERSIONBITS_THRESHOLD_MAINNET, VERSIONBITS_THRESHOLD_TESTNET,
    ALWAYS_ACTIVE, NEVER_ACTIVE, NO_TIMEOUT,
};
pub use chain_manager::{
    block_status, compare_chain_work, find_descendants, get_ancestor, is_ancestor,
    is_ancestor_or_descendant, BlockMeta, ChainManagementError, ChainManagerState,
    InvalidateBlockResult, PreciousBlockResult, ReconsiderBlockResult,
};
pub use sig_cache::{SigCache, DEFAULT_MAX_ENTRIES};
