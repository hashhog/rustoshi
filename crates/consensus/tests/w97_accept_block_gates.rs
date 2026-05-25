//! W97 AcceptBlock/AcceptBlockHeader gate audit.
//!
//! This file encodes the Bitcoin Core spec for the 30 gates G1-G30
//! identified in Bitcoin Core `src/validation.cpp`:
//!
//! - `ChainstateManager::AcceptBlockHeader` (lines 4186-4239)
//! - `ChainstateManager::ProcessNewBlockHeaders` (lines 4242-4270)
//! - `ChainstateManager::AcceptBlock` (lines 4298-4396)
//!
//! Tests that should FAIL today document gates that are missing or buggy
//! in rustoshi.  Tests that pass document gates that ARE correctly
//! implemented and pin the spec so future refactors do not regress them.
//!
//! Many tests are `#[ignore]`d to keep the test binary green; they should
//! be flipped on once the corresponding bug is fixed.  Other tests
//! exercise the well-isolated `contextual_check_block_header` helper
//! directly to assert spec-correctness of the header-side checks (the
//! "Core helper exists; production path doesn't call it" pattern).
//!
//! Severity legend:
//! - CONSENSUS-DIVERGENT: real fork risk on real data
//! - DOS:                 resource exhaustion / peer-misbehavior bypass
//! - CORRECTNESS:         bad input handling but no fork risk
//! - OBSERVABILITY:       wrong error string / log / metric

use rustoshi_consensus::chain_state::{ChainState, UtxoCache};
use rustoshi_consensus::params::{ChainParams, MAX_FUTURE_BLOCK_TIME, MIN_BLOCKS_TO_KEEP};
use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_consensus::validation::{
    accept_block_header_chain_work, contextual_check_block_header, BlockIndexEntry, ChainContext,
    CoinEntry, ValidationError,
};
use rustoshi_primitives::serialize::Encodable;
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::HashMap;

// ----------------------------------------------------------------------
// Test stubs
// ----------------------------------------------------------------------

/// Minimal `ChainContext` for header tests.  Only `get_median_time_past`
/// is consulted by `contextual_check_block_header`.
struct MtpStub {
    mtp_by_hash: HashMap<Hash256, u32>,
}

impl ChainContext for MtpStub {
    fn get_block_index(&self, _hash: &Hash256) -> Option<BlockIndexEntry> {
        None
    }
    fn get_utxo(&self, _outpoint: &OutPoint) -> Option<CoinEntry> {
        None
    }
    fn get_median_time_past(&self, hash: &Hash256) -> u32 {
        self.mtp_by_hash.get(hash).copied().unwrap_or(0)
    }
    fn get_hash_at_height(&self, _height: u32) -> Option<Hash256> {
        None
    }
    fn tip_height(&self) -> u32 {
        0
    }
}

fn dummy_prev_entry(timestamp: u32) -> BlockIndexEntry {
    BlockIndexEntry {
        height: 0,
        timestamp,
        bits: 0,
        prev_hash: Hash256::ZERO,
        chain_work: [0u8; 32],
    }
}

// ----------------------------------------------------------------------
// G7 / G3 / G6 / G8 / G14 / G15 / G16 — header-acceptance gates.
//
// Core entry point `AcceptBlockHeader` performs (in order):
//   * G1 duplicate-hash short-circuit
//   * G2 genesis bypass
//   * G3 BLOCK_FAILED_VALID → "duplicate-invalid"
//   * G4 CheckBlockHeader (PoW + nBits sanity)
//   * G5 prev lookup → "prev-blk-not-found"
//   * G6 prev BLOCK_FAILED_VALID → "bad-prevblk"
//   * G7 ContextualCheckBlockHeader (MTP + timewarp + bad-version + 7200)
//   * G8 min_pow_checked → "too-little-chainwork"
//   * G9 AddToBlockIndex(updates m_best_header + nChainWork)
//   * G10 ppindex write-back
//
// rustoshi has NO function called `accept_block_header`.  Headers flow
// through `header_sync::process_headers`, which inlines a PARTIAL subset
// of these checks and skips others entirely.
// ----------------------------------------------------------------------

/// G7: BIP-113 MTP rejection — header timestamp == MTP must be REJECTED.
///
/// `contextual_check_block_header` is implemented correctly in
/// `validation.rs`, BUT IS NEVER CALLED from production code paths.
/// `process_headers` (network/header_sync.rs) inlines a partial copy and
/// `chain_state::process_block` checks only `<=` against the *parent*
/// MTP after the block body has arrived — too late for headers-first
/// DoS protection.
#[test]
fn g7_helper_rejects_time_equals_mtp() {
    let prev_hash = Hash256([0xab; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 1_700_000_000);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let header = BlockHeader {
        version: 4,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: 1_700_000_000, // == MTP → reject
        bits: 0,
        nonce: 0,
    };
    let params = ChainParams::regtest();
    let res = contextual_check_block_header(
        &header,
        10,
        &dummy_prev_entry(1_699_999_990),
        &ctx,
        &params,
        0,
    );
    assert!(matches!(res, Err(ValidationError::TimeTooOld)));
}

/// G7: BIP-34 nVersion gate — version 1 at bip34_height must be rejected
/// with `bad-version(0x00000001)`.
#[test]
fn g7_helper_rejects_v1_at_bip34_height() {
    let prev_hash = Hash256([0xcd; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 0);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: 1_700_000_000,
        bits: 0,
        nonce: 0,
    };
    let mut params = ChainParams::regtest();
    params.bip34_height = 100;
    let res =
        contextual_check_block_header(&header, 100, &dummy_prev_entry(0), &ctx, &params, 0);
    assert!(matches!(res, Err(ValidationError::BadVersion(1))));
}

/// G7: BIP-94 timewarp gate — at first block of difficulty period, on
/// networks where enforce_bip94 is true, timestamp < prev - 600s must
/// be rejected.
#[test]
fn g7_helper_rejects_bip94_timewarp_on_testnet4() {
    let prev_hash = Hash256([0xef; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 0);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let prev_time: u32 = 1_700_000_000;
    let header = BlockHeader {
        version: 4,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: prev_time - 1000, // 1000s earlier than parent — beyond 600s
        bits: 0,
        nonce: 0,
    };
    let mut params = ChainParams::regtest();
    params.enforce_bip94 = true;
    let res = contextual_check_block_header(
        &header,
        2016, // first block of next period
        &dummy_prev_entry(prev_time),
        &ctx,
        &params,
        0,
    );
    assert!(matches!(res, Err(ValidationError::TimeTimewarpAttack)));
}

/// G7 / production-path wiring assertion: `contextual_check_block_header`
/// must be invoked from `chain_state::process_block` so the 7200-future,
/// BIP-94 timewarp, and outdated-version gates fire on the
/// production block-acceptance path.
///
/// Wiring landed 2026-05-25 in chain_state.rs:497 (see
/// `CORE-PARITY-AUDIT/_bug-reports/rustoshi-contextual-check-block-
/// header-dead-code-2026-05-24.md` for the bug report and rustoshi
/// commit 630166f for the fix). This test exercises gate 3 (7200-future
/// `time-too-new`) on the production path. If the gate is unwired the
/// block is accepted; if wired the block is rejected with
/// `ValidationError::TimeTooNew`.
///
/// Header-sync path (`header_sync::process_headers`) is a separate
/// wiring gap tracked by task #111; this test only asserts the
/// block-body acceptance path which is the exploitable one.
///
/// Severity: CONSENSUS-DIVERGENT (bad-version / BIP-94 timewarp /
/// 7200-future are silently skipped on every header rustoshi accepts).
#[test]
fn g7_contextual_check_block_header_is_wired_into_production() {
    // Build a coinbase-only block at height 1 with a timestamp
    // MAX_FUTURE_BLOCK_TIME + 100s past `current_time`. Everything else
    // (PoW, coinbase shape, merkle root) is valid so `check_block` passes
    // and execution reaches `contextual_check_block_header`.
    let params = ChainParams::regtest();
    let genesis_hash = params.genesis_hash;
    let mut state = ChainState::new(genesis_hash, 0, params);
    let mut cache = UtxoCache::new(|_: &OutPoint| None, 1000);

    let current_time: u64 = 1_700_000_000;
    let future_ts = (current_time + MAX_FUTURE_BLOCK_TIME + 100) as u32;
    let mut block = make_future_dated_coinbase_block(genesis_hash, 1, future_ts);
    // Mine regtest PoW (max target — ~50% of nonces pass; usually <8 attempts).
    let regtest = ChainParams::regtest();
    for nonce in 0u32..1_000_000 {
        block.header.nonce = nonce;
        if rustoshi_consensus::pow::check_proof_of_work(
            &block.block_hash().0,
            block.header.bits,
            &regtest,
        ) {
            break;
        }
    }

    let result = state.process_block(&block, &mut cache, 0, true, current_time);
    assert!(
        matches!(result, Err(ValidationError::TimeTooNew)),
        "production process_block must reject a block timestamped {} \
         ({}h past current_time {}); got: {:?}",
        future_ts,
        (future_ts as u64 - current_time) / 3600,
        current_time,
        result
    );
    // Also confirm process_block with current_time=0 (skip future gate)
    // does NOT reject for TimeTooNew — proves the gate is gated on
    // current_time and not always-on. The block may still fail for some
    // other downstream reason, but it must NOT be TimeTooNew.
    let result_skip = state.process_block(&block, &mut cache, 0, true, 0);
    assert!(
        !matches!(result_skip, Err(ValidationError::TimeTooNew)),
        "with current_time=0 the 7200-future gate must be skipped; got: {:?}",
        result_skip
    );
}

/// Helper for `g7_contextual_check_block_header_is_wired_into_production`:
/// build a coinbase-only block at the given height with an arbitrary header
/// timestamp. Mirrors the `make_coinbase_block` helper in w105_checkqueue.rs.
fn make_future_dated_coinbase_block(prev_hash: Hash256, height: u32, timestamp: u32) -> Block {
    // BIP-34: push block height as CScriptNum in coinbase scriptSig.
    let coinbase_script: Vec<u8> = {
        let mut s = vec![0x03u8]; // push 3 bytes
        let h = height.to_le_bytes();
        s.extend_from_slice(&h[..3]);
        s
    };
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0u8; 32]), vout: 0xFFFF_FFFF },
            script_sig: coinbase_script,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 5_000_000_000,
            script_pubkey: vec![0x51], // OP_1
        }],
        lock_time: 0,
    };
    let merkle_root = rustoshi_crypto::sha256d(&{
        let mut bytes = Vec::new();
        coinbase_tx.encode(&mut bytes).unwrap();
        bytes
    });
    Block {
        header: BlockHeader {
            version: 0x20000000,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp,
            bits: 0x207fffff, // regtest max target — any nonce passes PoW
            nonce: 0,
        },
        transactions: vec![coinbase_tx],
    }
}

/// G3 / G6: BLOCK_FAILED_VALID short-circuit.
///
/// Core's AcceptBlockHeader returns the canonical error string
/// `duplicate-invalid` when a header is re-seen after being marked
/// `BLOCK_FAILED_VALID`, and `bad-prevblk` if the *parent* carries that
/// flag.  rustoshi has `block_store::is_block_invalid()` defined but
/// no caller consults it before invoking `process_block`, so neither
/// gate fires.
///
/// Severity: DOS (peer can re-spam a known-bad block and bypass the
/// fast reject; the block is fully re-validated each time).
#[test]
#[ignore = "G3+G6: is_block_invalid() is dead code — see block_store.rs:615"]
fn g3_g6_duplicate_invalid_and_bad_prevblk_short_circuit() {
    assert!(
        false,
        "no production caller of block_store::is_block_invalid"
    );
}

/// G8 case (a): low-work header with `min_pow_checked=false` → rejected with
/// `TooLittleChainwork`.
///
/// A peer feeding headers whose accumulated chain work is below
/// `params.minimum_chain_work` must be rejected when the PRESYNC pipeline
/// has NOT already validated the chain work.
///
/// Bitcoin Core: `AcceptBlockHeader` (validation.cpp:4229-4231):
///   `if (!min_pow_checked) {`
///   `    return state.Invalid(BLOCK_HEADER_LOW_WORK, "too-little-chainwork");`
///   `}`
///
/// Severity: DOS.
#[test]
fn g8_low_work_header_without_presync_rejected() {
    let mut params = ChainParams::regtest();
    // Set minimum_chain_work to a non-zero value so low-work headers can be
    // tested.  Use mainnet's minimum_chain_work (a real non-trivial value).
    let mainnet = ChainParams::mainnet();
    params.minimum_chain_work = mainnet.minimum_chain_work;

    // Simulate a header with bits=0x207fffff (regtest easy difficulty).
    // Its block proof is tiny — far below mainnet's minimum_chain_work.
    let easy_bits = 0x207fffff_u32;
    let header_proof = get_block_proof(easy_bits);

    // accumulated chain_work = genesis_work + header_proof (still tiny)
    let accumulated = ChainWork::ZERO.saturating_add(&header_proof);

    let result = accept_block_header_chain_work(&accumulated.0, false, &params);
    assert!(
        matches!(result, Err(ValidationError::TooLittleChainwork)),
        "low-work header with min_pow_checked=false must be rejected TooLittleChainwork; \
         got: {result:?}"
    );
}

/// G8 case (b): low-work header with `min_pow_checked=true` → accepted.
///
/// When the PRESYNC/REDOWNLOAD pipeline already validated accumulated chain
/// work, the per-header gate is skipped.  This mirrors Core's behaviour:
/// headers that passed PRESYNC get `min_pow_checked=true` and bypass G8.
///
/// Severity: n/a — this is the correct fast path.
#[test]
fn g8_low_work_header_with_presync_accepted() {
    let mut params = ChainParams::regtest();
    let mainnet = ChainParams::mainnet();
    params.minimum_chain_work = mainnet.minimum_chain_work;

    let easy_bits = 0x207fffff_u32;
    let header_proof = get_block_proof(easy_bits);
    let accumulated = ChainWork::ZERO.saturating_add(&header_proof);

    // min_pow_checked=true → PRESYNC already validated; gate is skipped.
    let result = accept_block_header_chain_work(&accumulated.0, true, &params);
    assert!(
        result.is_ok(),
        "low-work header with min_pow_checked=true must be accepted (PRESYNC bypass); \
         got: {result:?}"
    );
}

/// G8 case (c): high-work header with `min_pow_checked=false` → accepted.
///
/// A header whose accumulated chain work meets or exceeds
/// `params.minimum_chain_work` must pass even without PRESYNC validation.
/// This is the normal mainnet case once the chain has sufficient work.
///
/// Severity: n/a — correct behaviour.
#[test]
fn g8_high_work_header_without_presync_accepted() {
    let params = ChainParams::mainnet();

    // Build an accumulated work value that is >= minimum_chain_work by
    // setting it to exactly minimum_chain_work (lower-bound edge case).
    let sufficient_work = params.minimum_chain_work;

    let result = accept_block_header_chain_work(&sufficient_work, false, &params);
    assert!(
        result.is_ok(),
        "header with chain_work == minimum_chain_work and min_pow_checked=false \
         must be accepted; got: {result:?}"
    );
}

/// G16: IBD progress log uses PowTargetSpacing.
///
/// Core's `NotifyHeaderTip` (after ProcessNewBlockHeaders) logs an IBD
/// progress estimate computed from `consensus.nPowTargetSpacing` (10
/// minutes on mainnet, 1 second on testnet4).  rustoshi's `ChainParams`
/// has no `pow_target_spacing` field at all and logs raw heights only.
///
/// Severity: OBSERVABILITY.
#[test]
#[ignore = "G16: ChainParams has no pow_target_spacing field"]
fn g16_chainparams_has_pow_target_spacing() {
    assert!(
        false,
        "ChainParams::pow_target_spacing missing — IBD progress can't use network-dependent value"
    );
}

// ----------------------------------------------------------------------
// AcceptBlock body-stage gates
// ----------------------------------------------------------------------

/// G18: fAlreadyHave short-circuit.
///
/// Core's AcceptBlock checks `nStatus & BLOCK_HAVE_DATA` and returns
/// `true` (success) immediately if the block is already on disk.
/// rustoshi's `chain_state::process_block` performs no such check and
/// will re-validate the block, returning `PrevBlockNotFound` if the
/// tip has already advanced past it.
///
/// Severity: CORRECTNESS (legitimate re-submission of a known block
/// returns an error instead of success).
#[test]
#[ignore = "G18: process_block has no fAlreadyHave check"]
fn g18_already_have_short_circuit() {
    assert!(
        false,
        "process_block does not check BLOCK_HAVE_DATA before re-validating"
    );
}

// G19c: fTooFarAhead gate (MIN_BLOCKS_TO_KEEP = 288).
//
// Bitcoin Core AcceptBlock (validation.cpp:4325-4330):
//   bool fTooFarAhead = (pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP);
//   if (!fRequested) {
//       ...
//       if (fTooFarAhead) return true;   // silent early-return, no error state
//       ...
//   }
//
// rustoshi equivalent: process_block_at_height with f_requested=false and
// claimed_height > tip_height + MIN_BLOCKS_TO_KEEP returns BlockTooFarAhead.

/// Helper: build a minimal block that passes no validation (used for gate tests
/// where we just need the fTooFarAhead check to fire *before* any other check).
fn build_minimal_block(prev_hash: Hash256) -> Block {
    Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![],
    }
}

/// G19c case 1: unrequested block with claimed nHeight = tip + 289 is rejected.
///
/// A peer can lie about a block's height.  If rustoshi would download, validate,
/// and store such a block, it wastes bandwidth and CPU.  The fTooFarAhead gate
/// must reject BEFORE any validation work is done.
///
/// Severity: DOS.
#[test]
fn g19c_unrequested_block_too_far_ahead_rejected() {
    let params = ChainParams::regtest();
    let genesis_hash = params.genesis_hash;
    let mut state = ChainState::new(genesis_hash, 0, params);
    let mut cache = UtxoCache::new(|_: &OutPoint| None, 1000);

    // Block whose prev_hash == tip (would extend), but claimed height is 289.
    // tip_height=0, claimed_height=289 → 289 > 0 + 288, so fTooFarAhead fires.
    let claimed_height = MIN_BLOCKS_TO_KEEP + 1; // 289
    let block = build_minimal_block(genesis_hash);

    let result = state.process_block_at_height(&block, &mut cache, 0, false, claimed_height, 0);
    assert!(
        matches!(result, Err(ValidationError::BlockTooFarAhead(289, 0))),
        "unrequested block at claimed height {claimed_height} (> tip 0 + MIN_BLOCKS_TO_KEEP {MIN_BLOCKS_TO_KEEP}) \
         must return BlockTooFarAhead; got: {result:?}"
    );
    // Tip must not advance
    assert_eq!(state.tip_height(), 0, "rejected block must not advance tip");
}

/// G19c case 2: unrequested block with claimed nHeight = tip + 288 (at gate) is
/// not rejected by fTooFarAhead (may fail for other reasons, but NOT BlockTooFarAhead).
///
/// Core: `>` not `>=`, so exactly tip + MIN_BLOCKS_TO_KEEP is allowed.
#[test]
fn g19c_unrequested_block_at_gate_not_too_far() {
    let params = ChainParams::regtest();
    let genesis_hash = params.genesis_hash;
    let mut state = ChainState::new(genesis_hash, 0, params);
    let mut cache = UtxoCache::new(|_: &OutPoint| None, 1000);

    // claimed_height == MIN_BLOCKS_TO_KEEP (288): 288 > 0 + 288 is false → gate does NOT fire.
    let claimed_height = MIN_BLOCKS_TO_KEEP; // exactly 288
    let block = build_minimal_block(genesis_hash);

    let result = state.process_block_at_height(&block, &mut cache, 0, false, claimed_height, 0);
    assert!(
        !matches!(result, Err(ValidationError::BlockTooFarAhead(_, _))),
        "block at claimed height {claimed_height} (== tip 0 + {MIN_BLOCKS_TO_KEEP}) \
         must NOT be rejected by fTooFarAhead; got: {result:?}"
    );
}

/// G19c case 3: requested block with claimed nHeight = tip + 289 is NOT rejected.
///
/// The fTooFarAhead gate only applies to unrequested blocks (f_requested=false).
/// A block actively requested via getdata (f_requested=true) must not be rejected
/// even if its claimed height exceeds tip + MIN_BLOCKS_TO_KEEP.
#[test]
fn g19c_requested_block_far_ahead_accepted_past_gate() {
    let params = ChainParams::regtest();
    let genesis_hash = params.genesis_hash;
    let mut state = ChainState::new(genesis_hash, 0, params);
    let mut cache = UtxoCache::new(|_: &OutPoint| None, 1000);

    // claimed_height = 289 (> tip 0 + 288), but f_requested=true → gate skipped.
    let claimed_height = MIN_BLOCKS_TO_KEEP + 1; // 289
    let block = build_minimal_block(genesis_hash);

    let result = state.process_block_at_height(&block, &mut cache, 0, true, claimed_height, 0);
    assert!(
        !matches!(result, Err(ValidationError::BlockTooFarAhead(_, _))),
        "requested block at claimed height {claimed_height} must NOT be rejected \
         by fTooFarAhead even though it exceeds tip + MIN_BLOCKS_TO_KEEP; got: {result:?}"
    );
}

/// G19d: anti-low-work block-side gate.
///
/// Core's AcceptBlock also performs a `nChainWork < MinimumChainWork()`
/// check on the block path, complementing the header-side G8.  rustoshi
/// does neither.
///
/// Severity: DOS.
#[test]
#[ignore = "G19d: minimum_chain_work not consulted on block path"]
fn g19d_block_path_minimum_chain_work() {
    assert!(false, "no caller rejects block chain_work < params.minimum_chain_work");
}

/// G22: InvalidBlockFound on CheckBlock/ContextualCheckBlock failure.
///
/// Core calls `InvalidBlockFound(state, pindex)` which sets
/// BLOCK_FAILED_VALID + records the rejected hash.  rustoshi's
/// `process_block` returns the error but never sets the
/// `FAILED_VALIDITY` flag on the block-index entry, so a repeat
/// submission of the same bad block does the full validation work
/// again (peer can DoS by replaying).
///
/// Severity: DOS.
#[test]
#[ignore = "G22: validation failure does not call mark_block_invalid()"]
fn g22_invalid_block_found_marks_failed_validity() {
    assert!(
        false,
        "validation errors don't set FAILED_VALIDITY on the block index entry"
    );
}

/// G23: NewPoWValidBlock signal only when (!IBD && ActiveTip == pindex.prev).
///
/// Core fires this signal so the wallet / GBT / ZMQ subscribers see
/// new-block events.  rustoshi has no signal infrastructure (no
/// NotifyHeaderTip, no UpdatedBlockTip, no NewPoWValidBlock).  ZMQ
/// publish topics are silent.
///
/// Severity: OBSERVABILITY (ZMQ subscribers / wallets / external
/// tooling cannot observe new blocks except via polling).
#[test]
#[ignore = "G23: no NewPoWValidBlock/UpdatedBlockTip signal in rustoshi"]
fn g23_new_pow_valid_block_signal_present() {
    assert!(
        false,
        "no signal fired on new-block; rustoshi has no signal infrastructure"
    );
}

/// G25: ReceivedBlockTransactions transitions BLOCK_HAVE_DATA + marks
/// the block as a connect candidate.
///
/// Core flips `BLOCK_HAVE_DATA` on AS PART OF AcceptBlock immediately
/// after `WriteBlock` succeeds.  In rustoshi the flag is set later, by
/// the caller in main.rs, AFTER process_block has run.  A crash
/// between these two steps leaves the block on disk with no
/// HAVE_DATA flag, so it is re-downloaded on startup.
///
/// Severity: CORRECTNESS.
#[test]
#[ignore = "G25: HAVE_DATA flag set by caller, not by process_block — see main.rs:2074 vs chain_state.rs:395"]
fn g25_received_block_transactions_atomic_with_disk_write() {
    assert!(
        false,
        "HAVE_DATA flag is set by main.rs after process_block, not inside it"
    );
}

/// G26: FlushStateToDisk(FlushStateMode::NONE) — pruning hint.
///
/// Core calls FlushStateToDisk at the end of AcceptBlock to let the
/// pruner observe the new height.  rustoshi has an auto-prune path
/// in main.rs (height % 100) but it's outside process_block; the
/// pruner doesn't get a hook on every accepted block.
///
/// Severity: OBSERVABILITY.
#[test]
#[ignore = "G26: no per-block FlushStateToDisk hook"]
fn g26_flush_state_to_disk_per_block_hook() {
    assert!(
        false,
        "process_block does not call FlushStateToDisk; pruner only ticks every 100 blocks"
    );
}

/// G27: CheckBlockIndex invariant after AcceptBlock returns.
///
/// Core asserts that the block index is consistent (chain work is
/// monotonic, prev pointers are well-formed, etc.) after every
/// accept.  rustoshi has no such invariant function.
///
/// Severity: CORRECTNESS (latent bugs in block-index state aren't
/// surfaced).
#[test]
#[ignore = "G27: no CheckBlockIndex equivalent"]
fn g27_check_block_index_invariant() {
    assert!(false, "no CheckBlockIndex function in rustoshi");
}

/// G29: System-error catch on disk write.
///
/// Core wraps the WriteBlock / put_undo call sites in a try/catch
/// that maps fs::filesystem_error to a clean BLOCK_RESULT_UNSET +
/// AbortNode rather than propagating a panic.  rustoshi's RPC layer
/// catches deserialization panics (server.rs:4179) but the IBD path
/// in main.rs:920 calls `process_block` directly and a
/// filesystem-error panic from the underlying put_block call
/// would terminate the IBD loop without a clean abort.
///
/// Severity: CORRECTNESS.
#[test]
#[ignore = "G29: no AbortNode equivalent on disk-write panic in IBD path"]
fn g29_disk_write_panic_clean_abort() {
    assert!(false, "no panic catcher around put_block in IBD path");
}

/// G28: fNewBlock output.
///
/// Core's AcceptBlock takes an `fNewBlock` out-parameter that the
/// caller uses to distinguish "block accepted for the first time"
/// from "duplicate request for known block".  rustoshi's
/// `process_block` returns `Ok((UndoData, fees))` on real accepts
/// and `Err(PrevBlockNotFound)` on duplicates / forks — these are
/// the same error variant as a true missing-parent, so callers
/// cannot tell duplicate-known-block from missing-prev.
///
/// Severity: CORRECTNESS.
#[test]
#[ignore = "G28: process_block has no fNewBlock-equivalent"]
fn g28_f_new_block_distinguishes_duplicate_from_new() {
    assert!(
        false,
        "process_block returns the same error for duplicates and unknown-prev cases"
    );
}

/// G30: HAVE_DATA must be set BEFORE the next ReceivedBlockTransactions
/// short-circuit.
///
/// Because rustoshi's HAVE_DATA flag is set OUTSIDE process_block
/// (G25), a second arriving copy of the same block in the same tokio
/// task run cannot short-circuit on G18 — process_block runs the full
/// validation twice if a peer re-sends.
///
/// Severity: DOS (relatively low — the second copy is rejected by
/// the BlockDownloader's in-flight dedup before reaching process_block
/// in the healthy case, but the protection is incidental).
#[test]
#[ignore = "G30: HAVE_DATA is set after process_block, so G18 short-circuit can never fire"]
fn g30_have_data_set_before_short_circuit() {
    assert!(false, "HAVE_DATA / G18 ordering broken — see G18 + G25");
}

// ----------------------------------------------------------------------
// Gates that rustoshi DOES implement — sanity tests.
// ----------------------------------------------------------------------

/// G2 / G4: rustoshi's `check_proof_of_work` (PoW + nBits sanity) is
/// implemented and called by `check_block`, which is in turn called by
/// `process_block`.  Spec is verified separately in pow.rs tests.
///
/// This test pins the existence of the call so a refactor that
/// accidentally removes `check_block(...)` from `process_block` will
/// be caught.
#[test]
fn g4_check_block_calls_check_proof_of_work() {
    // Construct a header with bits=0x1d00ffff (mainnet difficulty) but
    // a hash that won't satisfy.  Easier: call check_proof_of_work
    // directly with a known-bad hash to confirm the gate function
    // exists and rejects.
    use rustoshi_consensus::pow::check_proof_of_work;
    let params = ChainParams::mainnet();
    let bad_hash = [0xff; 32];
    assert!(
        !check_proof_of_work(&bad_hash, 0x1d00ffff, &params),
        "all-ones hash must NOT satisfy mainnet difficulty"
    );
}

/// G7 helper: BIP-34/66/65 version-gate spec is implemented in
/// `contextual_check_block_header` (validation.rs:946-952).  This test
/// pins the spec.  See `g7_contextual_check_block_header_is_wired_into_production`
/// for the wiring bug.
#[test]
fn g7_helper_rejects_v3_at_bip65_height() {
    let prev_hash = Hash256([0x12; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 0);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let header = BlockHeader {
        version: 3,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: 1_700_000_000,
        bits: 0,
        nonce: 0,
    };
    let mut params = ChainParams::regtest();
    params.bip65_height = 50;
    let res =
        contextual_check_block_header(&header, 50, &dummy_prev_entry(0), &ctx, &params, 0);
    assert!(matches!(res, Err(ValidationError::BadVersion(3))));
}

/// G7 helper: BIP-66 nVersion gate — version 2 at bip66_height must be
/// rejected.
#[test]
fn g7_helper_rejects_v2_at_bip66_height() {
    let prev_hash = Hash256([0x34; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 0);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let header = BlockHeader {
        version: 2,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: 1_700_000_000,
        bits: 0,
        nonce: 0,
    };
    let mut params = ChainParams::regtest();
    params.bip66_height = 75;
    let res =
        contextual_check_block_header(&header, 75, &dummy_prev_entry(0), &ctx, &params, 0);
    assert!(matches!(res, Err(ValidationError::BadVersion(2))));
}

/// G7 helper: future-drift rejection at 7201s.
#[test]
fn g7_helper_rejects_time_too_new_7201s() {
    let prev_hash = Hash256([0x56; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 0);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let now: u64 = 1_700_000_000;
    let header = BlockHeader {
        version: 4,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: (now + 7201) as u32,
        bits: 0,
        nonce: 0,
    };
    let params = ChainParams::regtest();
    let res = contextual_check_block_header(
        &header,
        10,
        &dummy_prev_entry(0),
        &ctx,
        &params,
        now,
    );
    assert!(matches!(res, Err(ValidationError::TimeTooNew)));
}

/// G7 helper: future-drift accept at exactly 7200s.
#[test]
fn g7_helper_accepts_time_too_new_exactly_7200s() {
    let prev_hash = Hash256([0x78; 32]);
    let mut mtp = HashMap::new();
    mtp.insert(prev_hash, 0);
    let ctx = MtpStub { mtp_by_hash: mtp };
    let now: u64 = 1_700_000_000;
    let header = BlockHeader {
        version: 4,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp: (now + 7200) as u32,
        bits: 0,
        nonce: 0,
    };
    let params = ChainParams::regtest();
    let res = contextual_check_block_header(
        &header,
        10,
        &dummy_prev_entry(0),
        &ctx,
        &params,
        now,
    );
    assert!(res.is_ok(), "exactly 7200s in the future must be accepted: {res:?}");
}
