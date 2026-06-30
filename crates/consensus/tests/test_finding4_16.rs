//! Tests for Finding 4 (assumevalid faithful 5-condition gate) and
//! Finding 16 (BIP-94 timewarp gate defanged by prev_timestamp=0).
//!
//! Bitcoin Core reference:
//!   - Finding 4: validation.cpp:2346-2382 (5-condition gate)
//!   - Finding 16: validation.cpp:4097-4104 (BIP-94 timewarp)
//!
//! All tests use pure, exported functions and require no running node.

use rustoshi_consensus::{
    contextual_check_block_header, params::ChainParams, should_skip_scripts, BlockIndexEntry,
    StubChainContext, ValidationError,
};
use rustoshi_primitives::{BlockHeader, Hash256};

// ============================================================
// Helpers
// ============================================================

/// Build a 256-bit big-endian value with `n` in the low 8 bytes.
fn chain_work_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

/// A deterministic Hash256 from a seed byte.
fn hash_from_seed(seed: u8) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    Hash256(bytes)
}

/// A minimal BlockIndexEntry with only `timestamp` set (other fields zero).
fn prev_entry_with_ts(ts: u32) -> BlockIndexEntry {
    BlockIndexEntry {
        height: 0,
        timestamp: ts,
        bits: 0,
        prev_hash: Hash256::ZERO,
        chain_work: [0u8; 32],
    }
}

/// A minimal BlockHeader suitable for contextual_check_block_header tests.
/// Does NOT satisfy PoW — for use with the pure contextual function only.
fn test_header(prev_hash: Hash256, timestamp: u32, bits: u32) -> BlockHeader {
    BlockHeader {
        version: 4,
        prev_block_hash: prev_hash,
        merkle_root: Hash256::ZERO,
        timestamp,
        bits,
        nonce: 0,
    }
}

// ============================================================
// Finding 4: should_skip_scripts — faithful 5-condition gate
// ============================================================

/// F4-A: Condition 1 — no assumed_valid_block configured → always false.
///
/// Regtest has `assumed_valid_block: None`; should_skip_scripts must return
/// false regardless of work or height.
#[test]
fn f4a_no_assumed_valid_block_never_skips() {
    let params = ChainParams::regtest();
    assert!(params.assumed_valid_block.is_none(), "regtest must not have AV block");

    let block_hash = hash_from_seed(1);
    let av_chain_work = chain_work_from_u64(1_000_000);

    let result = should_skip_scripts(
        &block_hash,
        0,
        &av_chain_work,
        &av_chain_work,
        0x1d00ffff,
        &|_| Some(block_hash),
        &params,
    );
    assert!(!result, "no AV configured → must never skip scripts");
}

/// F4-B: Condition 3 — fork block at AV height is NOT skipped.
///
/// Two blocks at the same height: the canonical one (matches height index)
/// and a fork block (different hash). The canonical block IS an ancestor of AV;
/// the fork block is NOT. The gate must only skip for the canonical block.
///
/// This is the PRIMARY regression test: the old height-only gate would skip
/// BOTH. The faithful 5-condition gate skips only the canonical one.
///
/// For condition 5 to pass (burial > 2 weeks): best_header must have enormous
/// chain work relative to the block. We set block_chain_work=[0;32] and
/// best_header_chain_work=[0xff;32], which makes the PoW burial time saturate
/// to i64::MAX (>> TWO_WEEKS). This simulates a block deeply buried in the chain.
#[test]
fn f4b_fork_block_at_av_height_not_skipped() {
    // Synthetic params: AV at height 20, zero minimum_chain_work (condition 4 always passes).
    let canonical_hash_at_10 = hash_from_seed(10);
    let av_hash = hash_from_seed(42); // AV block is at height 20.
    let av_height: u32 = 20;

    // Start from mainnet params and override AV config.
    let mut params = ChainParams::mainnet();
    params.assumed_valid_block = Some(av_hash);
    params.assumed_valid_height = Some(av_height);
    params.minimum_chain_work = [0u8; 32]; // disable condition 4 (let condition 3 decide)

    // For condition 5: block has minimal chain work, best_header has maximum.
    // diff = [0xff;32] - [0;32] → scaled saturates → quotient = i64::MAX >> TWO_WEEKS.
    let block_work = [0u8; 32];        // block barely started
    let best_work = [0xff_u8; 32];     // best header has maximum possible work

    // The height index: AV at 20 = av_hash, canonical at 10 = canonical_hash_at_10.
    let hash_at_height = |h: u32| -> Option<Hash256> {
        match h {
            20 => Some(av_hash),
            10 => Some(canonical_hash_at_10),
            _ => None,
        }
    };

    // Case A: canonical block at height 10 — IS in our chain → must skip.
    let result_canonical = should_skip_scripts(
        &canonical_hash_at_10,
        10,
        &block_work,
        &best_work,
        0x1700f000, // easy bits so block_proof is small → burial time saturates
        &hash_at_height,
        &params,
    );
    assert!(
        result_canonical,
        "canonical block at height 10 with AV at height 20 and sufficient burial must skip scripts"
    );

    // Case B: fork block at height 10 — different hash, NOT in our canonical chain → must verify.
    let fork_hash_at_10 = hash_from_seed(11); // different from canonical
    let result_fork = should_skip_scripts(
        &fork_hash_at_10,
        10,
        &block_work,
        &best_work,
        0x1700f000,
        &hash_at_height,
        &params,
    );
    assert!(
        !result_fork,
        "fork block at height 10 (hash mismatch in height index) must NOT skip scripts — \
         this was the bug: the old height-only gate would have skipped it"
    );
}

/// F4-C: Condition 4 — insufficient best-header chain work → gate returns false.
///
/// Even if the block is on the canonical chain below AV, if best_header.chainWork
/// is below minimum_chain_work the gate must reject the skip (eclipse defense).
#[test]
fn f4c_low_chain_work_does_not_skip() {
    let canonical_hash = hash_from_seed(5);
    let av_hash = hash_from_seed(99);
    let av_height: u32 = 10;

    // Use mainnet params: mainnet minimum_chain_work is large (non-trivial).
    let mut params = ChainParams::mainnet();
    params.assumed_valid_block = Some(av_hash);
    params.assumed_valid_height = Some(av_height);
    // mainnet minimum_chain_work is already large from chainparams.

    // Best-header chain work is BELOW minimum_chain_work (tiny).
    let tiny_work = chain_work_from_u64(1);

    let hash_at_height = |h: u32| -> Option<Hash256> {
        match h {
            10 => Some(av_hash),
            5 => Some(canonical_hash),
            _ => None,
        }
    };

    let result = should_skip_scripts(
        &canonical_hash,
        5,
        &tiny_work,
        &tiny_work, // best_header has tiny work → condition 4 fails
        0x1700f000,
        &hash_at_height,
        &params,
    );
    assert!(
        !result,
        "insufficient best_header chain work (eclipse defense) must prevent script skip"
    );
}

/// F4-D: Condition 5 — block too recent (< 2 weeks equivalent PoW burial) → gate false.
///
/// When block_chain_work == best_header_chain_work, the PoW burial time is zero.
/// Zero seconds < 2 weeks → must NOT skip.
#[test]
fn f4d_insufficient_burial_does_not_skip() {
    let canonical_hash = hash_from_seed(5);
    let av_hash = hash_from_seed(99);
    let av_height: u32 = 10;

    let mut params = ChainParams::mainnet();
    params.assumed_valid_block = Some(av_hash);
    params.assumed_valid_height = Some(av_height);
    params.minimum_chain_work = [0u8; 32]; // pass condition 4

    // Same chain work for block and best_header → 0 equivalent burial seconds.
    let work = chain_work_from_u64(1_000_000);

    let hash_at_height = |h: u32| -> Option<Hash256> {
        match h {
            10 => Some(av_hash),
            5 => Some(canonical_hash),
            _ => None,
        }
    };

    let result = should_skip_scripts(
        &canonical_hash,
        5,
        &work,
        &work, // best_header == block → 0 equiv secs < 2 weeks → condition 5 fails
        0x1700f000,
        &hash_at_height,
        &params,
    );
    assert!(
        !result,
        "block with 0 equivalent PoW burial (<2 weeks) must not skip scripts (condition 5)"
    );
}

/// F4-E: Block height > AV height → gate returns false (early exit).
///
/// A block above the assumed-valid point must always verify scripts.
#[test]
fn f4e_block_above_av_height_not_skipped() {
    let av_hash = hash_from_seed(99);
    let av_height: u32 = 10;
    let block_at_15 = hash_from_seed(15);

    let mut params = ChainParams::mainnet();
    params.assumed_valid_block = Some(av_hash);
    params.assumed_valid_height = Some(av_height);
    params.minimum_chain_work = [0u8; 32];

    let enormous_work = chain_work_from_u64(u64::MAX);

    let result = should_skip_scripts(
        &block_at_15,
        15, // > av_height (10)
        &enormous_work,
        &enormous_work,
        0x1700f000,
        &|_| None,
        &params,
    );
    assert!(!result, "block above AV height must not skip scripts (early exit)");
}

/// F4-F: AV block not in canonical chain → gate returns false (condition 2).
///
/// If the AV block hash is not at the expected height in our chain, we refuse
/// to skip (we're on a different chain or haven't synced to that point yet).
#[test]
fn f4f_av_block_not_in_canonical_chain_does_not_skip() {
    let av_hash = hash_from_seed(42);
    let different_hash_at_av_height = hash_from_seed(43); // NOT our AV block
    let av_height: u32 = 10;
    let block_hash = hash_from_seed(5);

    let mut params = ChainParams::mainnet();
    params.assumed_valid_block = Some(av_hash);
    params.assumed_valid_height = Some(av_height);
    params.minimum_chain_work = [0u8; 32];

    let block_work = [0u8; 32];
    let best_work = [0xff_u8; 32];

    // The height index has a DIFFERENT hash at av_height (not our AV block).
    let hash_at_height = |h: u32| -> Option<Hash256> {
        match h {
            10 => Some(different_hash_at_av_height), // not av_hash
            5 => Some(block_hash),
            _ => None,
        }
    };

    let result = should_skip_scripts(
        &block_hash,
        5,
        &block_work,
        &best_work,
        0x1700f000,
        &hash_at_height,
        &params,
    );
    assert!(
        !result,
        "AV block not in canonical chain (condition 2 fail) → must not skip scripts"
    );
}

// ============================================================
// Finding 16: BIP-94 timewarp gate — prev_timestamp must be real
// ============================================================

/// F16-A: BIP-94 gate fires when prev_entry.timestamp is real (non-zero) and
/// the block's timestamp is > 600 seconds before the parent.
///
/// Core reference: validation.cpp:4097-4104
///   if (nHeight % DifficultyAdjustmentInterval() == 0)
///     if (block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP)
///       return state.Invalid(...)
///
/// This exercises the pure `contextual_check_block_header` gate directly.
/// Height must be 2016 (first retarget boundary where BIP-94 applies).
#[test]
fn f16a_bip94_gate_fires_with_real_prev_timestamp() {
    let params = ChainParams::testnet4();
    assert!(params.enforce_bip94, "testnet4 must have enforce_bip94=true");

    let prev_ts: u32 = 1_700_010_000;
    // block_ts = prev_ts - 601 → 601 seconds before parent → timewarp violation.
    // Must also be > MTP (to pass time-too-old): set mtp = block_ts - 400.
    let block_ts: u32 = prev_ts - 601; // = 1_700_009_399

    let header = test_header(Hash256::ZERO, block_ts, 0x1d00ffff);

    // Pass the REAL prev timestamp via prev_entry.timestamp.
    let prev_entry = prev_entry_with_ts(prev_ts);

    // StubChainContext returns MTP=0 — time-too-old check (block_ts > 0) will pass.
    let result = contextual_check_block_header(
        &header,
        2016, // first retarget boundary: 2016 % 2016 == 0
        &prev_entry,
        &StubChainContext,
        &params,
        0,
        None, // skip diffbits gate
    );
    assert!(
        matches!(result, Err(ValidationError::TimeTimewarpAttack)),
        "BIP-94 timewarp violation (block_ts={block_ts} < prev_ts={prev_ts} - 600) \
         with real prev_timestamp must be rejected; got: {result:?}"
    );
}

/// F16-B: BIP-94 gate is silently disabled when prev_entry.timestamp=0 (the bug).
///
/// Documents the pre-fix behavior: with timestamp=0 in the placeholder
/// BlockIndexEntry, `block_time < (0u32 - 600)` is `block_time < u32::MAX - 599`
/// which is always false for any realistic timestamp → gate silently passes.
///
/// After the fix, callers thread the real prev_timestamp through and this
/// case should no longer arise in production. The test documents WHY the fix
/// was needed by showing what happened with the old placeholder.
#[test]
fn f16b_bip94_gate_silent_with_zero_prev_timestamp() {
    let params = ChainParams::testnet4();

    let prev_ts: u32 = 1_700_010_000;
    let block_ts: u32 = prev_ts - 601; // timewarp violation IF prev_ts is real

    let header = test_header(Hash256::ZERO, block_ts, 0x1d00ffff);

    // BUG: prev_entry.timestamp = 0 (the placeholder that was in chain_state.rs).
    let prev_entry_bug = prev_entry_with_ts(0);

    // With prev_time=0: check is `block_ts < 0i64 - 600 = -600`.
    // As u32 arithmetic: `block_ts < (0u32).wrapping_sub(600) = 0xFFFFFDA8`
    // which is false for any realistic timestamp → gate silently passes.
    let result = contextual_check_block_header(
        &header,
        2016,
        &prev_entry_bug,
        &StubChainContext,
        &params,
        0,
        None,
    );
    assert!(
        !matches!(result, Err(ValidationError::TimeTimewarpAttack)),
        "with prev_timestamp=0 (the bug) the BIP-94 gate must be silently disabled; got: {result:?}"
    );
}

/// F16-C: BIP-94 gate NOT on mainnet (enforce_bip94=false).
///
/// Mainnet uses enforce_bip94=false so the gate must never fire even if
/// the block timestamp is before the parent.
#[test]
fn f16c_bip94_not_enforced_on_mainnet() {
    let params = ChainParams::mainnet();
    assert!(!params.enforce_bip94, "mainnet must NOT enforce BIP-94");

    let prev_ts: u32 = 1_700_010_000;
    let block_ts: u32 = prev_ts - 700; // timewarp violation IF enforced

    let header = test_header(Hash256::ZERO, block_ts, 0x1d00ffff);
    let prev_entry = prev_entry_with_ts(prev_ts);

    let result = contextual_check_block_header(
        &header,
        2016,
        &prev_entry,
        &StubChainContext,
        &params,
        0,
        None,
    );
    assert!(
        !matches!(result, Err(ValidationError::TimeTimewarpAttack)),
        "BIP-94 must not be enforced on mainnet; got: {result:?}"
    );
}

/// F16-D: BIP-94 exact boundary — block_ts == prev_ts - 600 is ACCEPTED.
///
/// Core uses STRICT less-than: `block_time < prev_time - 600`.
/// So exactly `prev_time - 600` is allowed (not a violation).
#[test]
fn f16d_bip94_exactly_at_boundary_accepted() {
    let params = ChainParams::testnet4();

    let prev_ts: u32 = 1_700_010_000;
    // Exactly at boundary: block_ts = prev_ts - 600 (NOT strictly less-than 600s behind).
    let block_ts: u32 = prev_ts - 600;

    let header = test_header(Hash256::ZERO, block_ts, 0x1d00ffff);
    let prev_entry = prev_entry_with_ts(prev_ts);

    let result = contextual_check_block_header(
        &header,
        2016,
        &prev_entry,
        &StubChainContext,
        &params,
        0,
        None,
    );
    assert!(
        !matches!(result, Err(ValidationError::TimeTimewarpAttack)),
        "block at exactly prev_ts - 600 must NOT trigger BIP-94 (strict <); got: {result:?}"
    );
}

/// F16-E: BIP-94 only fires at retarget boundaries (height % 2016 == 0).
///
/// At height 2015 (non-retarget), the same timewarp-violating block
/// must be accepted.
#[test]
fn f16e_bip94_only_at_retarget_boundary() {
    let params = ChainParams::testnet4();

    let prev_ts: u32 = 1_700_010_000;
    let block_ts: u32 = prev_ts - 601; // timewarp violation at retarget boundary

    let header = test_header(Hash256::ZERO, block_ts, 0x1d00ffff);
    let prev_entry = prev_entry_with_ts(prev_ts);

    // Height 2015 is NOT a retarget boundary → BIP-94 must not fire.
    let result = contextual_check_block_header(
        &header,
        2015, // NOT % 2016 == 0
        &prev_entry,
        &StubChainContext,
        &params,
        0,
        None,
    );
    assert!(
        !matches!(result, Err(ValidationError::TimeTimewarpAttack)),
        "BIP-94 must only fire at retarget boundary (height % 2016 == 0); at 2015 got: {result:?}"
    );
}
