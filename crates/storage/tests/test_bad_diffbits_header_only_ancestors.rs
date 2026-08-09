//! `bad-diffbits` over header-only ancestors — the gate Core runs FIRST in
//! `ContextualCheckBlockHeader` (bitcoin-core/src/validation.cpp:4088):
//!
//! ```text
//! if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
//!     return state.Invalid(..., "bad-diffbits", "incorrect proof of work");
//! ```
//!
//! # What broke
//!
//! rustoshi resolved the parent's height with `BlockStore::get_height`, which
//! reads `CF_BLOCK_INDEX`. `CF_BLOCK_INDEX` is written only when a block
//! *connects* (or at assumeUTXO activation); header acceptance writes
//! `CF_HEADERS` + `CF_HEIGHT_INDEX` and nothing else. Under headers-first sync
//! every header above the connected block tip has a header-only parent, so the
//! lookup returned `None`, the helper returned `None`, and the caller read
//! `None` as "no check". The gate ran on at most one header per session; the
//! 2018-header ancestor walk behind it was dead code.
//!
//! [`legacy_expected_bits_via_get_height`] below is a faithful replica of that
//! short-circuit. Several tests assert it returns `None` on exactly the fixture
//! where the new resolver returns the right answer — that pair is the proof the
//! fix is not itself dead code.
//!
//! # Why these are mainnet/testnet4-shaped
//!
//! regtest sets `pow_no_retargeting`, so a regtest-only difficulty test passes
//! against a completely wrong implementation. Every load-bearing assertion here
//! uses mainnet (retargeting, no min-difficulty), testnet4 (min-difficulty +
//! BIP-94), or testnet3 (min-difficulty, no BIP-94) parameters. Exactly one
//! regtest test exists and it is explicitly labelled non-load-bearing.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::cell::RefCell;
use std::collections::HashMap;

use rustoshi_consensus::params::{
    compact_to_target, target_to_compact, ChainParams, DIFFICULTY_ADJUSTMENT_INTERVAL,
    MAX_TIMESPAN, MIN_TIMESPAN, TARGET_BLOCK_TIME, TARGET_TIMESPAN,
};
use rustoshi_consensus::{
    check_proof_of_work, contextual_check_block_header,
    BlockIndexEntry as ConsensusBlockIndexEntry, StubChainContext, ValidationError,
};
use rustoshi_primitives::{BlockHeader, Hash256};
use rustoshi_storage::header_context::{
    diffbits_gate_for_header, expected_bits_for_child, DiffBitsGate, ExpectedBitsError, HeaderCache,
    HeaderMeta, HeaderProvider, IndexedBlock,
};
use rustoshi_storage::{BlockStatus, BlockStore, ChainDb, StorageError};

// ---------------------------------------------------------------------------
// A `BlockIndex` shim used ONLY to compute the expected answer independently,
// with the same `rustoshi_consensus::pow` code the production path uses. If the
// expected value were recomputed by hand here, the tests would pin a
// reimplementation rather than the spec.
// ---------------------------------------------------------------------------

struct TestIndex {
    height: u32,
    timestamp: u32,
    bits: u32,
    prev: Option<Box<TestIndex>>,
}

impl rustoshi_consensus::BlockIndex for TestIndex {
    fn height(&self) -> u32 {
        self.height
    }
    fn timestamp(&self) -> u32 {
        self.timestamp
    }
    fn bits(&self) -> u32 {
        self.bits
    }
    fn prev(&self) -> Option<&Self> {
        self.prev.as_deref()
    }
    fn ancestor(&self, h: u32) -> Option<&Self> {
        if h > self.height {
            return None;
        }
        let mut cur = self;
        while cur.height > h {
            cur = cur.prev.as_deref()?;
        }
        Some(cur)
    }
}

/// Build the full `TestIndex` chain for `chain[0..=idx]` (index 0 == genesis).
fn build_test_index(chain: &[BlockHeader], upto: usize) -> Box<TestIndex> {
    let mut node: Option<Box<TestIndex>> = None;
    for (h, hdr) in chain.iter().enumerate().take(upto + 1) {
        node = Some(Box::new(TestIndex {
            height: h as u32,
            timestamp: hdr.timestamp,
            bits: hdr.bits,
            prev: node,
        }));
    }
    node.unwrap()
}

/// Independent reference answer, via the SAME `pow::get_next_work_required` the
/// production path calls, but over a fully in-memory chain.
fn reference_expected_bits(
    chain: &[BlockHeader],
    parent_idx: usize,
    new_block_time: u32,
    params: &ChainParams,
) -> u32 {
    let tip = build_test_index(chain, parent_idx);
    rustoshi_consensus::get_next_work_required(&*tip, new_block_time, params)
        .expect("reference chain is complete")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Address of `chain[i]`: genesis is addressed by `params.genesis_hash`
/// (what `init_genesis` keys CF_HEADERS by), everything else by its own hash.
fn hash_at(chain: &[BlockHeader], params: &ChainParams, i: usize) -> Hash256 {
    if i == 0 {
        params.genesis_hash
    } else {
        chain[i].block_hash()
    }
}

/// Deterministic synthetic header chain rooted at the network's real genesis.
///
/// `bits_at(height)` and `time_at(height)` let each test shape the difficulty
/// and timestamp schedule. Proof-of-work is intentionally NOT valid: none of
/// the code under test looks at the hash-vs-target relation (that is
/// "high-hash", a different check — see `pow_limit_ceiling_*` below).
fn synth_chain(
    params: &ChainParams,
    len: usize,
    bits_at: &dyn Fn(u32) -> u32,
    time_at: &dyn Fn(u32) -> u32,
) -> Vec<BlockHeader> {
    let mut chain = Vec::with_capacity(len + 1);
    chain.push(params.genesis_block.header.clone());
    for h in 1..=len as u32 {
        // Genesis is addressed by `params.genesis_hash`, which is what
        // `BlockStore::init_genesis` keys CF_HEADERS by — and which is NOT
        // always `genesis_block.header.block_hash()` (rustoshi's testnet4
        // genesis block is built with the mainnet coinbase script, so its
        // merkle root and therefore its hash disagree with the declared
        // genesis hash). Root the fixture the way production stores it.
        let prev = hash_at(&chain, params, (h - 1) as usize);
        chain.push(BlockHeader {
            version: 0x2000_0000u32 as i32,
            prev_block_hash: prev,
            merkle_root: Hash256([h as u8; 32]),
            timestamp: time_at(h),
            bits: bits_at(h),
            nonce: h,
        });
    }
    chain
}

/// In-memory provider that serves ONLY headers — the exact storage shape
/// headers-first sync produces above the connected block tip. Optionally holds
/// a handful of authoritative block-index entries (connected blocks / snapshot
/// base). Counts reads so the performance guard can assert the window stayed
/// lazy.
#[derive(Default)]
struct HeaderOnlyProvider {
    headers: HashMap<Hash256, HeaderMeta>,
    indexed: HashMap<Hash256, IndexedBlock>,
    header_reads: RefCell<u64>,
    index_reads: RefCell<u64>,
}

impl HeaderOnlyProvider {
    fn from_chain(chain: &[BlockHeader], params: &ChainParams) -> Self {
        let mut p = Self::default();
        for (i, hdr) in chain.iter().enumerate() {
            p.put_at(hash_at(chain, params, i), hdr);
        }
        p
    }
    fn put(&mut self, hdr: &BlockHeader) {
        self.put_at(hdr.block_hash(), hdr);
    }
    fn put_at(&mut self, hash: Hash256, hdr: &BlockHeader) {
        self.headers.insert(
            hash,
            HeaderMeta {
                bits: hdr.bits,
                timestamp: hdr.timestamp,
                prev_hash: hdr.prev_block_hash,
            },
        );
    }
    fn forget(&mut self, hash: &Hash256) {
        self.headers.remove(hash);
    }
    fn index(&mut self, hash: Hash256, height: u32, bits: u32) {
        self.indexed.insert(hash, IndexedBlock { height, bits });
    }
    fn reset_counters(&self) {
        *self.header_reads.borrow_mut() = 0;
        *self.index_reads.borrow_mut() = 0;
    }
    fn header_reads(&self) -> u64 {
        *self.header_reads.borrow()
    }
}

impl HeaderProvider for HeaderOnlyProvider {
    fn header_meta(&self, hash: &Hash256) -> Result<Option<HeaderMeta>, StorageError> {
        *self.header_reads.borrow_mut() += 1;
        Ok(self.headers.get(hash).copied())
    }
    fn indexed_block(&self, hash: &Hash256) -> Result<Option<IndexedBlock>, StorageError> {
        *self.index_reads.borrow_mut() += 1;
        Ok(self.indexed.get(hash).copied())
    }
}

/// Faithful replica of the deleted `compute_expected_bits_via_store` prologue
/// (`rustoshi/src/main.rs` and `crates/rpc/src/server.rs`, both identical).
/// The whole bug is in these five lines: `get_height` reads `CF_BLOCK_INDEX`,
/// which header-only ancestors never populate, and `None` meant "skip".
fn legacy_expected_bits_via_get_height(store: &BlockStore, parent_hash: &Hash256) -> Option<u32> {
    // let parent_header = match block_store.get_header(parent_hash) { Ok(Some(h)) => h, _ => return None };
    store.get_header(parent_hash).ok().flatten()?;
    // let parent_height = match block_store.get_height(parent_hash) { Ok(Some(h)) => h, _ => return None };
    let _parent_height = match store.get_height(parent_hash) {
        Ok(Some(h)) => h,
        _ => return None, // <-- THE FAIL-OPEN
    };
    // ... (walk + get_next_work_required, unreachable in the header-only case)
    Some(0)
}

fn open_store(dir: &std::path::Path) -> ChainDb {
    ChainDb::open(dir).expect("open chaindb")
}

fn mainnet_min_bits() -> u32 {
    target_to_compact(&ChainParams::mainnet().pow_limit)
}

// ---------------------------------------------------------------------------
// 1. REGRESSION — the test that fails without the fix.
// ---------------------------------------------------------------------------

/// MAINNET, non-boundary, ALL ancestors header-only (`put_header` only, never
/// `put_block_index`) — exactly the storage shape headers-first sync produces.
///
/// * The legacy resolver returns `None` (gate skipped — the vulnerability).
/// * The new resolver returns the parent's bits (Core `GetNextWorkRequired`
///   non-boundary arm: `return pindexLast->nBits`).
/// * A header carrying any other nBits is rejected `bad-diffbits`.
#[test]
fn regression_mainnet_non_boundary_header_only_ancestors() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32; // a real historical mainnet difficulty
    let chain = synth_chain(
        &params,
        100,
        &|_h| bits,
        &|h| 1_300_000_000 + h * TARGET_BLOCK_TIME,
    );

    let dir = tempfile::tempdir().unwrap();
    let db = open_store(dir.path());
    let store = BlockStore::new(&db);
    // Header acceptance writes CF_HEADERS + CF_HEIGHT_INDEX and NOTHING else.
    for (h, hdr) in chain.iter().enumerate() {
        let hash = hash_at(&chain, &params, h);
        store.put_header(&hash, hdr).unwrap();
        store.put_height_index(h as u32, &hash).unwrap();
    }

    let parent_hash = chain[100].block_hash();

    // --- what the code did before this fix -------------------------------
    assert_eq!(
        store.get_height(&parent_hash).unwrap(),
        None,
        "precondition: a header-only parent has NO CF_BLOCK_INDEX entry"
    );
    assert_eq!(
        legacy_expected_bits_via_get_height(&store, &parent_hash),
        None,
        "the legacy resolver fails open here — this is the bug being fixed"
    );

    // --- what it does now -------------------------------------------------
    let mut cache = HeaderCache::default();
    let got = expected_bits_for_child(
        &store,
        &mut cache,
        &parent_hash,
        Some(100),
        chain[100].timestamp + TARGET_BLOCK_TIME,
        &params,
    )
    .expect("header-only ancestors must resolve by prev_block_hash pointers");
    assert_eq!(got, bits, "non-boundary mainnet: expected == parent.nBits");

    // --- and the gate now actually rejects --------------------------------
    let mut child = chain[100].clone();
    child.prev_block_hash = parent_hash;
    child.timestamp = chain[100].timestamp + TARGET_BLOCK_TIME;
    child.bits = 0x1d00_ffff; // difficulty 1 — the attack
    let res = contextual_check_block_header(
        &child,
        101,
        &dummy_prev(),
        &StubChainContext,
        &params,
        0,
        Some(got),
    );
    assert_eq!(res, Err(ValidationError::BadDifficulty));
    assert_eq!(res.unwrap_err().bip22_string(), "bad-diffbits");

    // The honest value passes.
    child.bits = bits;
    assert!(contextual_check_block_header(
        &child,
        101,
        &dummy_prev(),
        &StubChainContext,
        &params,
        0,
        Some(got)
    )
    .is_ok());
}

fn dummy_prev() -> ConsensusBlockIndexEntry {
    ConsensusBlockIndexEntry {
        height: 0,
        timestamp: 0,
        bits: 0,
        prev_hash: Hash256::ZERO,
        chain_work: [0u8; 32],
    }
}

/// The same regression, one layer up: `diffbits_gate_for_header` (what the
/// production header path actually calls) must return `Required(..)` — NOT a
/// degraded/skip outcome — for a fully header-only mainnet chain.
#[test]
fn regression_gate_is_required_not_degraded_for_header_only_chain() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let chain = synth_chain(&params, 50, &|_| bits, &|h| 1_300_000_000 + h * 600);
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::default();

    let gate = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &chain[50].block_hash(),
        bits,
        chain[50].timestamp + 600,
        51,
        Some(50),
        &params,
    )
    .expect("must not error");
    assert_eq!(
        gate,
        DiffBitsGate::Required(bits),
        "the gate must be ENFORCED on header-only ancestors, not degraded"
    );
}

// ---------------------------------------------------------------------------
// 2. MAINNET RETARGET BOUNDARY (header-only ancestors)
// ---------------------------------------------------------------------------

#[test]
fn mainnet_retarget_boundary_header_only_ancestors() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    // Exactly on schedule: 2016 blocks x 600 s == TARGET_TIMESPAN, so the
    // retarget is a no-op except for compact rounding.
    let chain = synth_chain(
        &params,
        2016,
        &|_| bits,
        &|h| 1_300_000_000 + h * TARGET_BLOCK_TIME,
    );
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::default();

    let parent_idx = 2016usize; // child height 2017? no: parent 2015 -> child 2016
    let _ = parent_idx;
    // The BOUNDARY child is the one at height 2016, whose parent is 2015.
    let parent = &chain[2015];
    let child_time = parent.timestamp + TARGET_BLOCK_TIME;

    let got = expected_bits_for_child(
        &provider,
        &mut cache,
        &parent.block_hash(),
        Some(2015),
        child_time,
        &params,
    )
    .expect("2016-header window must be walkable by pointers");

    let want = reference_expected_bits(&chain, 2015, child_time, &params);
    assert_eq!(got, want, "boundary value must match pow::get_next_work_required");

    // And drive the gate: any other nBits is rejected.
    let mut child = chain[2016].clone();
    child.bits = bits.wrapping_add(1);
    let res = contextual_check_block_header(
        &child,
        2016,
        &dummy_prev(),
        &StubChainContext,
        &params,
        0,
        Some(got),
    );
    assert_eq!(res.unwrap_err().bip22_string(), "bad-diffbits");
}

/// The boundary walk must go through pointers only — assert it materialised the
/// full 2016-header window (2016 header reads on a cold cache) and produced the
/// same answer with the height index absent entirely.
#[test]
fn mainnet_boundary_walks_2016_ancestors_by_pointer() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 600);
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::new(0); // caching disabled: count raw reads
    provider.reset_counters();

    let parent = &chain[2015];
    let _ = expected_bits_for_child(
        &provider,
        &mut cache,
        &parent.block_hash(),
        Some(2015),
        parent.timestamp + 600,
        &params,
    )
    .unwrap();
    assert_eq!(
        provider.header_reads(),
        2016,
        "boundary window is exactly parent..parent-2015 inclusive"
    );
}

// ---------------------------------------------------------------------------
// 3. MAINNET CLAMP ARMS
// ---------------------------------------------------------------------------

/// Core `CalculateNextWorkRequired`: `nActualTimespan` is clamped to
/// `[nPowTargetTimespan/4, nPowTargetTimespan*4]`.
///
/// The boundary under test is the child at height 4032, whose period is
/// [2016, 4031]. Height 2016 (not genesis) is `pindexFirst`, so the fixture
/// fully controls the period's start timestamp — using the height-2016 boundary
/// instead would make `pindexFirst` the REAL genesis header, whose timestamp is
/// decades away and would silently pin the max clamp in both arms.
#[test]
fn mainnet_boundary_clamp_arms() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    const N: usize = 4032;

    // Blocks 0..=2016 on a normal 600 s schedule; the period under test then
    // runs fast (1 s spacing -> below MIN_TIMESPAN) or slow (60_000 s spacing ->
    // above MAX_TIMESPAN).
    let fast = synth_chain(&params, N, &|_| bits, &|h| {
        if h <= 2016 {
            1_300_000_000 + h * 600
        } else {
            1_300_000_000 + 2016 * 600 + (h - 2016)
        }
    });
    let slow = synth_chain(&params, N, &|_| bits, &|h| {
        if h <= 2016 {
            1_300_000_000 + h * 600
        } else {
            1_300_000_000 + 2016 * 600 + (h - 2016) * 60_000
        }
    });

    let mut answers = Vec::new();
    for (label, chain) in [("fast/min-clamp", &fast), ("slow/max-clamp", &slow)] {
        let provider = HeaderOnlyProvider::from_chain(chain, &params);
        let mut cache = HeaderCache::default();
        let parent = &chain[4031];
        let child_time = parent.timestamp + 600;
        let got = expected_bits_for_child(
            &provider,
            &mut cache,
            &parent.block_hash(),
            Some(4031),
            child_time,
            &params,
        )
        .unwrap();
        // Cross-check against pow::get_next_work_required over the same chain.
        let want = reference_expected_bits(chain, 4031, child_time, &params);
        assert_eq!(got, want, "{label}");
        answers.push(got);
    }

    let base = compact_to_target(bits);
    let fast_target = compact_to_target(answers[0]);
    let slow_target = compact_to_target(answers[1]);
    assert!(
        cmp_target(&fast_target, &base) < 0,
        "MIN_TIMESPAN clamp must make the target HARDER (smaller): {:#010x} vs {:#010x}",
        answers[0],
        bits
    );
    assert!(
        cmp_target(&slow_target, &base) > 0,
        "MAX_TIMESPAN clamp must make the target EASIER (larger): {:#010x} vs {:#010x}",
        answers[1],
        bits
    );
    // Pin the clamp magnitudes Core uses.
    assert_eq!(MIN_TIMESPAN, TARGET_TIMESPAN / 4);
    assert_eq!(MAX_TIMESPAN, TARGET_TIMESPAN * 4);
    // And pin that the clamps, not the raw timespans, produced these: exactly
    // 4x harder / 4x easier (modulo compact-encoding rounding).
    let quarter = mul_div_target(&base, 1, 4);
    let quadruple = mul_div_target(&base, 4, 1);
    assert_eq!(
        answers[0],
        target_to_compact(&quarter),
        "min clamp must yield target/4"
    );
    assert_eq!(
        answers[1],
        target_to_compact(&quadruple),
        "max clamp must yield target*4"
    );
}

/// target * num / den on a 32-byte big-endian value (test-local, only used to
/// pin the 4x / one-quarter clamp magnitudes).
fn mul_div_target(t: &[u8; 32], num: u32, den: u32) -> [u8; 32] {
    let mut words = [0u128; 32];
    for (i, b) in t.iter().enumerate() {
        words[i] = *b as u128;
    }
    // multiply
    let mut carry = 0u128;
    for i in (0..32).rev() {
        let v = words[i] * num as u128 + carry;
        words[i] = v & 0xff;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "overflow in test helper");
    // divide
    let mut rem = 0u128;
    for w in words.iter_mut() {
        let cur = (rem << 8) | *w;
        *w = cur / den as u128;
        rem = cur % den as u128;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = words[i] as u8;
    }
    out
}

/// A retarget that would push the target past `powLimit` must clamp to
/// `powLimit` (Core: `if (bnNew > bnPowLimit) bnNew = bnPowLimit;`).
#[test]
fn mainnet_boundary_clamps_to_pow_limit() {
    let params = ChainParams::mainnet();
    // Start already AT the mainnet minimum difficulty, then produce blocks far
    // too slowly: the 4x-easier retarget would exceed pow_limit.
    let bits = mainnet_min_bits();
    let chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 60_000);
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::default();
    let parent = &chain[2015];
    let got = expected_bits_for_child(
        &provider,
        &mut cache,
        &parent.block_hash(),
        Some(2015),
        parent.timestamp + 600,
        &params,
    )
    .unwrap();
    assert_eq!(
        got,
        target_to_compact(&params.pow_limit),
        "retarget must clamp to pow_limit"
    );
}

fn cmp_target(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] != b[i] {
            return if a[i] < b[i] { -1 } else { 1 };
        }
    }
    0
}

// ---------------------------------------------------------------------------
// 4. TESTNET4 20-MINUTE RULE (both arms), header-only ancestors
// ---------------------------------------------------------------------------

#[test]
fn testnet4_min_difficulty_rule_both_arms() {
    let params = ChainParams::testnet4();
    let pow_limit_bits = target_to_compact(&params.pow_limit);
    let real_bits = 0x1c00_ffffu32; // harder than pow_limit

    // Heights 1..=90: the last non-min-difficulty block is height 90 - N.
    // Build: 1..=85 at real difficulty, 86..=90 at pow_limit (min-difficulty
    // blocks produced under the 20-minute rule).
    let chain = synth_chain(
        &params,
        90,
        &|h| {
            if h >= 86 {
                pow_limit_bits
            } else {
                real_bits
            }
        },
        &|h| 1_700_000_000 + h * 600,
    );
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let parent = &chain[90];

    // (a) child timestamp MORE than 20 min after parent -> min-difficulty.
    // Core: `if (pblock->GetBlockTime() > pindexLast->GetBlockTime() +
    //           params.nPowTargetSpacing*2) return nProofOfWorkLimit;`
    let mut cache = HeaderCache::default();
    let late = expected_bits_for_child(
        &provider,
        &mut cache,
        &parent.block_hash(),
        Some(90),
        parent.timestamp + TARGET_BLOCK_TIME * 2 + 1,
        &params,
    )
    .unwrap();
    assert_eq!(late, pow_limit_bits, "20-minute rule: min-difficulty allowed");

    // (b) child timestamp WITHIN 20 min -> walk back past every min-difficulty
    //     ancestor to the last real one (height 85).
    let mut cache = HeaderCache::default();
    let ontime = expected_bits_for_child(
        &provider,
        &mut cache,
        &parent.block_hash(),
        Some(90),
        parent.timestamp + TARGET_BLOCK_TIME,
        &params,
    )
    .unwrap();
    assert_eq!(
        ontime, real_bits,
        "walk-back must return the last non-min-difficulty ancestor's bits"
    );
    assert_ne!(
        ontime, pow_limit_bits,
        "if these were equal the walk-back would be untested"
    );
    // The walk genuinely crossed more than one ancestor (90, 89, 88, 87, 86, 85).
    let want = reference_expected_bits(&chain, 90, parent.timestamp + TARGET_BLOCK_TIME, &params);
    assert_eq!(ontime, want);

    // Exactly at the boundary (+1200 s) is NOT "more than", so it takes the
    // walk-back arm — Core uses a strict `>`.
    let mut cache = HeaderCache::default();
    let exact = expected_bits_for_child(
        &provider,
        &mut cache,
        &parent.block_hash(),
        Some(90),
        parent.timestamp + TARGET_BLOCK_TIME * 2,
        &params,
    )
    .unwrap();
    assert_eq!(exact, real_bits, "`>` is strict: +1200s is still walk-back");
}

// ---------------------------------------------------------------------------
// 5. TESTNET4 BIP-94 vs TESTNET3 — the flag must actually be consulted
// ---------------------------------------------------------------------------

/// Core `CalculateNextWorkRequired`:
/// ```text
/// if (params.enforce_BIP94) { ... bnNew.SetCompact(pindexFirst->nBits); }
/// else                      {     bnNew.SetCompact(pindexLast->nBits);  }
/// ```
/// testnet4 sets `enforce_BIP94`; testnet3 does not. Build a period whose FIRST
/// and LAST blocks carry different bits and assert the two networks disagree.
#[test]
fn testnet4_bip94_uses_first_of_period_testnet3_uses_last() {
    let first_bits = 0x1c00_ffffu32;
    let last_bits = 0x1d00_7fffu32;
    assert_ne!(first_bits, last_bits);

    // Period for the child at height 2016 is [0, 2015]; pindexFirst is height 0
    // (`next - 2016`). Give height 0..=1000 `first_bits` and 1001..=2015
    // `last_bits` — but height 0 is genesis and its bits are fixed by
    // chainparams, so use the child at height 4032 instead, whose period is
    // [2016, 4031].
    let bits_at = move |h: u32| {
        if h < 2016 {
            0x1d00_ffffu32
        } else if h < 3000 {
            first_bits
        } else {
            last_bits
        }
    };
    let time_at = |h: u32| 1_700_000_000 + h * 600;

    let t4 = ChainParams::testnet4();
    let t3 = ChainParams::testnet3();
    let chain4 = synth_chain(&t4, 4032, &bits_at, &time_at);
    let chain3 = synth_chain(&t3, 4032, &bits_at, &time_at);

    // Keep the child within 20 minutes of its parent so the min-difficulty
    // short-circuit cannot pre-empt the boundary arm (the boundary check comes
    // first in Core anyway, but be explicit).
    let child_time4 = chain4[4031].timestamp + 600;
    let child_time3 = chain3[4031].timestamp + 600;

    let p4 = HeaderOnlyProvider::from_chain(&chain4, &t4);
    let mut c4 = HeaderCache::default();
    let got4 = expected_bits_for_child(
        &p4,
        &mut c4,
        &chain4[4031].block_hash(),
        Some(4031),
        child_time4,
        &t4,
    )
    .unwrap();

    let p3 = HeaderOnlyProvider::from_chain(&chain3, &t3);
    let mut c3 = HeaderCache::default();
    let got3 = expected_bits_for_child(
        &p3,
        &mut c3,
        &chain3[4031].block_hash(),
        Some(4031),
        child_time3,
        &t3,
    )
    .unwrap();

    assert_eq!(got4, reference_expected_bits(&chain4, 4031, child_time4, &t4));
    assert_eq!(got3, reference_expected_bits(&chain3, 4031, child_time3, &t3));
    assert_ne!(
        got4, got3,
        "BIP-94 must change the answer: testnet4 bases on the FIRST block of the \
         period, testnet3 on the LAST"
    );

    // And pin the direction: first_bits is HARDER than last_bits, so the
    // BIP-94 (testnet4) answer must be the harder of the two.
    assert!(
        cmp_target(&compact_to_target(got4), &compact_to_target(got3)) < 0,
        "testnet4 (first-of-period base, harder) must yield the smaller target"
    );
}

// ---------------------------------------------------------------------------
// 6. POISON IMMUNITY
// ---------------------------------------------------------------------------

/// Constraint 2: retarget ancestors must be resolved by PARENT POINTERS, never
/// through the height→hash index. That index is attacker-poisonable (header
/// acceptance writes it, and rustoshi keeps one hash per height so a fork
/// overwrites slots) and it does not cover headers ahead of the validated tip.
///
/// Structural half: [`HeaderProvider`] exposes no height→hash method at all, so
/// the resolver *cannot* consult it. Behavioural half: fill every slot in the
/// window with an attacker hash and assert the answers are byte-identical.
#[test]
fn poison_immunity_height_index_is_never_consulted() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 600);

    let dir = tempfile::tempdir().unwrap();
    let db = open_store(dir.path());
    let store = BlockStore::new(&db);
    for (h, hdr) in chain.iter().enumerate() {
        let hash = hash_at(&chain, &params, h);
        store.put_header(&hash, hdr).unwrap();
        store.put_height_index(h as u32, &hash).unwrap();
    }

    let non_boundary_parent = chain[100].block_hash();
    let boundary_parent = chain[2015].block_hash();

    let mut cache = HeaderCache::default();
    let clean_nb = expected_bits_for_child(
        &store,
        &mut cache,
        &non_boundary_parent,
        Some(100),
        chain[100].timestamp + 600,
        &params,
    )
    .unwrap();
    let mut cache = HeaderCache::default();
    let clean_b = expected_bits_for_child(
        &store,
        &mut cache,
        &boundary_parent,
        Some(2015),
        chain[2015].timestamp + 600,
        &params,
    )
    .unwrap();

    // POISON: overwrite every height slot in the window with attacker hashes.
    for h in 0..=2016u32 {
        let mut attacker = [0u8; 32];
        attacker[0..4].copy_from_slice(&h.to_le_bytes());
        attacker[31] = 0xAB;
        store.put_height_index(h, &Hash256(attacker)).unwrap();
    }
    for h in 0..=2016u32 {
        assert_ne!(
            store.get_hash_by_height(h).unwrap().unwrap(),
            hash_at(&chain, &params, h as usize),
            "precondition: the height index really is poisoned at {h}"
        );
    }

    let mut cache = HeaderCache::default();
    let poisoned_nb = expected_bits_for_child(
        &store,
        &mut cache,
        &non_boundary_parent,
        Some(100),
        chain[100].timestamp + 600,
        &params,
    )
    .unwrap();
    let mut cache = HeaderCache::default();
    let poisoned_b = expected_bits_for_child(
        &store,
        &mut cache,
        &boundary_parent,
        Some(2015),
        chain[2015].timestamp + 600,
        &params,
    )
    .unwrap();

    assert_eq!(clean_nb, poisoned_nb, "non-boundary answer must be poison-immune");
    assert_eq!(clean_b, poisoned_b, "boundary answer must be poison-immune");
}

/// A pointer-derived height that disagrees with the authoritative
/// `CF_BLOCK_INDEX` height must FAIL CLOSED, not silently pick a winner.
#[test]
fn height_inconsistency_fails_closed() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 600);
    let mut provider = HeaderOnlyProvider::from_chain(&chain, &params);
    // Claim that the ancestor at height 1000 is really at height 999.
    provider.index(chain[1000].block_hash(), 999, bits);

    let mut cache = HeaderCache::default();
    let err = expected_bits_for_child(
        &provider,
        &mut cache,
        &chain[2015].block_hash(),
        Some(2015),
        chain[2015].timestamp + 600,
        &params,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExpectedBitsError::HeightInconsistent { derived: 1000, indexed: 999, .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. FAIL-CLOSED + the one carve-out
// ---------------------------------------------------------------------------

/// A gap in the retarget window whose terminal ancestor is NOT a configured
/// snapshot base must be rejected, not skipped.
#[test]
fn ancestor_gap_without_snapshot_base_is_rejected() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 600);
    let mut provider = HeaderOnlyProvider::from_chain(&chain, &params);
    provider.forget(&chain[500].block_hash()); // hole inside the window

    let mut cache = HeaderCache::default();
    let err = expected_bits_for_child(
        &provider,
        &mut cache,
        &chain[2015].block_hash(),
        Some(2015),
        chain[2015].timestamp + 600,
        &params,
    )
    .unwrap_err();
    match err {
        ExpectedBitsError::AncestorGap {
            deepest_height,
            missing_height,
            needed_height,
            ..
        } => {
            assert_eq!(deepest_height, 501);
            assert_eq!(missing_height, 500);
            assert_eq!(needed_height, 0);
        }
        other => panic!("expected AncestorGap, got {other:?}"),
    }

    // And the caller-facing gate REJECTS (does not degrade, does not skip).
    let mut cache = HeaderCache::default();
    let reason = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &chain[2015].block_hash(),
        bits,
        chain[2015].timestamp + 600,
        2016,
        Some(2015),
        &params,
    )
    .unwrap_err();
    assert!(reason.starts_with("bad-diffbits"), "got {reason}");
}

/// An unknown parent header is a rejection too — never a skip.
#[test]
fn unknown_parent_header_is_rejected() {
    let params = ChainParams::mainnet();
    let provider = HeaderOnlyProvider::default();
    let mut cache = HeaderCache::default();
    let err = expected_bits_for_child(
        &provider,
        &mut cache,
        &Hash256([0x77; 32]),
        Some(10),
        1_700_000_000,
        &params,
    )
    .unwrap_err();
    assert!(matches!(err, ExpectedBitsError::ParentHeaderUnknown(_)));

    let mut cache = HeaderCache::default();
    assert!(diffbits_gate_for_header(
        &provider,
        &mut cache,
        &Hash256([0x77; 32]),
        0x1d00_ffff,
        1_700_000_000,
        11,
        Some(10),
        &params
    )
    .is_err());
}

/// With no hint and no reachable genesis/index anchor, the height is
/// unresolvable — reject.
#[test]
fn unresolvable_height_without_hint_is_rejected() {
    let params = ChainParams::mainnet();
    // A free-floating header whose parent is not stored and which is not
    // genesis: nothing anchors it.
    let orphan = BlockHeader {
        version: 0x2000_0000u32 as i32,
        prev_block_hash: Hash256([0x99; 32]),
        merkle_root: Hash256([1u8; 32]),
        timestamp: 1_700_000_000,
        bits: 0x1b04_864c,
        nonce: 7,
    };
    let mut provider = HeaderOnlyProvider::default();
    provider.put(&orphan);

    let mut cache = HeaderCache::default();
    let err = expected_bits_for_child(
        &provider,
        &mut cache,
        &orphan.block_hash(),
        None,
        1_700_000_600,
        &params,
    )
    .unwrap_err();
    assert!(matches!(err, ExpectedBitsError::ParentHeightUnresolved(_)), "got {err:?}");
}

/// THE ONLY CARVE-OUT. When the window terminates at a hard-coded assumeUTXO
/// snapshot base from chainparams, the gate degrades to Core's
/// `PermittedDifficultyTransition` (pow.cpp) — which is a REAL check, not a
/// skip: a transition outside the 4x / one-quarter bound is still rejected.
///
/// An attacker cannot steer into this: the predicate is equality against a
/// built-in block hash.
#[test]
fn snapshot_base_carveout_degrades_to_permitted_transition_not_to_nothing() {
    let params = ChainParams::mainnet();
    let base = params
        .assumeutxo_data
        .first()
        .expect("mainnet ships assumeUTXO entries")
        .clone();
    let bits = 0x1b04_864cu32;

    // A chain whose deepest reachable ancestor's PARENT is the snapshot base:
    // exactly the `--load-snapshot` shape (no headers below the base).
    let mut chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 600);
    // Splice: make height 500's parent pointer the snapshot base hash and drop
    // everything below it from the provider.
    chain[500].prev_block_hash = base.blockhash;
    for h in 501..=2016usize {
        let prev = chain[h - 1].block_hash();
        chain[h].prev_block_hash = prev;
    }
    let mut provider = HeaderOnlyProvider::default();
    for hdr in chain.iter().skip(500) {
        provider.put(hdr);
    }

    // Non-boundary transition (nBits must be unchanged) — honest value passes.
    let mut cache = HeaderCache::default();
    let gate = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &chain[2015].block_hash(),
        bits,
        chain[2015].timestamp + 600,
        2016,
        Some(2015),
        &params,
    )
    .expect("carve-out applies at a configured snapshot base");
    assert_eq!(gate, DiffBitsGate::DegradedSnapshotBase);

    // ...and a transition outside the permitted bound is STILL REJECTED. Height
    // 2016 is a retarget boundary, so PermittedDifficultyTransition bounds the
    // change to [1/4x, 4x] of the parent target; difficulty-1 is far easier.
    let mut cache = HeaderCache::default();
    let reason = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &chain[2015].block_hash(),
        0x1d00_ffff,
        chain[2015].timestamp + 600,
        2016,
        Some(2015),
        &params,
    )
    .unwrap_err();
    assert!(
        reason.starts_with("bad-diffbits"),
        "the degraded path must still reject an out-of-bounds transition, got {reason}"
    );
}

/// The `--load-snapshot` boot shape for the FIRST post-snapshot header: the
/// parent IS the base and its header was never downloaded. Must degrade (not
/// wedge the node by rejecting every header), and must still reject an
/// out-of-bounds transition when the base's indexed nBits is known.
#[test]
fn snapshot_base_as_direct_parent_degrades_rather_than_wedging() {
    let params = ChainParams::mainnet();
    let base = params.assumeutxo_data.first().unwrap().clone();
    let bits = 0x1702_1b10u32;

    let mut provider = HeaderOnlyProvider::default();
    // Only CF_BLOCK_INDEX exists for the base (what snapshot activation writes),
    // with real bits (the case where AssumeutxoData::base_tail_headers was
    // supplied).
    provider.index(base.blockhash, base.height, bits);

    let mut cache = HeaderCache::default();
    let gate = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &base.blockhash,
        bits,
        1_700_000_000,
        base.height + 1,
        Some(base.height),
        &params,
    )
    .expect("must not wedge the snapshot boot");
    assert_eq!(gate, DiffBitsGate::DegradedSnapshotBase);

    // base.height + 1 is not a retarget boundary, so nBits must be unchanged.
    assert!(
        (base.height + 1) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0,
        "fixture assumption"
    );
    let mut cache = HeaderCache::default();
    let reason = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &base.blockhash,
        0x1d00_ffff,
        1_700_000_000,
        base.height + 1,
        Some(base.height),
        &params,
    )
    .unwrap_err();
    assert!(reason.starts_with("bad-diffbits"), "got {reason}");
}

/// The carve-out predicate is a chainparams hash. A near-miss (any other
/// terminal hash) gets no carve-out.
#[test]
fn carveout_predicate_is_not_steerable() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let mut chain = synth_chain(&params, 2016, &|_| bits, &|h| 1_300_000_000 + h * 600);
    // Attacker-chosen terminal ancestor (not a chainparams snapshot base).
    chain[500].prev_block_hash = Hash256([0xEE; 32]);
    for h in 501..=2016usize {
        let prev = chain[h - 1].block_hash();
        chain[h].prev_block_hash = prev;
    }
    let mut provider = HeaderOnlyProvider::default();
    for hdr in chain.iter().skip(500) {
        provider.put(hdr);
    }
    let mut cache = HeaderCache::default();
    let reason = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &chain[2015].block_hash(),
        bits,
        chain[2015].timestamp + 600,
        2016,
        Some(2015),
        &params,
    )
    .unwrap_err();
    assert!(reason.starts_with("bad-diffbits"), "got {reason}");
}

// ---------------------------------------------------------------------------
// 8. pow_limit CEILING — the header-path "high-hash" hole
// ---------------------------------------------------------------------------

/// `BlockHeader::validate_pow_against_declared_target` compares the hash to the
/// target the header DECLARES and never bounds that target by `pow_limit`
/// (bitcoin-core/src/pow.cpp `DeriveTarget`). `HeaderSync` calls only that, so
/// before this change a peer could declare nBits easier than the mainnet
/// minimum (0x1d00ffff) and mine the header trivially.
///
/// This pins the exact hole and the fix: `check_proof_of_work` (now called on
/// the header path in `rustoshi/src/main.rs` before the contextual gates)
/// rejects it.
#[test]
fn pow_limit_ceiling_header_path() {
    let params = ChainParams::mainnet();
    // 0x2000ffff -> target 0x0000ffff_0000...  (way easier than 0x1d00ffff).
    let easy_bits = 0x2000_ffffu32;

    let mut header = BlockHeader {
        version: 0x2000_0000u32 as i32,
        prev_block_hash: Hash256([0x11; 32]),
        merkle_root: Hash256([0x22; 32]),
        timestamp: 1_700_000_000,
        bits: easy_bits,
        nonce: 0,
    };
    // "Mine" it: with this target we need only the top big-endian byte of the
    // hash to be zero (== the LAST byte of the internal little-endian hash).
    let mut found = false;
    for nonce in 0..2_000_000u32 {
        header.nonce = nonce;
        if header.block_hash().0[31] == 0 {
            found = true;
            break;
        }
    }
    assert!(found, "grinding one zero byte must succeed");

    assert!(
        header.validate_pow_against_declared_target(),
        "THE HOLE: the params-free check accepts an easier-than-pow_limit target"
    );
    assert!(
        !check_proof_of_work(header.block_hash().as_bytes(), header.bits, &params),
        "THE FIX: check_proof_of_work enforces target <= pow_limit"
    );

    // The fix must not false-reject the honest mainnet minimum: 0x1d00ffff
    // decodes to a target at or below `pow_limit` (Core's mainnet powLimit is
    // 0x00000000ffff...ffff, and 0x1d00ffff is its compact form rounded down,
    // so the round trip is lossy in the SAFE direction).
    assert!(
        cmp_target(&compact_to_target(mainnet_min_bits()), &params.pow_limit) <= 0,
        "the ceiling must accept the network minimum"
    );
    let mut at_limit = header.clone();
    at_limit.bits = mainnet_min_bits();
    // (hash won't meet it; we are asserting the TARGET bound, not the hash.)
    assert!(
        compact_to_target(at_limit.bits) != [0u8; 32],
        "0x1d00ffff must be a structurally valid compact target"
    );
}

// ---------------------------------------------------------------------------
// 9. PERFORMANCE GUARD
// ---------------------------------------------------------------------------

/// The 2018-header walk used to be dead code; it is now live on every header.
/// Guard the amortised cost so the lazy window cannot silently regress back to
/// an eager full-interval walk.
///
/// 4032 mainnet-shaped headers = 4030 non-boundary (1 read each) + 2 boundaries
/// (2016 each, minus cache hits). With the cache on, the second boundary's
/// window is partly resident.
#[test]
fn performance_guard_amortised_reads_per_header() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let n = 4032usize;
    let chain = synth_chain(&params, n, &|_| bits, &|h| 1_300_000_000 + h * 600);
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::default();
    provider.reset_counters();

    for child_height in 1..=n as u32 {
        let parent_idx = (child_height - 1) as usize;
        let _ = expected_bits_for_child(
            &provider,
            &mut cache,
            &chain[parent_idx].block_hash(),
            Some(child_height - 1),
            chain[parent_idx].timestamp + 600,
            &params,
        )
        .unwrap();
    }

    let reads = provider.header_reads();
    let budget = 2 * n as u64;
    assert!(
        reads <= budget,
        "header reads {reads} exceed the ~2/header budget ({budget}) for {n} headers — \
         the retarget window is no longer lazy"
    );
    // And it must not be trivially small either (that would mean the window
    // never materialised at all).
    assert!(reads >= n as u64, "reads {reads} < {n}: the parent was not even read");
}

// ---------------------------------------------------------------------------
// 10. REGTEST — explicitly NON-LOAD-BEARING
// ---------------------------------------------------------------------------

/// regtest sets `pow_no_retargeting`, so `CalculateNextWorkRequired` returns
/// `pindexLast->nBits` unconditionally and a WRONG implementation passes this
/// test. It exists only to prove the code path does not panic / error on the
/// network the smoke harness uses. It proves nothing about difficulty.
#[test]
fn regtest_sanity_non_load_bearing() {
    let params = ChainParams::regtest();
    let bits = target_to_compact(&params.pow_limit);
    let chain = synth_chain(&params, 20, &|_| bits, &|h| 1_700_000_000 + h * 600);
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::default();
    let got = expected_bits_for_child(
        &provider,
        &mut cache,
        &chain[20].block_hash(),
        Some(20),
        chain[20].timestamp + 600,
        &params,
    )
    .unwrap();
    assert_eq!(got, bits);
}

// ---------------------------------------------------------------------------
// 11. Genesis-adjacent + hintless resolution
// ---------------------------------------------------------------------------

/// Height 1's parent is genesis: resolved by hash equality against
/// `params.genesis_hash`, with no index, no hint and no walk.
#[test]
fn genesis_parent_resolves_without_index_or_hint() {
    for params in [ChainParams::mainnet(), ChainParams::testnet4()] {
        let bits = params.genesis_block.header.bits;
        let chain = synth_chain(&params, 1, &|_| bits, &|h| {
            params.genesis_block.header.timestamp + h * 600
        });
        let provider = HeaderOnlyProvider::from_chain(&chain, &params);
        let mut cache = HeaderCache::default();
        let got = expected_bits_for_child(
            &provider,
            &mut cache,
            &params.genesis_hash,
            None, // no hint at all
            params.genesis_block.header.timestamp + 600,
            &params,
        )
        .expect("genesis parent must always resolve");
        assert_eq!(got, bits);
    }
}

/// Without a hint, the resolver walks `prev_block_hash` back to a genesis or
/// block-index anchor. Pin both anchor kinds.
#[test]
fn hintless_pointer_walk_finds_genesis_and_index_anchors() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;
    let chain = synth_chain(&params, 50, &|_| bits, &|h| 1_300_000_000 + h * 600);

    // (a) genesis anchor.
    let provider = HeaderOnlyProvider::from_chain(&chain, &params);
    let mut cache = HeaderCache::default();
    assert_eq!(
        expected_bits_for_child(
            &provider,
            &mut cache,
            &chain[50].block_hash(),
            None,
            chain[50].timestamp + 600,
            &params
        )
        .unwrap(),
        bits
    );

    // (b) block-index anchor partway down, genesis unreachable.
    let mut provider = HeaderOnlyProvider::default();
    for hdr in chain.iter().skip(20) {
        provider.put(hdr);
    }
    provider.index(chain[20].block_hash(), 20, bits);
    let mut cache = HeaderCache::default();
    assert_eq!(
        expected_bits_for_child(
            &provider,
            &mut cache,
            &chain[50].block_hash(),
            None,
            chain[50].timestamp + 600,
            &params
        )
        .unwrap(),
        bits
    );
}

// ---------------------------------------------------------------------------
// 12. Real BlockStore end-to-end, testnet4 shaped
// ---------------------------------------------------------------------------

/// Same as the mainnet regression but through a real RocksDB-backed
/// `BlockStore` on testnet4 parameters, including a connected prefix (which DOES
/// have `CF_BLOCK_INDEX` entries) and a header-only suffix — the exact mixed
/// state a node is in mid-IBD.
#[test]
fn real_store_testnet4_mixed_connected_and_header_only() {
    let params = ChainParams::testnet4();
    let real_bits = 0x1c00_ffffu32;
    let chain = synth_chain(&params, 300, &|_| real_bits, &|h| 1_700_000_000 + h * 600);

    let dir = tempfile::tempdir().unwrap();
    let db = open_store(dir.path());
    let store = BlockStore::new(&db);
    for (h, hdr) in chain.iter().enumerate() {
        let hash = hash_at(&chain, &params, h);
        store.put_header(&hash, hdr).unwrap();
        store.put_height_index(h as u32, &hash).unwrap();
        // Only the first 100 are CONNECTED.
        if h <= 100 {
            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_SCRIPTS);
            status.set(BlockStatus::HAVE_DATA);
            store
                .put_block_index(
                    &hash,
                    &rustoshi_storage::BlockIndexEntry {
                        height: h as u32,
                        status,
                        n_tx: 1,
                        timestamp: hdr.timestamp,
                        bits: hdr.bits,
                        nonce: hdr.nonce,
                        version: hdr.version,
                        prev_hash: hdr.prev_block_hash,
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
        }
    }

    // Header-only parent (height 300, well above the connected tip of 100).
    assert_eq!(store.get_height(&chain[300].block_hash()).unwrap(), None);
    assert_eq!(
        legacy_expected_bits_via_get_height(&store, &chain[300].block_hash()),
        None,
        "legacy resolver still fails open on the mixed state"
    );

    let mut cache = HeaderCache::default();
    let got = expected_bits_for_child(
        &store,
        &mut cache,
        &chain[300].block_hash(),
        Some(300),
        chain[300].timestamp + 600, // within 20 min -> walk-back arm
        &params,
    )
    .unwrap();
    assert_eq!(got, real_bits);

    // The connected prefix still resolves through CF_BLOCK_INDEX with no hint.
    let mut cache = HeaderCache::default();
    let got = expected_bits_for_child(
        &store,
        &mut cache,
        &chain[100].block_hash(),
        None,
        chain[100].timestamp + 600,
        &params,
    )
    .unwrap();
    assert_eq!(got, real_bits);
}

/// PINNED XFAIL — out of scope for this fix, found while writing it.
///
/// `ChainParams::testnet4()`'s `genesis_block` is built with the MAINNET
/// coinbase scriptSig (`params.rs::genesis_block_testnet4`), so its merkle root
/// — and therefore its block hash — does not equal the declared
/// `params.genesis_hash` (`00000000da84f2ba...`). Every other network is
/// self-consistent.
///
/// Why this fix is unaffected: `BlockStore::init_genesis` keys `CF_HEADERS` by
/// `params.genesis_hash`, and `expected_bits_for_child` short-circuits on
/// `parent_hash == params.genesis_hash`, so the resolver reads the header
/// production actually stored. The stored header's `bits` (0x1d00ffff) and
/// `timestamp` (1714777860) match real testnet4, which are the only two fields
/// the retarget algorithm reads — so the height-2016 boundary computes the
/// right answer despite the wrong merkle root.
///
/// Remove the `#[ignore]` once `genesis_block_testnet4` uses testnet4's real
/// coinbase ("03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb...").
#[test]
#[ignore = "BUG(params): testnet4 genesis_block uses the mainnet coinbase; hash != genesis_hash"]
fn genesis_hash_matches_genesis_block_header() {
    for (name, p) in [
        ("mainnet", ChainParams::mainnet()),
        ("testnet3", ChainParams::testnet3()),
        ("testnet4", ChainParams::testnet4()),
        ("signet", ChainParams::signet()),
        ("regtest", ChainParams::regtest()),
    ] {
        assert_eq!(
            p.genesis_hash,
            p.genesis_block.header.block_hash(),
            "{name}: genesis_block must hash to the declared genesis_hash"
        );
    }
}

/// The part of the above that IS load-bearing for this fix, asserted
/// unconditionally: whatever `genesis_block.header` contains, `init_genesis`
/// stores it under `params.genesis_hash`, so the resolver's genesis
/// short-circuit and the pointer walk agree with production.
#[test]
fn genesis_header_is_stored_under_the_declared_genesis_hash() {
    for params in [
        ChainParams::mainnet(),
        ChainParams::testnet3(),
        ChainParams::testnet4(),
        ChainParams::regtest(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = open_store(dir.path());
        let store = BlockStore::new(&db);
        store.init_genesis(&params).unwrap();
        let hdr = store
            .get_header(&params.genesis_hash)
            .unwrap()
            .expect("init_genesis keys CF_HEADERS by params.genesis_hash");
        assert_eq!(hdr.bits, params.genesis_block.header.bits);
        // ...and the resolver resolves it with no index, no hint, no walk.
        let provider_bits = {
            let mut cache = HeaderCache::default();
            expected_bits_for_child(
                &store,
                &mut cache,
                &params.genesis_hash,
                None,
                hdr.timestamp + 600,
                &params,
            )
            .expect("genesis parent must always resolve")
        };
        // height 1 is never a retarget boundary, and mainnet has no
        // min-difficulty rule, so this is genesis's own nBits there.
        if !params.pow_allow_min_difficulty_blocks {
            assert_eq!(provider_bits, hdr.bits);
        }
    }
}

/// The arm that was the actual fail-open, and is now closed.
///
/// Before 2026-08-09, when NEITHER the base's own header NOR its indexed nBits
/// was available, `degrade_at_snapshot_base` returned
/// `Ok(DiffBitsGate::DegradedSnapshotBase)` — it SKIPPED the difficulty check
/// altogether. That was documented as a narrow, unsteerable edge case. It was
/// neither: every built-in mainnet `AssumeutxoData` shipped
/// `base_tail_headers: Vec::new()`, so snapshot activation wrote the base's
/// index entry with a placeholder `bits: 0`, which the caller maps back to
/// `None` here (`.filter(|b| *b != 0)`). The arm was therefore taken on EVERY
/// mainnet snapshot boot, for the whole first retarget period above the base.
///
/// Core never has to answer this question: `ActivateSnapshot` refuses a
/// snapshot whose base header is not already linked into the headers chain
/// (validation.cpp:5611-5624), so `GetAncestor` cannot fail and
/// `ContextualCheckBlockHeader` asserts `pindexPrev != nullptr` (:4083).
/// Having already permitted the boot, refusing the header is the closest we
/// get to that guarantee. "I cannot evaluate the rule" must never mean "admit".
#[test]
fn snapshot_base_without_header_or_indexed_bits_refuses_instead_of_skipping() {
    let params = ChainParams::mainnet();
    let base = params.assumeutxo_data.first().unwrap().clone();

    // A base whose index entry carries the all-zero placeholder: no real
    // header, no usable nBits. This is exactly what activation wrote for every
    // built-in entry before the tail bands were baked in.
    let mut provider = HeaderOnlyProvider::default();
    provider.index(base.blockhash, base.height, 0);

    let mut cache = HeaderCache::default();
    let reason = diffbits_gate_for_header(
        &provider,
        &mut cache,
        &base.blockhash,
        0x1d00_ffff, // difficulty-1: what an attacker would claim
        1_700_000_000,
        base.height + 1,
        Some(base.height),
        &params,
    )
    .expect_err("unevaluable difficulty rule must REFUSE, never skip");
    assert!(reason.starts_with("bad-diffbits"), "got {reason}");
    assert!(
        reason.contains("Refusing rather than admitting the header unchecked"),
        "got {reason}"
    );
}

/// The baked tail bands make the refusing arm unreachable on mainnet: every
/// entry now supplies a real header for its own base, so the gate has a genuine
/// parent nBits to compare against and the boot is not wedged.
#[test]
fn every_mainnet_snapshot_base_has_a_real_header_to_gate_against() {
    let params = ChainParams::mainnet();
    assert!(!params.assumeutxo_data.is_empty(), "fixture assumption");
    for entry in &params.assumeutxo_data {
        let tail = &entry.base_tail_headers;
        assert!(
            !tail.is_empty(),
            "assumeutxo entry at height {} ships no tail band, so the \
             bad-diffbits gate would refuse every header above it",
            entry.height,
        );
        let base_header = tail.last().unwrap();
        assert_eq!(
            base_header.block_hash(),
            entry.blockhash,
            "tail band for height {} does not end at the declared base",
            entry.height,
        );
        assert_ne!(
            base_header.bits, 0,
            "base header for height {} has placeholder bits — the gate would \
             still have nothing to compare against",
            entry.height,
        );
    }
}
