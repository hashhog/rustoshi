//! Header-context difficulty resolution: the input to Core's FIRST contextual
//! header gate, `bad-diffbits`.
//!
//! # What this is
//!
//! Bitcoin Core, `validation.cpp::ContextualCheckBlockHeader` (validation.cpp:4088):
//!
//! ```text
//! if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
//!     return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER,
//!                          "bad-diffbits", "incorrect proof of work");
//! ```
//!
//! That is the ONLY place a header's claimed `nBits` is compared to the value
//! the retarget algorithm mandates for its height. It is *not* the same check
//! as `CheckProofOfWork` ("high-hash"), which only compares the block hash to
//! the target the header *declares*. A header may declare an arbitrarily easy
//! target and mine it trivially; only this gate rejects that.
//!
//! # The bug this module exists to close
//!
//! rustoshi used to resolve the parent's height with
//! `BlockStore::get_height` -> `CF_BLOCK_INDEX`. `CF_BLOCK_INDEX` is written
//! only when a block **connects** (or at assumeUTXO snapshot activation);
//! header acceptance writes `CF_HEADERS` + `CF_HEIGHT_INDEX` and nothing else.
//! Under headers-first sync every header above the connected block tip has a
//! header-only parent, so `get_height` returned `None`, the helper returned
//! `None`, and the caller treated `None` as "no check". The gate therefore ran
//! on at most one header per session, and the ancestor walk behind it was dead
//! code. An attacker could feed an arbitrarily long difficulty-1 header chain.
//!
//! Two invariants this module holds, both learned the hard way:
//!
//! 1. **Fail closed.** [`expected_bits_for_child`] returns `Result`, never
//!    `Option`. There is no value that spells "skip silently". The one
//!    documented degradation ([`DiffBitsGate::DegradedSnapshotBase`]) keys off
//!    a hard-coded chainparams hash that an attacker cannot steer into, is
//!    logged at WARN, and downgrades to a real check
//!    ([`rustoshi_consensus::permitted_difficulty_transition`], Core
//!    `pow.cpp::PermittedDifficultyTransition`) rather than to nothing.
//!
//! 2. **Poison immunity.** Retarget ancestors are resolved by `prev_block_hash`
//!    **pointers** only. `CF_HEIGHT_INDEX` (height -> hash) is NEVER consulted:
//!    it is attacker-poisonable (header acceptance writes it, and rustoshi
//!    keeps exactly one hash per height, so a fork overwrites slots), and it
//!    does not cover headers ahead of the validated tip at all. Resolving the
//!    window through it would INVERT the check -- rejecting honest headers and
//!    accepting the attacker's easy ones. The [`HeaderProvider`] trait
//!    deliberately exposes no height -> hash lookup, so this is a structural
//!    guarantee, not a convention.
//!
//! # Cost
//!
//! The window is sized *before* anything is read (see [`window_floor`]), so the
//! mainnet steady state is one `header_meta` call for 2015 of every 2016
//! headers and 2016 calls on a retarget boundary -- ~2 reads per header
//! amortised. [`HeaderCache`] keeps the boundary and testnet walk-back windows
//! in RAM.

use std::collections::{HashMap, VecDeque};

use rustoshi_consensus::params::{
    ChainParams, DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_BLOCK_TIME,
};
use rustoshi_consensus::pow::{
    get_next_work_required, permitted_difficulty_transition, BlockIndex as PowBlockIndex, PowError,
};
use rustoshi_primitives::Hash256;

use crate::block_store::BlockStore;
use crate::db::StorageError;

/// Maximum number of `prev_block_hash` steps taken while searching for a
/// height anchor (genesis or a `CF_BLOCK_INDEX` entry) when no caller hint is
/// available. One retarget interval is enough for every case the retarget
/// algorithm can ask about; beyond that we fail closed rather than walk the
/// whole chain (which would also be a cheap remote DoS).
pub const HEIGHT_ANCHOR_WALK_LIMIT: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL;

/// Default `HeaderCache` capacity: enough to hold a full retarget window plus
/// slack, so a boundary walk and the testnet4 min-difficulty walk-back are
/// served from RAM.
pub const DEFAULT_HEADER_CACHE_ENTRIES: usize = 8192;

/// The three header fields the difficulty algorithm needs, plus the pointer
/// used to walk backwards. Deliberately not the whole `BlockHeader`: the walk
/// must never need anything the retarget math doesn't read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderMeta {
    /// Compact difficulty target (`nBits`).
    pub bits: u32,
    /// Block timestamp.
    pub timestamp: u32,
    /// Parent pointer -- the ONLY way this module moves between blocks.
    pub prev_hash: Hash256,
}

/// The authoritative (connect-time / snapshot-activation) index entry for a
/// block, when one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedBlock {
    /// Height recorded in `CF_BLOCK_INDEX`.
    pub height: u32,
    /// `nBits` recorded in `CF_BLOCK_INDEX` (0 for an assumeUTXO base whose
    /// real header was never downloaded).
    pub bits: u32,
}

/// Read-only access to the two lookups this module is allowed to make.
///
/// Note what is **absent**: there is no height -> hash method. That omission is
/// the poison-immunity guarantee (see the module docs). Adding one here would
/// reopen the inversion failure mode.
pub trait HeaderProvider {
    /// Header fields by hash (`CF_HEADERS`).
    fn header_meta(&self, hash: &Hash256) -> Result<Option<HeaderMeta>, StorageError>;

    /// Authoritative block-index entry by hash (`CF_BLOCK_INDEX`). `None` for
    /// a header-only block -- the normal case above the connected tip.
    fn indexed_block(&self, hash: &Hash256) -> Result<Option<IndexedBlock>, StorageError>;
}

impl HeaderProvider for BlockStore<'_> {
    fn header_meta(&self, hash: &Hash256) -> Result<Option<HeaderMeta>, StorageError> {
        Ok(self.get_header(hash)?.map(|h| HeaderMeta {
            bits: h.bits,
            timestamp: h.timestamp,
            prev_hash: h.prev_block_hash,
        }))
    }

    fn indexed_block(&self, hash: &Hash256) -> Result<Option<IndexedBlock>, StorageError> {
        Ok(self.get_block_index(hash)?.map(|e| IndexedBlock {
            height: e.height,
            bits: e.bits,
        }))
    }
}

/// Why the mandated `nBits` could not be produced.
///
/// Every variant is a **rejection**, not a skip. The single documented
/// degradation is applied one layer up, in [`diffbits_gate_for_header`], and
/// only for a hard-coded assumeUTXO snapshot base.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpectedBitsError {
    /// No header stored for the parent -- we cannot even start.
    #[error("parent header {0} not in the header store")]
    ParentHeaderUnknown(Hash256),

    /// The parent's height could not be established from genesis, the block
    /// index, a caller hint, or a bounded pointer walk to one of those.
    #[error("parent {0} height unresolved (no genesis or block-index anchor within 2016 pointer steps)")]
    ParentHeightUnresolved(Hash256),

    /// The retarget window runs below the deepest header we can reach.
    #[error(
        "retarget ancestors unreachable: need height {needed_height}, deepest readable \
         {deepest_hash} at height {deepest_height}, missing ancestor {missing_hash} at height \
         {missing_height}"
    )]
    AncestorGap {
        /// Deepest header actually readable via `prev_block_hash`.
        deepest_hash: Hash256,
        /// Its derived height.
        deepest_height: u32,
        /// The first ancestor we could NOT read (`deepest.prev_block_hash`).
        missing_hash: Hash256,
        /// The height that missing ancestor would have had.
        missing_height: u32,
        /// The height the window had to reach.
        needed_height: u32,
    },

    /// A pointer-derived height disagrees with the authoritative
    /// `CF_BLOCK_INDEX` height for the same hash. An inconsistent index must
    /// fail closed -- silently picking a winner is how the original bug hid.
    #[error("height inconsistency at {hash}: pointer-derived {derived}, block index {indexed}")]
    HeightInconsistent {
        hash: Hash256,
        derived: u32,
        indexed: u32,
    },

    /// Underlying storage failure. Carried as a rendered string so this error
    /// stays `Clone + PartialEq` (`StorageError` wraps `rocksdb::Error`, which
    /// is neither) -- callers only ever log or reject on it.
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<StorageError> for ExpectedBitsError {
    fn from(e: StorageError) -> Self {
        ExpectedBitsError::Storage(e.to_string())
    }
}

impl ExpectedBitsError {
    /// Operator-facing description. Always names the hashes/heights involved,
    /// so a false-reject is diagnosable from one log line instead of a bisect.
    pub fn describe(&self) -> String {
        self.to_string()
    }
}

/// A small insertion-ordered cache of [`HeaderMeta`], owned by the caller and
/// threaded into [`expected_bits_for_child`].
///
/// Purpose is purely cost: the mainnet retarget boundary walks 2016 ancestors
/// and the testnet4 min-difficulty walk-back can walk up to 2015, and those
/// same ancestors are re-walked by the next boundary/min-difficulty header.
/// Only *hits* are cached -- a miss is never memoised, because a header that
/// is absent now may be stored a moment later.
///
/// Eviction is insertion-order (FIFO), not true LRU: the access pattern here is
/// a descending walk, for which FIFO over a window larger than the walk is
/// equivalent and much cheaper.
pub struct HeaderCache {
    cap: usize,
    map: HashMap<Hash256, HeaderMeta>,
    order: VecDeque<Hash256>,
    /// Number of provider `header_meta` calls made through this cache.
    /// Used by the performance-guard test; harmless in production.
    provider_reads: u64,
}

impl Default for HeaderCache {
    fn default() -> Self {
        Self::new(DEFAULT_HEADER_CACHE_ENTRIES)
    }
}

impl HeaderCache {
    /// Create a cache holding at most `cap` headers (0 disables caching).
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            map: HashMap::new(),
            order: VecDeque::new(),
            provider_reads: 0,
        }
    }

    /// Number of times the underlying provider was actually asked for a header.
    pub fn provider_reads(&self) -> u64 {
        self.provider_reads
    }

    /// Reset the read counter (test instrumentation).
    pub fn reset_provider_reads(&mut self) {
        self.provider_reads = 0;
    }

    fn get<P: HeaderProvider + ?Sized>(
        &mut self,
        provider: &P,
        hash: &Hash256,
    ) -> Result<Option<HeaderMeta>, StorageError> {
        if let Some(m) = self.map.get(hash) {
            return Ok(Some(*m));
        }
        self.provider_reads += 1;
        let meta = provider.header_meta(hash)?;
        if let Some(m) = meta {
            if self.cap > 0 {
                if self.map.len() >= self.cap {
                    while self.map.len() >= self.cap {
                        match self.order.pop_front() {
                            Some(old) => {
                                self.map.remove(&old);
                            }
                            None => break,
                        }
                    }
                }
                if self.map.insert(*hash, m).is_none() {
                    self.order.push_back(*hash);
                }
            }
        }
        Ok(meta)
    }
}

/// Deepest ancestor height the retarget algorithm can possibly read for the
/// block at `parent_height + 1`, computed BEFORE any storage access.
///
/// This is the whole reason the walk is cheap. It mirrors, arm for arm, what
/// `rustoshi_consensus::pow::get_next_work_required` (Core
/// `pow.cpp::GetNextWorkRequired`) will actually ask for:
///
/// * **Retarget boundary** (`next % 2016 == 0`): Core takes
///   `pindexLast->GetAncestor(nHeight - 2015)`, i.e. `next - 2016`. BIP-94
///   (testnet4) reads the *first* block of the period in
///   `CalculateNextWorkRequired` -- the same ancestor, so no extra depth.
/// * **Min-difficulty networks, child within 20 minutes of its parent**: Core
///   walks back while `height % 2016 != 0 && nBits == powLimit`. We size to the
///   retarget boundary at or below the parent rather than trying to predict
///   where that walk stops. Duplicating
///   `pow::get_last_non_min_difficulty_bits`'s stop condition here would be a
///   NEW fail-open: if the window were cut short, that function's `prev()`
///   returns `None` and it silently returns the truncated node's bits. Over-
///   fetching is bounded (<= 2015 headers) and provably safe.
/// * **Everything else** (the mainnet hot path, 2015 headers in 2016): Core
///   returns `pindexLast->nBits`. One header.
pub fn window_floor(
    parent_height: u32,
    parent_timestamp: u32,
    new_block_time: u32,
    params: &ChainParams,
) -> u32 {
    let next = parent_height.saturating_add(1);
    if next % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        // next >= 2016 whenever next % 2016 == 0 and next > 0.
        next.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL)
    } else if params.pow_allow_min_difficulty_blocks
        && new_block_time <= parent_timestamp.saturating_add(TARGET_BLOCK_TIME * 2)
    {
        next - (next % DIFFICULTY_ADJUSTMENT_INTERVAL)
    } else {
        parent_height
    }
}

/// Recompute the consensus-mandated `nBits` for the block that extends
/// `parent_hash` -- Core `GetNextWorkRequired(pindexPrev, &block, params)`,
/// the right-hand side of the `bad-diffbits` comparison at
/// `validation.cpp:4088`.
///
/// The retarget math itself is NOT reimplemented here: this materialises the
/// ancestor window and hands it to `rustoshi_consensus::pow`, the same code the
/// block-template and connect paths use.
///
/// # Height resolution, and why the hint is safe
///
/// The parent's height is resolved in this order:
///
/// 1. `parent_hash == params.genesis_hash` -> 0.
/// 2. `CF_BLOCK_INDEX` (authoritative: connected blocks + the assumeUTXO base).
/// 3. `parent_height_hint`.
/// 4. A bounded `prev_block_hash` walk (<= [`HEIGHT_ANCHOR_WALK_LIMIT`] steps)
///    looking for (1) or (2); on a hit, `anchor_height + steps`.
/// 5. Otherwise [`ExpectedBitsError::ParentHeightUnresolved`].
///
/// (3) precedes (4) purely for cost: during IBD the nearest `CF_BLOCK_INDEX`
/// anchor is the connected block tip, which can be hundreds of thousands of
/// headers below the header tip, so the walk is guaranteed to miss.
///
/// **The hint is trusted, and this is the invariant the whole design rests
/// on.** It is legitimate only because it is itself pointer-derived:
/// `HeaderSync` is re-seeded at every startup from the CONNECTED BLOCK TIP
/// (`rustoshi/src/main.rs`, `header_sync.set_best_header(best_height,
/// best_hash)`), and within a batch `height = base_height + 1 + i` where every
/// step is chain-verified by `header.prev_block_hash != prev_hash -> Err`
/// (`crates/network/src/header_sync.rs`), and fork points are located BY HASH.
/// So the hint is always `validated_tip_height + (number of prev-pointer steps
/// followed)`; a peer cannot choose it. Any future change that lets the header
/// tip persist above the block tip across restarts, or that seeds
/// `set_best_header` from anything other than a validated tip, silently weakens
/// this and must revisit the hint.
///
/// As a backstop, every ancestor materialised for the window is cross-checked
/// against `CF_BLOCK_INDEX`/genesis where such an anchor exists; a disagreement
/// is [`ExpectedBitsError::HeightInconsistent`] (fail closed), never a silent
/// pick.
pub fn expected_bits_for_child<P: HeaderProvider + ?Sized>(
    provider: &P,
    cache: &mut HeaderCache,
    parent_hash: &Hash256,
    parent_height_hint: Option<u32>,
    new_block_time: u32,
    params: &ChainParams,
) -> Result<u32, ExpectedBitsError> {
    let parent = cache
        .get(provider, parent_hash)?
        .ok_or(ExpectedBitsError::ParentHeaderUnknown(*parent_hash))?;

    let parent_height = resolve_parent_height(
        provider,
        cache,
        parent_hash,
        &parent,
        parent_height_hint,
        params,
    )?;

    let floor = window_floor(parent_height, parent.timestamp, new_block_time, params);

    // Materialise parent -> floor by POINTERS ONLY (poison immunity).
    // `chain[0]` is the parent, descending.
    let mut chain: Vec<(Hash256, u32, HeaderMeta)> = Vec::new();
    chain.push((*parent_hash, parent_height, parent));

    let mut cur_hash = *parent_hash;
    let mut cur_height = parent_height;
    let mut cur_meta = parent;

    while cur_height > floor {
        let prev_hash = cur_meta.prev_hash;
        let prev_height = cur_height - 1;
        let prev_meta = match cache.get(provider, &prev_hash)? {
            Some(m) => m,
            None => {
                return Err(ExpectedBitsError::AncestorGap {
                    deepest_hash: cur_hash,
                    deepest_height: cur_height,
                    missing_hash: prev_hash,
                    missing_height: prev_height,
                    needed_height: floor,
                });
            }
        };

        // Opportunistic height verification, at the cost of the lookups we are
        // already making: genesis is free (hash compare), and a CF_BLOCK_INDEX
        // hit is authoritative. Any disagreement means our derived heights (and
        // therefore the retarget schedule) are wrong -- reject rather than
        // guess.
        if prev_hash == params.genesis_hash {
            if prev_height != 0 {
                tracing::error!(
                    "diffbits height inconsistency: genesis {} derived at height {} while walking \
                     the retarget window for parent {} (derived height {})",
                    prev_hash,
                    prev_height,
                    parent_hash,
                    parent_height
                );
                return Err(ExpectedBitsError::HeightInconsistent {
                    hash: prev_hash,
                    derived: prev_height,
                    indexed: 0,
                });
            }
        } else if let Some(idx) = provider.indexed_block(&prev_hash)? {
            if idx.height != prev_height {
                tracing::error!(
                    "diffbits height inconsistency at {}: pointer-derived {} vs block index {} \
                     (walking the retarget window for parent {})",
                    prev_hash,
                    prev_height,
                    idx.height,
                    parent_hash
                );
                return Err(ExpectedBitsError::HeightInconsistent {
                    hash: prev_hash,
                    derived: prev_height,
                    indexed: idx.height,
                });
            }
        }

        chain.push((prev_hash, prev_height, prev_meta));
        cur_hash = prev_hash;
        cur_height = prev_height;
        cur_meta = prev_meta;
    }

    // Build the linked index the pow crate consumes, oldest first.
    let mut node: Option<Box<WindowNode>> = None;
    for (_, height, meta) in chain.iter().rev() {
        node = Some(Box::new(WindowNode {
            height: *height,
            timestamp: meta.timestamp,
            bits: meta.bits,
            prev: node,
        }));
    }
    let tip = node.expect("chain always contains the parent");

    // Reuse the real retarget implementation -- do NOT re-derive difficulty.
    // Core: pow.cpp::GetNextWorkRequired / CalculateNextWorkRequired.
    //
    // A `PowError` here means the window was sized too shallow. Historically
    // this was `.ok()`-folded into `None` (a second fail-open); now it is a
    // rejection carrying the deepest hash so the snapshot-base carve-out (and
    // only that carve-out) can act on it.
    get_next_work_required(&*tip, new_block_time, params).map_err(|e| {
        let PowError::MissingRetargetAncestor {
            ancestor_height, ..
        } = e;
        ExpectedBitsError::AncestorGap {
            deepest_hash: cur_hash,
            deepest_height: cur_height,
            missing_hash: cur_meta.prev_hash,
            missing_height: cur_height.saturating_sub(1),
            needed_height: ancestor_height,
        }
    })
}

fn resolve_parent_height<P: HeaderProvider + ?Sized>(
    provider: &P,
    cache: &mut HeaderCache,
    parent_hash: &Hash256,
    parent: &HeaderMeta,
    parent_height_hint: Option<u32>,
    params: &ChainParams,
) -> Result<u32, ExpectedBitsError> {
    // (a) genesis.
    if *parent_hash == params.genesis_hash {
        return Ok(0);
    }
    // (b) authoritative index.
    if let Some(idx) = provider.indexed_block(parent_hash)? {
        return Ok(idx.height);
    }
    // (c) caller hint -- pointer-derived, see the doc comment on
    // `expected_bits_for_child`.
    if let Some(h) = parent_height_hint {
        return Ok(h);
    }
    // (d) bounded pointer walk to a genesis / block-index anchor.
    let mut cursor = parent.prev_hash;
    for steps in 1..=HEIGHT_ANCHOR_WALK_LIMIT {
        if cursor == params.genesis_hash {
            return Ok(steps);
        }
        if let Some(idx) = provider.indexed_block(&cursor)? {
            return Ok(idx.height.saturating_add(steps));
        }
        match cache.get(provider, &cursor)? {
            Some(m) => {
                if m.prev_hash == Hash256::ZERO {
                    break;
                }
                cursor = m.prev_hash;
            }
            None => break,
        }
    }
    // (e) fail closed.
    Err(ExpectedBitsError::ParentHeightUnresolved(*parent_hash))
}

struct WindowNode {
    height: u32,
    timestamp: u32,
    bits: u32,
    prev: Option<Box<WindowNode>>,
}

impl PowBlockIndex for WindowNode {
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
    fn ancestor(&self, target_height: u32) -> Option<&Self> {
        if target_height > self.height {
            return None;
        }
        let mut cur = self;
        while cur.height > target_height {
            cur = cur.prev.as_deref()?;
        }
        Some(cur)
    }
}

/// Outcome of the `bad-diffbits` gate for one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffBitsGate {
    /// The consensus-mandated `nBits`. Callers pass this to
    /// `contextual_check_block_header` as `Some(..)`; it MUST equal
    /// `header.bits`.
    Required(u32),

    /// The ONLY carve-out. The full retarget window is unavailable because the
    /// chain terminates at a **hard-coded assumeUTXO snapshot base** from
    /// chainparams (rustoshi's `--load-snapshot` boot materialises no headers
    /// below the base). This is not a skip: Core's
    /// `PermittedDifficultyTransition` has already been applied and PASSED, or
    /// -- when even the base's `nBits` is unknown -- a loud WARN has been
    /// emitted. An attacker cannot steer into this: the predicate is equality
    /// against a built-in chainparams block hash.
    DegradedSnapshotBase,
}

/// Run Core's first contextual header gate for one header, applying the single
/// documented carve-out.
///
/// Mirrors `bitcoin-core/src/validation.cpp:4088`. `height` is the *child's*
/// height (used only by the degraded arm's
/// `PermittedDifficultyTransition`). `parent_height_hint` is described on
/// [`expected_bits_for_child`].
///
/// Returns the BIP-22 style reject reason (`"bad-diffbits..."`) on failure --
/// every non-carve-out error path is a rejection.
pub fn diffbits_gate_for_header<P: HeaderProvider + ?Sized>(
    provider: &P,
    cache: &mut HeaderCache,
    parent_hash: &Hash256,
    header_bits: u32,
    header_time: u32,
    height: u32,
    parent_height_hint: Option<u32>,
    params: &ChainParams,
) -> Result<DiffBitsGate, String> {
    match expected_bits_for_child(
        provider,
        cache,
        parent_hash,
        parent_height_hint,
        header_time,
        params,
    ) {
        Ok(bits) => Ok(DiffBitsGate::Required(bits)),

        Err(ExpectedBitsError::AncestorGap {
            deepest_hash,
            deepest_height,
            missing_hash,
            missing_height,
            needed_height,
        }) => {
            let is_snapshot_base = params.assumeutxo_for_blockhash(&missing_hash).is_some()
                || params.assumeutxo_for_blockhash(&deepest_hash).is_some();
            if !is_snapshot_base {
                return Err(format!(
                    "bad-diffbits: retarget ancestors unreachable (need height {}, deepest \
                     readable {} at {}, missing {} at {})",
                    needed_height, deepest_hash, deepest_height, missing_hash, missing_height
                ));
            }
            // Parent header IS readable in this arm (the gap is deeper), so we
            // have real parent bits for the downgraded check.
            let parent_bits = cache
                .get(provider, parent_hash)
                .map_err(|e| format!("bad-diffbits: storage error: {}", e))?
                .map(|m| m.bits);
            degrade_at_snapshot_base(
                parent_bits,
                header_bits,
                height,
                &missing_hash,
                needed_height,
                params,
            )
        }

        Err(ExpectedBitsError::ParentHeaderUnknown(h))
            if params.assumeutxo_for_blockhash(&h).is_some() =>
        {
            // The parent IS the snapshot base and its own header was never
            // downloaded (every built-in AssumeutxoData currently ships
            // `base_tail_headers: []`). The base's CF_BLOCK_INDEX entry may
            // still carry real bits when a tail band was supplied.
            let parent_bits = provider
                .indexed_block(&h)
                .map_err(|e| format!("bad-diffbits: storage error: {}", e))?
                .map(|i| i.bits)
                .filter(|b| *b != 0);
            degrade_at_snapshot_base(parent_bits, header_bits, height, &h, height, params)
        }

        Err(e) => Err(format!("bad-diffbits: {}", e.describe())),
    }
}

fn degrade_at_snapshot_base(
    parent_bits: Option<u32>,
    header_bits: u32,
    height: u32,
    base_hash: &Hash256,
    needed_height: u32,
    params: &ChainParams,
) -> Result<DiffBitsGate, String> {
    match parent_bits {
        Some(old_bits) => {
            tracing::warn!(
                "bad-diffbits gate DEGRADED at assumeUTXO snapshot base {} (needed retarget \
                 ancestor at height {}, height now {}): full window unavailable, falling back to \
                 PermittedDifficultyTransition (Core pow.cpp)",
                base_hash,
                needed_height,
                height
            );
            // Core pow.cpp::PermittedDifficultyTransition -- needs only the
            // parent. A real check, not a skip.
            if !permitted_difficulty_transition(height, old_bits, header_bits, params) {
                return Err(format!(
                    "bad-diffbits: difficulty transition {:#010x} -> {:#010x} at height {} \
                     outside the permitted bounds (degraded snapshot-base check)",
                    old_bits, header_bits, height
                ));
            }
            Ok(DiffBitsGate::DegradedSnapshotBase)
        }
        None => {
            // Neither the base's own header nor its indexed nBits is
            // available, so there is NOTHING to compare against.
            //
            // Until 2026-08-09 this arm returned `Ok(DegradedSnapshotBase)` --
            // it SKIPPED the gate. That was described as narrow and
            // unsteerable, and it was neither: every built-in mainnet
            // `AssumeutxoData` shipped `base_tail_headers: Vec::new()`, so
            // activation wrote the base's index entry with a placeholder
            // `bits: 0` (main.rs) which the caller correctly maps back to
            // `None` here. This arm was therefore taken on EVERY mainnet
            // snapshot boot, for the entire first retarget period above the
            // base -- every retarget ancestor in that window lies below it.
            //
            // Now it refuses. Bitcoin Core reaches the equivalent conclusion
            // one step earlier and more cheaply: it will not activate a
            // snapshot whose base header is not already in the headers chain
            // (validation.cpp:5611-5624), so it never has to answer this
            // question at all. Refusing is the closest we get to that
            // guarantee once we have already allowed the boot.
            //
            // On mainnet this is now unreachable: all five entries bake a
            // 2027-header band (`consensus::assumeutxo_tails`), asserted by
            // `verify_bands_match_params`. It stays live for networks or
            // campaign entries that supply no tail.
            Err(format!(
                "bad-diffbits: cannot evaluate the difficulty rule for the child of assumeUTXO \
                 snapshot base {base_hash} at height {height}: neither the base header nor its \
                 indexed nBits is available. Refusing rather than admitting the header unchecked. \
                 Bake AssumeutxoData::base_tail_headers for this base, or sync headers from \
                 genesis instead of booting from a snapshot."
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_consensus::params::ChainParams;

    #[test]
    fn window_floor_mainnet_non_boundary_is_single_header() {
        let params = ChainParams::mainnet();
        // 800_000 % 2016 != 0 -> one header.
        assert_eq!(window_floor(799_999, 1_700_000_000, 1_700_000_600, &params), 799_999);
    }

    #[test]
    fn window_floor_mainnet_boundary_is_full_interval() {
        let params = ChainParams::mainnet();
        // next = 2016 -> floor = 0 (2016 headers).
        assert_eq!(window_floor(2015, 1_300_000_000, 1_300_000_600, &params), 0);
        // next = 4032 -> floor = 2016.
        assert_eq!(window_floor(4031, 1_300_000_000, 1_300_000_600, &params), 2016);
    }

    #[test]
    fn window_floor_min_difficulty_arms() {
        let params = ChainParams::testnet4();
        let parent_ts = 1_700_000_000u32;
        // >20 min gap -> min-difficulty short circuit, single header.
        assert_eq!(
            window_floor(100, parent_ts, parent_ts + 1201, &params),
            100
        );
        // <=20 min -> walk-back window down to the retarget boundary.
        assert_eq!(window_floor(100, parent_ts, parent_ts + 600, &params), 0);
        assert_eq!(
            window_floor(3000, parent_ts, parent_ts + 600, &params),
            2016
        );
    }
}
