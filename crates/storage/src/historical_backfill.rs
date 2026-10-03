//! Background backfill of genesis → snapshot-base after assumeUTXO boot.
//!
//! Bitcoin Core's `--loadtxoutset` / `-assumeutxo` path activates the snapshot
//! chainstate for immediate use AND keeps a second, background chainstate that
//! IBDs genesis→base (`validation.cpp` `ChainstateManager` /
//! `MaybeCompleteSnapshotValidation`). When the background chain reaches the
//! snapshot base, the two are reconciled and the node is fully indexed.
//!
//! rustoshi's `--load-snapshot` boot writes genesis, a baked assumeutxo tail
//! band (2027 headers ending at the snapshot base), and then everything after
//! the base. Heights `1..floor-1` are absent from `CF_HEIGHT_INDEX`. That is
//! the live mainnet shape (floor 942157 for the 944183 snapshot):
//! `getblockhash(1)` returns `-1 "Block not available (pruned data)"` and
//! `getblockchaininfo` reports `pruned:true pruneheight=942157`.
//!
//! This type fills that hole:
//!
//!   1. Request headers from genesis (locator = last contiguous genesis-side
//!      hash; `hash_stop` = the already-stored floor hash).
//!   2. Store connecting headers into `CF_HEADERS` + `CF_HEIGHT_INDEX` +
//!      `CF_BLOCK_INDEX` without touching the snapshot tail or the active tip.
//!   3. Request block bodies for those headers and store them in `CF_BLOCKS`.
//!   4. When height 1 is indexed and the contiguous genesis chain meets the
//!      previous floor, `snapshot_index_floor` returns `None` and
//!      `getblockchaininfo` reports `pruned: false`.
//!
//! Header-sync isolation: these headers MUST NOT be fed to the forward
//! `HeaderSync` whose tip is the snapshot tip. A genesis-connecting batch
//! would look like a rewind to height 0 and overwrite the snapshot tail.
//! The P2P loop classifies a batch as backfill iff [`HistoricalBackfill::is_backfill_batch`].
//!
//! Peer isolation: rustoshi has one P2P pipeline. Core keeps the snapshot
//! chainstate independent of background IBD. We approximate that with
//! [`HistoricalBackfill::may_use_peer`]: backfill getheaders/getdata are
//! forbidden while forward header-sync is in progress or the validated tip
//! is behind the header tip. A stored-0 overlapping resend cools getheaders
//! ([`HistoricalBackfill::should_request_headers`]) so it cannot tight-loop
//! the only peer. Observed 2026-09-19: 66,069 backfill iterations, zero
//! block requests, tip frozen at the snapshot base.
//!
//! Main-loop isolation (2026-09-28): the P2P loop is single-threaded, so
//! backfill work there delays everything else it handles, including peer
//! lifecycle events and new-tip headers. Three bounds keep it cheap:
//! a global window of [`BACKFILL_MAX_BODIES_OUTSTANDING`] bodies (Core draws
//! background-chainstate blocks from the same 16-per-peer in-transit budget,
//! after the active chain), a single outstanding genesis-side getheaders, and
//! body writes on the [`BodyWriter`] thread instead of the loop.
//!
//! Operator kill-switch: [`historical_backfill_is_enabled`] /
//! `--no-historical-backfill` / [`HISTORICAL_BACKFILL_DISABLE_ENV`]. Campaign
//! slices that only need the snapshot tip can disable this path so forward
//! header-sync and getdata own the single feeder peer. Default remains on.
//!
//! UTXO re-derivation of genesis→base (Core's in-memory/disk background
//! coins view) is a separate concern: `ChainstateManager` already does it
//! for small chains. Replaying ~942k mainnet blocks into a RAM `HashMap`
//! would OOM; this backfill is the operator-visible historical index.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

use rustoshi_consensus::params::ChainParams;
use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_consensus::{check_block, contextual_check_block, StubChainContext, ValidationError};
use rustoshi_primitives::{Block, BlockHeader, Hash256};

use crate::block_store::{BlockIndexEntry, BlockStatus, BlockStore};
use crate::db::{ChainDb, StorageError};
use crate::header_context::{expected_bits_for_child, HeaderCache};

/// Maximum bodies requested in one getdata burst. Matches Core's default
/// per-peer in-flight cap so historical download cannot starve tip sync.
pub const BACKFILL_BODIES_PER_REQUEST: usize = 16;

/// Hard cap on historical bodies outstanding at once, across ALL peers:
/// requested-and-not-yet-received plus received-and-not-yet-written.
///
/// Core's background-chainstate download (`TryDownloadingHistoricalBlocks`,
/// `net_processing.cpp`) draws from the same per-peer
/// `MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16` budget as the active chain, after
/// the active chain has taken its share. rustoshi had no such window: every
/// received body re-ran the scan and asked for up to 16 MORE, so the number
/// of bodies in flight grew by ~15 per body received. On an I/O-bound box
/// (2026-09-28, iowait ~68%) those bodies filled the priority event lane
/// ahead of lifecycle events and new-tip headers: a `Connected` was handled
/// 875 s after the handshake, a `Disconnected` 16 min after the task died,
/// and the node sat 5 blocks behind the tip for 20 min.
pub const BACKFILL_MAX_BODIES_OUTSTANDING: usize = 16;

/// Maximum heights one [`HistoricalBackfill::next_body_hashes`] call (and one
/// body-cursor advance) examines. Each height costs up to two RocksDB point
/// reads (height index + block presence), and the caller runs on the
/// node's main async task, so per-call work must not grow with the hole.
/// 2026-09-26 mainnet wedge: an unbounded walk of ~118k heights per call
/// stalled block connect and inbound P2P for ~15 min until the P2P watchdog
/// restarted the node.
pub const BACKFILL_BODY_SCAN_MAX_HEIGHTS: u32 = 1024;

/// While [`HistoricalBackfill::detect`] walks a datadir that has no body
/// progress marker yet, it persists the marker every this many heights so a
/// restart in the middle of that one-time walk does not start it over.
pub const DETECT_PERSIST_EVERY: u32 = 4096;

/// Env var an operator or campaign launcher sets to skip genesis→base P2P
/// backfill after `--load-snapshot`. Same effect as `--no-historical-backfill`.
pub const HISTORICAL_BACKFILL_DISABLE_ENV: &str = "HASHHOG_DISABLE_HISTORICAL_BACKFILL";

/// True unless the operator kill-switch is set.
///
/// `cli_disabled` is `--no-historical-backfill`. `env` is the raw value of
/// [`HISTORICAL_BACKFILL_DISABLE_ENV`] (`None` if unset). Either one disables:
/// campaign `--load-snapshot` slices can then run forward-only without the
/// 2026-09-19 stall (66,069 stored-0 getheaders, zero getdata).
pub fn historical_backfill_is_enabled(cli_disabled: bool, env: Option<&str>) -> bool {
    if cli_disabled {
        return false;
    }
    match env.map(str::trim) {
        None | Some("") => true,
        Some(v) => !matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

/// Error from applying a historical-backfill header or block batch.
#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    /// Underlying store failure.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    /// Batch does not connect to the genesis-side tip and is not an overlapping
    /// re-send of already-stored historical headers.
    #[error("historical headers do not connect (genesis tip {expected}, got prev {got})")]
    Unconnecting { expected: Hash256, got: Hash256 },
    /// Header hash does not meet the target it declares.
    #[error("high-hash at historical height {0}")]
    HighHash(u32),
    /// Header nBits does not match GetNextWorkRequired.
    #[error(
        "bad-diffbits at historical height {height}: claimed {claimed:#x} expected {expected:#x}"
    )]
    BadDiffBits {
        height: u32,
        claimed: u32,
        expected: u32,
    },
    /// Header timestamp is not strictly greater than the parent MTP.
    #[error("time-too-old at historical height {0}")]
    TimeTooOld(u32),
    /// Block body does not match a stored historical header.
    #[error("unexpected historical block {0}")]
    UnexpectedBlock(Hash256),
    /// Body fails Core's CheckBlock / ContextualCheckBlock (merkle root,
    /// witness commitment, BIP-34 coinbase height, ...). Not stored.
    #[error("invalid historical block {hash} at height {height}: {err}")]
    InvalidBody {
        hash: Hash256,
        height: u32,
        err: ValidationError,
    },
}

/// Outcome of [`HistoricalBackfill::admit_body`].
#[derive(Debug)]
pub enum BodyAdmission {
    /// Already stored or already being written; nothing to do.
    Duplicate,
    /// Write this body with this (pre-write) index entry, then report back.
    Store(BlockIndexEntry),
}

/// A historical body to persist off the P2P loop.
pub struct BodyWriteJob {
    pub hash: Hash256,
    pub block: Block,
    pub entry: BlockIndexEntry,
    /// Opaque caller data returned in [`BodyWriteDone`] (the P2P loop passes
    /// the delivering peer id so it can top the window back up there).
    pub tag: u64,
}

/// Result of a [`BodyWriteJob`].
#[derive(Debug)]
pub struct BodyWriteDone {
    pub hash: Hash256,
    pub height: u32,
    pub tag: u64,
    pub result: Result<(), String>,
    /// Set when the body was refused by [`HistoricalBackfill::check_body`]
    /// (the delivering peer sent a mutated/invalid block), as opposed to a
    /// local storage failure. The caller punishes the peer on this.
    pub invalid: Option<ValidationError>,
}

/// Dedicated OS thread that performs historical body writes
/// ([`HistoricalBackfill::write_body`]) so the node's single-threaded P2P
/// loop never blocks on them. The P2P loop only does bookkeeping
/// ([`HistoricalBackfill::admit_body`] / [`HistoricalBackfill::body_written`]).
///
/// The job queue is bounded to [`BACKFILL_MAX_BODIES_OUTSTANDING`]; the
/// window guarantees it cannot fill in normal operation, and
/// [`BodyWriter::try_submit`] never blocks if it somehow does. The thread
/// exits when the `BodyWriter` is dropped.
pub struct BodyWriter {
    tx: SyncSender<BodyWriteJob>,
}

impl BodyWriter {
    /// Spawn the writer thread. `on_done` runs on that thread after every job.
    /// Each body is checked ([`HistoricalBackfill::check_body`]) before it is
    /// written; the check runs here, off the P2P loop.
    pub fn spawn<F>(db: Arc<ChainDb>, params: ChainParams, mut on_done: F) -> std::io::Result<Self>
    where
        F: FnMut(BodyWriteDone) + Send + 'static,
    {
        let (tx, rx) = sync_channel::<BodyWriteJob>(BACKFILL_MAX_BODIES_OUTSTANDING);
        std::thread::Builder::new()
            .name("backfill-writer".into())
            .spawn(move || {
                let store = BlockStore::new(&db);
                while let Ok(job) = rx.recv() {
                    let height = job.entry.height;
                    let res = HistoricalBackfill::write_body(
                        &store, &job.hash, &job.block, job.entry, &params,
                    );
                    let invalid = match &res {
                        Err(BackfillError::InvalidBody { err, .. }) => Some(err.clone()),
                        _ => None,
                    };
                    on_done(BodyWriteDone {
                        hash: job.hash,
                        height,
                        tag: job.tag,
                        result: res.map_err(|e| e.to_string()),
                        invalid,
                    });
                }
            })?;
        Ok(BodyWriter { tx })
    }

    /// Queue a job without blocking. Returns the job if the queue is full or
    /// the thread is gone; the caller then reports the write as failed so
    /// the height is re-requested.
    pub fn try_submit(&self, job: BodyWriteJob) -> Result<(), BodyWriteJob> {
        self.tx.try_send(job).map_err(|e| match e {
            TrySendError::Full(j) | TrySendError::Disconnected(j) => j,
        })
    }
}

/// Background backfill of the assumeutxo height-index hole.
pub struct HistoricalBackfill {
    genesis_hash: Hash256,
    /// Last contiguous height from genesis that we have a header + height-index
    /// row for. Starts at 0; advances toward `target_floor - 1`.
    genesis_tip: u32,
    genesis_tip_hash: Hash256,
    /// First indexed height of the snapshot tail (the hole is `1..floor-1`).
    target_floor: u32,
    /// Hash already stored at `target_floor`. Used as getheaders `hash_stop`
    /// and as the linkage check when the hole closes.
    floor_hash: Hash256,
    /// First height in `1..floor-1` whose body is still missing.
    next_body_height: u32,
    /// Resume point of the missing-body scan. Heights in
    /// `next_body_height..body_scan_height` have already been examined: each
    /// was held, in flight, or has just been requested. Such a height can
    /// only become wanted again when its in-flight marker is dropped without
    /// the body being stored, and every place that does that rewinds this
    /// cursor. Without it, a single missing/in-flight body at
    /// `next_body_height` made every call re-walk the whole hole.
    body_scan_height: u32,
    /// Hashes we have asked a peer for and not yet received, with the
    /// [`Self::expire_in_flight`] generation they were requested in.
    in_flight_bodies: HashMap<Hash256, u64>,
    /// Current request generation (advanced by [`Self::expire_in_flight`]).
    body_generation: u64,
    /// Bodies received and handed to the writer, not yet confirmed stored
    /// (hash -> height). Count against [`BACKFILL_MAX_BODIES_OUTSTANDING`].
    pending_writes: HashMap<Hash256, u32>,
    /// A genesis-side getheaders is outstanding. Cleared by the next
    /// historical headers batch or by the maintenance tick.
    headers_in_flight: bool,
    /// Set when a headers batch stored 0 (overlapping resend). Cleared by
    /// [`Self::clear_getheaders_cooldown`] (maintenance tick). Prevents the
    /// tight loop that starved forward getheaders after `--load-snapshot`.
    getheaders_cooldown: bool,
}

impl HistoricalBackfill {
    /// Inspect the store. Returns `Some` when a snapshot hole exists.
    ///
    /// `tip` is the active chain tip height (snapshot tip). `genesis_hash`
    /// is the network genesis; height 0 must already be indexed.
    ///
    /// Cost: O(log n) plus the distance from the persisted progress markers
    /// ([`BlockStore::historical_backfill_header_tip`] /
    /// [`BlockStore::historical_backfill_next_body`]) to the real frontier,
    /// which the running backfill keeps current. Without markers (a datadir
    /// from before they existed) the first call walks the hole once, writing
    /// the markers as it goes, so an interrupted walk resumes. Bitcoin Core
    /// never makes startup wait on this: block availability is a per-entry
    /// `nStatus` bit, and background-chainstate download starts from the
    /// in-memory index. rustoshi used to run this walk on the main task
    /// before P2P started: 2026-10-01 mainnet, 942k height reads plus every
    /// stored historical body (multi-GB) on every boot, 20+ min off-network
    /// under load. The node now calls it on a blocking thread after P2P is up.
    pub fn detect(
        store: &BlockStore<'_>,
        genesis_hash: Hash256,
        tip: u32,
    ) -> Result<Option<Self>, StorageError> {
        Self::detect_cancellable(store, genesis_hash, tip, &AtomicBool::new(false))
    }

    /// [`Self::detect`] that gives up (returning `Ok(None)`, progress
    /// markers saved) as soon as `cancel` is set. The node runs detect on a
    /// background thread and sets `cancel` at shutdown so a stop never waits
    /// for a one-time walk to finish.
    pub fn detect_cancellable(
        store: &BlockStore<'_>,
        genesis_hash: Hash256,
        tip: u32,
        cancel: &AtomicBool,
    ) -> Result<Option<Self>, StorageError> {
        // Resume from the persisted floor if a backfill was already running
        // (height 1 may already be indexed, which makes snapshot_index_floor
        // return None even though a gap remains below the tail).
        let target_floor = match store.historical_backfill_floor()? {
            Some(floor) => floor,
            None => match store.snapshot_index_floor(tip)? {
                Some(floor) => {
                    store.set_historical_backfill_floor(floor)?;
                    floor
                }
                None => return Ok(None),
            },
        };
        let Some(stored_genesis) = store.get_hash_by_height(0)? else {
            return Ok(None);
        };
        if stored_genesis != genesis_hash {
            tracing::warn!(
                "historical backfill: height-0 hash {} != params genesis {}; using stored genesis",
                stored_genesis,
                genesis_hash
            );
        }
        let genesis_hash = stored_genesis;
        let Some(floor_hash) = store.get_hash_by_height(target_floor)? else {
            return Ok(None);
        };

        // Header hole: heights 1..=genesis_tip are contiguous. Start at the
        // marker when its row is there (rows below the floor are only ever
        // added, contiguously, by accept_headers), then find the first gap
        // with one sequential iterator pass.
        let header_marker = store.historical_backfill_header_tip()?;
        let header_start = match header_marker {
            Some(m) if m >= 1 && m < target_floor && store.get_hash_by_height(m)?.is_some() => m,
            _ => 0,
        };
        let first_gap = store.first_missing_height_index(header_start + 1, target_floor)?;
        let genesis_tip = first_gap - 1;
        let genesis_tip_hash = if genesis_tip == 0 {
            genesis_hash
        } else {
            match store.get_hash_by_height(genesis_tip)? {
                Some(h) => h,
                None => {
                    return Err(StorageError::Corruption(format!(
                        "historical backfill: height row {genesis_tip} vanished during detect"
                    )))
                }
            }
        };
        if genesis_tip > 0 && header_marker != Some(genesis_tip) {
            store.set_historical_backfill_header_tip(genesis_tip)?;
        }

        // Body fill: every height in 1..next_body_height has a body. Start
        // at the marker when the body just below it is still there.
        let body_marker = store.historical_backfill_next_body()?;
        let mut next_body_height = match body_marker {
            Some(m)
                if m >= 2
                    && m <= genesis_tip + 1
                    && m <= target_floor
                    && Self::height_has_body_cold(store, m - 1)? =>
            {
                m
            }
            _ => 1,
        };
        let mut since_persist = 0u32;
        while next_body_height <= genesis_tip && next_body_height < target_floor {
            if cancel.load(Ordering::Relaxed) {
                store.set_historical_backfill_next_body(next_body_height)?;
                return Ok(None);
            }
            if !Self::height_has_body_cold(store, next_body_height)? {
                break;
            }
            next_body_height += 1;
            since_persist += 1;
            if since_persist >= DETECT_PERSIST_EVERY {
                store.set_historical_backfill_next_body(next_body_height)?;
                since_persist = 0;
            }
        }
        if body_marker != Some(next_body_height) {
            store.set_historical_backfill_next_body(next_body_height)?;
        }

        Ok(Some(Self {
            genesis_hash,
            genesis_tip,
            genesis_tip_hash,
            target_floor,
            floor_hash,
            next_body_height,
            body_scan_height: next_body_height,
            in_flight_bodies: HashMap::new(),
            body_generation: 0,
            pending_writes: HashMap::new(),
            headers_in_flight: false,
            getheaders_cooldown: false,
        }))
    }

    /// Body presence at `height` without polluting the block cache.
    fn height_has_body_cold(store: &BlockStore<'_>, height: u32) -> Result<bool, StorageError> {
        match store.get_hash_by_height(height)? {
            Some(h) => store.has_block_uncached(&h),
            None => Ok(false),
        }
    }

    /// Like [`detect`], but returns `None` without reading or writing the
    /// store when the operator kill-switch is set. A `--load-snapshot` boot
    /// with the switch on therefore neither persists
    /// `META_HISTORICAL_BACKFILL_FLOOR` nor sends genesis-side getheaders.
    pub fn detect_unless_disabled(
        store: &BlockStore<'_>,
        genesis_hash: Hash256,
        tip: u32,
        cli_disabled: bool,
        env: Option<&str>,
    ) -> Result<Option<Self>, StorageError> {
        if !historical_backfill_is_enabled(cli_disabled, env) {
            return Ok(None);
        }
        Self::detect(store, genesis_hash, tip)
    }

    /// Whether historical backfill may send getheaders/getdata on the shared
    /// peer. False while forward header-sync is occupying getheaders, or
    /// while the validated tip is behind the header tip (forward block
    /// download still needs the connection).
    ///
    /// rustoshi has one P2P pipeline; Core's snapshot chainstate does not
    /// share that constraint. Yielding is how we keep `--load-snapshot`
    /// boot able to request blocks past the base.
    ///
    /// `forward_download_idle` is the forward block downloader having nothing
    /// queued and nothing in flight: a tip block announced but not yet
    /// fetched must not queue behind historical bodies on the same peer.
    pub fn may_use_peer(
        forward_header_sync_idle: bool,
        forward_download_idle: bool,
        validated_tip: u32,
        header_tip: u32,
    ) -> bool {
        forward_header_sync_idle && forward_download_idle && validated_tip >= header_tip
    }

    /// True when the P2P loop should send a genesis-side getheaders.
    /// False once the header hole is closed, during the stored-0 cooldown,
    /// or while a previous getheaders is still unanswered (one outstanding
    /// request, like Core's single headers-sync request per peer).
    pub fn should_request_headers(&self) -> bool {
        !self.headers_complete() && !self.getheaders_cooldown && !self.headers_in_flight
    }

    /// Record that a genesis-side getheaders was sent.
    pub fn note_headers_requested(&mut self) {
        self.headers_in_flight = true;
    }

    /// Allow getheaders again (maintenance tick / peer reconnect). Also
    /// forgets an unanswered getheaders, so a peer that never replied cannot
    /// stall the header backfill beyond one tick.
    pub fn clear_getheaders_cooldown(&mut self) {
        self.getheaders_cooldown = false;
        self.headers_in_flight = false;
    }

    /// Historical bodies requested-not-received plus received-not-written.
    /// Never exceeds [`BACKFILL_MAX_BODIES_OUTSTANDING`] through
    /// [`Self::next_body_hashes`].
    pub fn bodies_outstanding(&self) -> usize {
        self.in_flight_bodies.len() + self.pending_writes.len()
    }

    /// Genesis-side locator for `getheaders`. Newest-first: the last
    /// contiguous historical hash, then genesis if different.
    pub fn locator(&self) -> Vec<Hash256> {
        if self.genesis_tip_hash == self.genesis_hash {
            vec![self.genesis_hash]
        } else {
            vec![self.genesis_tip_hash, self.genesis_hash]
        }
    }

    /// `hash_stop` for `getheaders`: the already-stored floor hash, so the
    /// peer stops at the snapshot tail instead of walking to network tip.
    pub fn hash_stop(&self) -> Hash256 {
        self.floor_hash
    }

    /// Last contiguous genesis-side height we have a header for.
    pub fn genesis_tip(&self) -> u32 {
        self.genesis_tip
    }

    /// First height in `1..floor` whose body may still be missing.
    pub fn next_body_height(&self) -> u32 {
        self.next_body_height
    }

    /// Snapshot-index floor this backfill is filling toward (exclusive).
    pub fn target_floor(&self) -> u32 {
        self.target_floor
    }

    /// Header hole is closed (contiguous genesis chain meets the floor).
    pub fn headers_complete(&self) -> bool {
        self.genesis_tip + 1 >= self.target_floor
    }

    /// Every height in `1..floor-1` has a stored body.
    pub fn bodies_complete(&self) -> bool {
        self.next_body_height >= self.target_floor
    }

    /// Headers and bodies are both filled. `snapshot_index_floor` is `None`.
    pub fn is_complete(&self) -> bool {
        self.headers_complete() && self.bodies_complete()
    }

    /// True when this headers batch belongs to the historical backfill, not
    /// the forward header sync. A genesis-connecting (or overlapping) batch
    /// MUST NOT be given to `HeaderSync` at the snapshot tip: that path
    /// rewinds the header index to height 0 and would wipe the tail band.
    pub fn is_backfill_batch(&self, store: &BlockStore<'_>, headers: &[BlockHeader]) -> bool {
        let Some(first) = headers.first() else {
            return false;
        };
        if first.prev_block_hash == self.genesis_tip_hash {
            return true;
        }
        self.is_historical_hash(store, &first.prev_block_hash)
    }

    /// True when `hash` is a stored historical header whose body we still want.
    pub fn wants_hash(&self, store: &BlockStore<'_>, hash: &Hash256) -> bool {
        match store.get_block_index(hash) {
            Ok(Some(e)) => e.height > 0 && e.height < self.target_floor,
            _ => false,
        }
    }

    /// Apply a headers batch. Stores only missing heights in `1..floor-1`.
    /// Never writes the snapshot tail or moves the active tip.
    ///
    /// Overlapping re-sends of already-stored prefixes are ignored (`Ok(0)`).
    pub fn accept_headers(
        &mut self,
        headers: &[BlockHeader],
        store: &BlockStore<'_>,
        params: &ChainParams,
    ) -> Result<usize, BackfillError> {
        // Whatever this batch is, it answers (or overlaps) our getheaders.
        self.headers_in_flight = false;
        if headers.is_empty() || self.headers_complete() {
            if !self.headers_complete() {
                self.getheaders_cooldown = true;
            }
            return Ok(0);
        }

        let mut start = 0usize;
        if headers[0].prev_block_hash != self.genesis_tip_hash {
            while start < headers.len() && headers[start].prev_block_hash != self.genesis_tip_hash {
                start += 1;
            }
            if start == headers.len() {
                if self.is_historical_hash(store, &headers[0].prev_block_hash) {
                    self.getheaders_cooldown = true;
                    return Ok(0);
                }
                return Err(BackfillError::Unconnecting {
                    expected: self.genesis_tip_hash,
                    got: headers[0].prev_block_hash,
                });
            }
        }

        let mut cache = HeaderCache::new(crate::header_context::DEFAULT_HEADER_CACHE_ENTRIES);
        let mut stored = 0usize;
        let mut parent_work = match store.get_block_index(&self.genesis_tip_hash)? {
            Some(e) => ChainWork(e.chain_work),
            None => ChainWork::from_be_bytes(
                get_block_proof(
                    store
                        .get_header(&self.genesis_tip_hash)?
                        .map(|h| h.bits)
                        .unwrap_or(0),
                )
                .0,
            ),
        };

        for header in &headers[start..] {
            if self.headers_complete() {
                break;
            }
            let height = self.genesis_tip + 1;
            if height >= self.target_floor {
                break;
            }
            if header.prev_block_hash != self.genesis_tip_hash {
                return Err(BackfillError::Unconnecting {
                    expected: self.genesis_tip_hash,
                    got: header.prev_block_hash,
                });
            }
            if !header.validate_pow_against_declared_target() {
                return Err(BackfillError::HighHash(height));
            }
            let expected = expected_bits_for_child(
                store,
                &mut cache,
                &header.prev_block_hash,
                Some(self.genesis_tip),
                header.timestamp,
                params,
            )
            .map_err(|e| BackfillError::Storage(StorageError::Serialization(e.to_string())))?;
            if header.bits != expected {
                return Err(BackfillError::BadDiffBits {
                    height,
                    claimed: header.bits,
                    expected,
                });
            }
            if let Some(mtp) = mtp_of(store, &header.prev_block_hash) {
                if header.timestamp <= mtp {
                    return Err(BackfillError::TimeTooOld(height));
                }
            }

            let hash = header.block_hash();
            // Refuse to overwrite the snapshot tail if a peer walks past it.
            if height == self.target_floor {
                break;
            }
            store.put_header(&hash, header)?;
            store.put_height_index(height, &hash)?;

            let proof = get_block_proof(header.bits);
            parent_work = parent_work.saturating_add(&proof);
            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_HEADER);
            status.set(BlockStatus::VALID_TREE);
            store.put_block_index(
                &hash,
                &BlockIndexEntry {
                    height,
                    status,
                    n_tx: 0,
                    timestamp: header.timestamp,
                    bits: header.bits,
                    nonce: header.nonce,
                    version: header.version,
                    prev_hash: header.prev_block_hash,
                    chain_work: parent_work.0,
                },
            )?;

            self.genesis_tip = height;
            self.genesis_tip_hash = hash;
            stored += 1;
        }

        if stored > 0 {
            // After the rows: the marker may lag the truth, never lead it.
            store.set_historical_backfill_header_tip(self.genesis_tip)?;
        }
        if self.headers_complete() {
            self.verify_floor_link(store)?;
            if stored > 0 {
                tracing::info!(
                    "historical backfill: genesis→floor headers complete; chain work \
                     above the snapshot base is recomputed from them at next startup"
                );
            }
        }
        if self.is_complete() {
            store.clear_historical_backfill_floor()?;
        }
        // Overlapping resend (stored 0) must not immediately re-request: that
        // is the 66,069-iteration stall after `--load-snapshot`. Progress
        // (stored > 0) clears the cooldown so the next batch can be fetched.
        if stored == 0 && !self.headers_complete() {
            self.getheaders_cooldown = true;
        } else if stored > 0 {
            self.getheaders_cooldown = false;
        }
        Ok(stored)
    }

    /// Store a historical block body synchronously. Does not connect UTXO /
    /// does not move the active tip. Updates `n_tx` and `HAVE_DATA` on the
    /// index entry. Equivalent to [`Self::admit_body`] +
    /// [`Self::write_body`] + [`Self::body_written`]; the P2P loop uses the
    /// split form so the disk write runs on the [`BodyWriter`] thread.
    pub fn accept_block(
        &mut self,
        block: &Block,
        store: &BlockStore<'_>,
        params: &ChainParams,
    ) -> Result<bool, BackfillError> {
        let hash = block.block_hash();
        match self.admit_body(&hash, store)? {
            BodyAdmission::Duplicate => Ok(false),
            BodyAdmission::Store(entry) => {
                let res = Self::write_body(store, &hash, block, entry.clone(), params);
                let ok = res.is_ok();
                self.body_written(&hash, entry.height, ok, store)?;
                res.map(|()| true)
            }
        }
    }

    /// Context-free and height-contextual body checks before a historical
    /// body is stored: Core's `CheckBlock` (merkle root incl. CVE-2012-2459
    /// mutation, coinbase rules, per-tx checks, weight, legacy sigops) and
    /// `ContextualCheckBlock` (BIP-34 coinbase height, BIP-141 witness
    /// commitment / unexpected witness). Core runs both in `AcceptBlock`
    /// before `WriteBlock`, for background-chainstate blocks too. The header
    /// itself was already checked (PoW, nBits, MTP) when it was stored, and
    /// the body's hash is the stored header's hash, so this binds the
    /// transactions to that header. Script and UTXO checks are not done
    /// here: the backfill does not connect blocks (see the module docs).
    pub fn check_body(block: &Block, height: u32, params: &ChainParams) -> Result<(), ValidationError> {
        check_block(block, params)?;
        contextual_check_block(block, height, &StubChainContext, params)
    }

    /// Main-loop half of storing a received historical body: cheap checks
    /// (two point reads) and bookkeeping, no body write. On
    /// [`BodyAdmission::Store`] the hash moves from in-flight to
    /// pending-write (it still counts against
    /// [`BACKFILL_MAX_BODIES_OUTSTANDING`]) and the caller must eventually
    /// report the write via [`Self::body_written`].
    pub fn admit_body(
        &mut self,
        hash: &Hash256,
        store: &BlockStore<'_>,
    ) -> Result<BodyAdmission, BackfillError> {
        self.in_flight_bodies.remove(hash);
        if self.pending_writes.contains_key(hash) {
            // A second copy (re-request after expiry) of a body being written.
            return Ok(BodyAdmission::Duplicate);
        }
        let Some(entry) = store.get_block_index(hash)? else {
            return Err(BackfillError::UnexpectedBlock(*hash));
        };
        if entry.height == 0 || entry.height >= self.target_floor {
            return Err(BackfillError::UnexpectedBlock(*hash));
        }
        if store.has_block(hash)? {
            self.advance_body_cursor(store)?;
            return Ok(BodyAdmission::Duplicate);
        }
        self.pending_writes.insert(*hash, entry.height);
        Ok(BodyAdmission::Store(entry))
    }

    /// Disk half: check the body ([`Self::check_body`]), then write it and
    /// mark its index entry `HAVE_DATA`. Takes no `&self`, so it can run on
    /// the [`BodyWriter`] thread. A body that fails the check is not written.
    pub fn write_body(
        store: &BlockStore<'_>,
        hash: &Hash256,
        block: &Block,
        mut entry: BlockIndexEntry,
        params: &ChainParams,
    ) -> Result<(), BackfillError> {
        if block.block_hash() != *hash {
            return Err(BackfillError::UnexpectedBlock(*hash));
        }
        Self::check_body(block, entry.height, params).map_err(|err| BackfillError::InvalidBody {
            hash: *hash,
            height: entry.height,
            err,
        })?;
        store.put_block(hash, block)?;
        entry.n_tx = block.transactions.len() as u32;
        entry.status.set(BlockStatus::HAVE_DATA);
        store.put_block_index(hash, &entry)?;
        Ok(())
    }

    /// Main-loop completion of [`Self::admit_body`]. On failure the height is
    /// rescanned (and so re-requested); on success the completion cursor
    /// advances (bounded).
    pub fn body_written(
        &mut self,
        hash: &Hash256,
        height: u32,
        ok: bool,
        store: &BlockStore<'_>,
    ) -> Result<(), StorageError> {
        self.pending_writes.remove(hash);
        if !ok {
            self.body_scan_height = self.body_scan_height.min(height);
            return Ok(());
        }
        self.advance_body_cursor(store)
    }

    /// Next historical bodies to request, up to `limit`. Records them as
    /// in-flight so a subsequent call does not re-request the same hashes.
    ///
    /// Work per call is bounded by [`BACKFILL_BODY_SCAN_MAX_HEIGHTS`] (for the
    /// completion-cursor advance and for the scan, each): the scan resumes at
    /// `body_scan_height` instead of re-walking from `next_body_height`.
    /// A call may therefore return fewer than `limit` hashes (even none)
    /// while bodies are still missing further up; the next call continues.
    pub fn next_body_hashes(
        &mut self,
        store: &BlockStore<'_>,
        limit: usize,
    ) -> Result<Vec<(u32, Hash256)>, StorageError> {
        // Global window first, before any store read: when the window is
        // full this call costs nothing, however often the P2P loop calls it.
        let limit = limit.min(BACKFILL_MAX_BODIES_OUTSTANDING.saturating_sub(self.bodies_outstanding()));
        if self.bodies_complete() || limit == 0 {
            return Ok(Vec::new());
        }
        // Bodies may have landed out of band (or a previous advance hit its
        // cap): move the completion cursor, bounded.
        self.advance_body_cursor(store)?;
        if self.bodies_complete() {
            return Ok(Vec::new());
        }

        // Last height that can currently have a header: min(genesis_tip, floor-1).
        let end = self.genesis_tip.min(self.target_floor - 1);
        if self.body_scan_height < self.next_body_height {
            self.body_scan_height = self.next_body_height;
        }
        if self.body_scan_height > end && self.bodies_outstanding() == 0 {
            // Everything up to `end` was examined, nothing is outstanding,
            // yet the body at `next_body_height` is still absent: some marker
            // was lost without a rewind. Rescan rather than stall forever.
            self.body_scan_height = self.next_body_height;
        }

        let mut out = Vec::with_capacity(limit);
        let mut h = self.body_scan_height;
        let mut scanned = 0u32;
        while out.len() < limit && h <= end && scanned < BACKFILL_BODY_SCAN_MAX_HEIGHTS {
            scanned += 1;
            if let Some(hash) = store.get_hash_by_height(h)? {
                if !self.in_flight_bodies.contains_key(&hash)
                    && !self.pending_writes.contains_key(&hash)
                    && !store.has_block(&hash)?
                {
                    self.in_flight_bodies.insert(hash, self.body_generation);
                    out.push((h, hash));
                }
            }
            h += 1;
        }
        self.body_scan_height = h;
        Ok(out)
    }

    /// Drop in-flight markers (peer gone / timeout). Subsequent
    /// `next_body_hashes` calls rescan from `next_body_height` and
    /// re-request anything still undelivered.
    pub fn clear_in_flight(&mut self) {
        self.in_flight_bodies.clear();
        self.body_scan_height = self.next_body_height;
    }

    /// Drop body requests that have survived a full tick (requested before
    /// the previous call), then start a new generation. Called from the P2P
    /// maintenance tick (45 s), so an unanswered request is retried after
    /// 45-90 s. Unlike [`Self::clear_in_flight`] this does not forget
    /// requests that are merely recent, which would re-request them while
    /// the first copies are still on the wire and defeat the window.
    /// Returns the number of requests dropped.
    pub fn expire_in_flight(&mut self) -> usize {
        let gen = self.body_generation;
        let before = self.in_flight_bodies.len();
        self.in_flight_bodies.retain(|_, g| *g >= gen);
        self.body_generation += 1;
        let dropped = before - self.in_flight_bodies.len();
        if dropped > 0 {
            self.body_scan_height = self.next_body_height;
        }
        dropped
    }

    fn is_historical_hash(&self, store: &BlockStore<'_>, hash: &Hash256) -> bool {
        match store.get_block_index(hash) {
            Ok(Some(e)) => e.height < self.target_floor,
            _ => false,
        }
    }

    fn verify_floor_link(&self, store: &BlockStore<'_>) -> Result<(), BackfillError> {
        let Some(floor_header) = store.get_header(&self.floor_hash)? else {
            return Err(BackfillError::Unconnecting {
                expected: self.genesis_tip_hash,
                got: Hash256::ZERO,
            });
        };
        if floor_header.prev_block_hash != self.genesis_tip_hash {
            return Err(BackfillError::Unconnecting {
                expected: self.genesis_tip_hash,
                got: floor_header.prev_block_hash,
            });
        }
        Ok(())
    }

    /// Move `next_body_height` across a contiguous run of held bodies, at
    /// most [`BACKFILL_BODY_SCAN_MAX_HEIGHTS`] heights per call (a late body
    /// at the cursor can unblock a run of ~100k held bodies; that walk is
    /// spread over later calls instead of done at once). Clears the persisted
    /// floor when headers and bodies are both complete.
    fn advance_body_cursor(&mut self, store: &BlockStore<'_>) -> Result<(), StorageError> {
        let before = self.next_body_height;
        let mut steps = 0u32;
        while self.next_body_height < self.target_floor && steps < BACKFILL_BODY_SCAN_MAX_HEIGHTS {
            steps += 1;
            match store.get_hash_by_height(self.next_body_height)? {
                Some(h) if store.has_block(&h)? => self.next_body_height += 1,
                _ => break,
            }
        }
        if self.is_complete() {
            store.clear_historical_backfill_floor()?;
        } else if self.next_body_height != before {
            // The bodies below the cursor were read back just now, so they
            // are stored: the marker never leads the truth.
            store.set_historical_backfill_next_body(self.next_body_height)?;
        }
        Ok(())
    }
}

fn mtp_of(store: &BlockStore<'_>, tip_hash: &Hash256) -> Option<u32> {
    use rustoshi_consensus::params::MEDIAN_TIME_PAST_WINDOW;
    let mut timestamps: Vec<u32> = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
    let mut current = *tip_hash;
    for _ in 0..MEDIAN_TIME_PAST_WINDOW {
        match store.get_header(&current) {
            Ok(Some(header)) => {
                timestamps.push(header.timestamp);
                if header.prev_block_hash == Hash256::ZERO {
                    break;
                }
                current = header.prev_block_hash;
            }
            _ => break,
        }
    }
    if timestamps.is_empty() {
        return None;
    }
    timestamps.sort_unstable();
    Some(timestamps[timestamps.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ChainDb;
    use rustoshi_primitives::{OutPoint, Transaction, TxIn, TxOut};
    use tempfile::TempDir;

    fn temp_store() -> (TempDir, ChainDb) {
        let dir = TempDir::new().expect("temp dir");
        let db = ChainDb::open(dir.path()).expect("open db");
        (dir, db)
    }

    fn coinbase(height: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: {
                        // BIP-34 height push (OP_N for 1..=16, else a minimal
                        // CScriptNum push) + one pad byte (scriptSig 2..=100).
                        let mut sig = if height <= 16 {
                            vec![0x50 + height as u8]
                        } else {
                            let mut le = Vec::new();
                            let mut x = height;
                            while x > 0 {
                                le.push((x & 0xff) as u8);
                                x >>= 8;
                            }
                            if le.last().is_some_and(|b| b & 0x80 != 0) {
                                le.push(0);
                            }
                            let mut v = vec![le.len() as u8];
                            v.extend(le);
                            v
                        };
                        sig.push(0x00);
                        sig
                    },
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }
    }

    /// Linked regtest chain genesis..=tip. Returns (blocks, hashes).
    fn build_regtest_chain(params: &ChainParams, tip: u32) -> Vec<Block> {
        let mut blocks = Vec::with_capacity(tip as usize + 1);
        blocks.push(params.genesis_block.clone());
        let mut prev = params.genesis_hash;
        let mut ts = params.genesis_block.header.timestamp;
        let bits = params.genesis_block.header.bits;
        for h in 1..=tip {
            ts += 600;
            let tx = coinbase(h);
            let merkle = tx.txid();
            let mut header = BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: merkle,
                timestamp: ts,
                bits,
                nonce: 0,
            };
            while !header.validate_pow_against_declared_target() {
                header.nonce = header.nonce.wrapping_add(1);
            }
            let block = Block {
                header: header.clone(),
                transactions: vec![tx],
            };
            prev = block.header.block_hash();
            blocks.push(block);
        }
        blocks
    }

    fn seed_snapshot_hole(store: &BlockStore<'_>, blocks: &[Block], floor: u32, tip: u32) {
        // genesis
        let g = &blocks[0];
        let g_hash = g.header.block_hash();
        store.put_header(&g_hash, &g.header).unwrap();
        store.put_block(&g_hash, g).unwrap();
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_HEADER);
        status.set(BlockStatus::VALID_TREE);
        status.set(BlockStatus::HAVE_DATA);
        store
            .put_block_index(
                &g_hash,
                &BlockIndexEntry {
                    height: 0,
                    status,
                    n_tx: g.transactions.len() as u32,
                    timestamp: g.header.timestamp,
                    bits: g.header.bits,
                    nonce: g.header.nonce,
                    version: g.header.version,
                    prev_hash: g.header.prev_block_hash,
                    chain_work: get_block_proof(g.header.bits).0,
                },
            )
            .unwrap();
        store.put_height_index(0, &g_hash).unwrap();
        for n in floor..=tip {
            let b = &blocks[n as usize];
            let hash = b.header.block_hash();
            store.put_header(&hash, &b.header).unwrap();
            store.put_height_index(n, &hash).unwrap();
            let mut st = BlockStatus::new();
            st.set(BlockStatus::VALID_HEADER);
            store
                .put_block_index(
                    &hash,
                    &BlockIndexEntry {
                        height: n,
                        status: st,
                        n_tx: 0,
                        timestamp: b.header.timestamp,
                        bits: b.header.bits,
                        nonce: b.header.nonce,
                        version: b.header.version,
                        prev_hash: b.header.prev_block_hash,
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
        }
        let tip_hash = blocks[tip as usize].header.block_hash();
        store.set_best_block(&tip_hash, tip).unwrap();
    }

    #[test]
    fn historical_backfill_detect_none_when_no_hole() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        store.init_genesis(&params).unwrap();
        assert!(HistoricalBackfill::detect(&store, params.genesis_hash, 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn historical_backfill_detects_assumeutxo_hole() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        assert_eq!(store.snapshot_index_floor(20).unwrap(), Some(10));

        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .expect("hole must be detected");
        assert_eq!(bf.genesis_tip(), 0);
        assert_eq!(bf.target_floor(), 10);
        assert!(!bf.headers_complete());
        assert!(!bf.is_complete());
        assert_eq!(bf.locator()[0], params.genesis_hash);
        assert_eq!(bf.hash_stop(), blocks[10].header.block_hash());
    }

    #[test]
    fn historical_backfill_headers_fill_hole_and_clear_floor() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);

        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let hole: Vec<BlockHeader> = (1..10).map(|h| blocks[h].header.clone()).collect();
        assert!(bf.is_backfill_batch(&store, &hole));
        let n = bf.accept_headers(&hole, &store, &params).unwrap();
        assert_eq!(n, 9);
        assert!(bf.headers_complete());
        assert_eq!(bf.genesis_tip(), 9);
        assert_eq!(store.snapshot_index_floor(20).unwrap(), None);
        assert_eq!(
            store.get_hash_by_height(1).unwrap(),
            Some(blocks[1].header.block_hash())
        );
        // Snapshot tail and active tip are untouched.
        assert_eq!(
            store.get_hash_by_height(10).unwrap(),
            Some(blocks[10].header.block_hash())
        );
        assert_eq!(store.get_best_height().unwrap(), Some(20));
    }

    #[test]
    fn historical_backfill_overlapping_batch_is_ignored() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let hole: Vec<BlockHeader> = (1..10).map(|h| blocks[h].header.clone()).collect();
        assert_eq!(bf.accept_headers(&hole, &store, &params).unwrap(), 9);
        // Re-send the same batch: overlapping prefix, no rewind, no error.
        assert_eq!(bf.accept_headers(&hole, &store, &params).unwrap(), 0);
        assert_eq!(bf.genesis_tip(), 9);
    }

    #[test]
    fn historical_backfill_rejects_unconnecting_headers() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let bogus = BlockHeader {
            version: 1,
            prev_block_hash: Hash256([0x11; 32]),
            merkle_root: Hash256([0x22; 32]),
            timestamp: 1_700_000_000,
            bits: params.genesis_block.header.bits,
            nonce: 0,
        };
        let err = bf
            .accept_headers(&[bogus], &store, &params)
            .expect_err("unconnecting");
        assert!(matches!(err, BackfillError::Unconnecting { .. }));
        assert_eq!(bf.genesis_tip(), 0);
        assert_eq!(store.get_hash_by_height(1).unwrap(), None);
    }

    #[test]
    fn historical_backfill_does_not_rewind_snapshot_tip() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let hole: Vec<BlockHeader> = (1..10).map(|h| blocks[h].header.clone()).collect();
        bf.accept_headers(&hole, &store, &params).unwrap();
        assert_eq!(store.get_best_height().unwrap(), Some(20));
        assert_eq!(
            store.get_best_block_hash().unwrap(),
            Some(blocks[20].header.block_hash())
        );
        // Floor header still the original.
        assert_eq!(
            store.get_hash_by_height(10).unwrap(),
            Some(blocks[10].header.block_hash())
        );
    }

    #[test]
    fn historical_backfill_bodies_complete_the_index() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let hole: Vec<BlockHeader> = (1..10).map(|h| blocks[h].header.clone()).collect();
        bf.accept_headers(&hole, &store, &params).unwrap();
        assert!(!bf.bodies_complete());

        let want = bf.next_body_hashes(&store, 16).unwrap();
        assert_eq!(want.len(), 9);
        assert_eq!(want[0].0, 1);

        for h in 1..10 {
            assert!(bf.accept_block(&blocks[h], &store, &params).unwrap());
        }
        assert!(bf.bodies_complete());
        assert!(bf.is_complete());
        assert!(store.has_block(&blocks[1].header.block_hash()).unwrap());
        let entry = store
            .get_block_index(&blocks[1].header.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(entry.n_tx, 1);
        assert!(entry.status.has(BlockStatus::HAVE_DATA));
        // A second getdata burst is empty.
        assert!(bf.next_body_hashes(&store, 16).unwrap().is_empty());
    }

    #[test]
    fn historical_backfill_resumes_from_partial_fill() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let first: Vec<BlockHeader> = (1..5).map(|h| blocks[h].header.clone()).collect();
        assert_eq!(bf.accept_headers(&first, &store, &params).unwrap(), 4);
        assert_eq!(bf.genesis_tip(), 4);

        // Simulate a restart: detect again from the store.
        let mut bf2 = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        assert_eq!(bf2.genesis_tip(), 4);
        let rest: Vec<BlockHeader> = (5..10).map(|h| blocks[h].header.clone()).collect();
        assert!(bf2.is_backfill_batch(&store, &rest));
        assert_eq!(bf2.accept_headers(&rest, &store, &params).unwrap(), 5);
        assert!(bf2.headers_complete());
        assert_eq!(store.snapshot_index_floor(20).unwrap(), None);
    }

    #[test]
    fn historical_backfill_locator_is_genesis_rooted_not_tip_rooted() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let loc = bf.locator();
        assert_eq!(loc[0], params.genesis_hash);
        assert!(!loc.contains(&blocks[20].header.block_hash()));
        assert_eq!(bf.hash_stop(), blocks[10].header.block_hash());
        assert_ne!(bf.hash_stop(), Hash256::ZERO);
    }

    /// Control for the 2026-09-19 snapshot-boot stall: after `--load-snapshot`
    /// the background backfill must not occupy the shared peer while forward
    /// header-sync is in progress or the validated tip is behind the header
    /// tip. Observed: 66,069 backfill getheaders, zero block requests, tip
    /// frozen at the snapshot base.
    #[test]
    fn historical_backfill_yields_to_forward_sync() {
        assert!(
            !HistoricalBackfill::may_use_peer(false, true, 900_000, 900_000),
            "DownloadingHeaders must not share the getheaders slot with backfill"
        );
        assert!(
            !HistoricalBackfill::may_use_peer(true, true, 900_000, 906_000),
            "validated tip behind header tip: forward block download needs the peer"
        );
        assert!(
            !HistoricalBackfill::may_use_peer(true, false, 906_000, 906_000),
            "forward downloader has blocks queued/in flight: it owns the peer"
        );
        assert!(
            HistoricalBackfill::may_use_peer(true, true, 906_000, 906_000),
            "caught up: backfill may use the peer"
        );
        assert!(
            HistoricalBackfill::may_use_peer(true, true, 910_000, 906_000),
            "validated tip ahead of header tip is still idle-forward"
        );
    }

    /// Post-snapshot headers (connecting at the assumeutxo tail) must never be
    /// classified as historical. If they were, HeaderSync would not see them
    /// and would never enqueue bodies past the snapshot base.
    #[test]
    fn historical_backfill_post_snapshot_headers_are_forward() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        let post: Vec<BlockHeader> = (11..16)
            .map(|h| blocks[h as usize].header.clone())
            .collect();
        assert!(
            !bf.is_backfill_batch(&store, &post),
            "headers connecting past the snapshot floor are forward-sync, not backfill"
        );
        let hole: Vec<BlockHeader> = (1..5).map(|h| blocks[h as usize].header.clone()).collect();
        assert!(bf.is_backfill_batch(&store, &hole));
    }

    /// A stored-0 overlapping resend must cool getheaders. The live stall was
    /// 66,069 iterations of `stored 0 headers, genesis_tip=16000/897973` with
    /// an immediate re-request after every one.
    #[test]
    fn historical_backfill_zero_store_cools_getheaders() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, 20)
            .unwrap()
            .unwrap();
        assert!(
            bf.should_request_headers(),
            "fresh hole must request genesis-side headers"
        );
        let first: Vec<BlockHeader> = (1..5).map(|h| blocks[h as usize].header.clone()).collect();
        assert_eq!(bf.accept_headers(&first, &store, &params).unwrap(), 4);
        assert!(bf.should_request_headers(), "progress must keep requesting");
        assert_eq!(bf.accept_headers(&first, &store, &params).unwrap(), 0);
        assert!(
            !bf.should_request_headers(),
            "stored-0 overlapping resend must not tight-loop getheaders"
        );
        bf.clear_getheaders_cooldown();
        assert!(
            bf.should_request_headers(),
            "maintenance tick clears cooldown so backfill can retry"
        );
    }

    /// Operator kill-switch (QUEUES 2026-09-19): `--no-historical-backfill` /
    /// `HASHHOG_DISABLE_HISTORICAL_BACKFILL` must default to enabled, and
    /// either CLI or a truthy env value must disable. Campaign slices that
    /// boot via `--load-snapshot` need this to skip genesis getheaders so
    /// forward sync owns the only peer.
    #[test]
    fn historical_backfill_kill_switch_defaults_enabled() {
        assert!(historical_backfill_is_enabled(false, None));
        assert!(historical_backfill_is_enabled(false, Some("")));
        assert!(historical_backfill_is_enabled(false, Some("0")));
        assert!(historical_backfill_is_enabled(false, Some("false")));
        assert!(historical_backfill_is_enabled(false, Some("no")));
        assert!(historical_backfill_is_enabled(false, Some("off")));
        assert!(historical_backfill_is_enabled(false, Some("garbage")));
    }

    #[test]
    fn historical_backfill_kill_switch_cli_or_env_disables() {
        assert!(!historical_backfill_is_enabled(true, None));
        assert!(
            !historical_backfill_is_enabled(true, Some("0")),
            "CLI flag disables even if env is a falsey string"
        );
        for v in ["1", "true", "TRUE", "yes", "on", " Yes "] {
            assert!(
                !historical_backfill_is_enabled(false, Some(v)),
                "env={v:?} must disable"
            );
        }
    }

    /// Disabled detect must not persist META_HISTORICAL_BACKFILL_FLOOR.
    /// A "detect then drop" implementation would still write the resume
    /// marker and is not a kill-switch.
    #[test]
    fn historical_backfill_disabled_skips_detect_and_does_not_persist_floor() {
        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, 20);
        seed_snapshot_hole(&store, &blocks, 10, 20);
        assert_eq!(store.snapshot_index_floor(20).unwrap(), Some(10));
        assert!(store.historical_backfill_floor().unwrap().is_none());

        let armed =
            HistoricalBackfill::detect_unless_disabled(&store, params.genesis_hash, 20, true, None)
                .unwrap();
        assert!(armed.is_none(), "CLI kill-switch must not arm P2P backfill");
        assert!(
            store.historical_backfill_floor().unwrap().is_none(),
            "disabled detect must not persist META_HISTORICAL_BACKFILL_FLOOR"
        );

        let armed = HistoricalBackfill::detect_unless_disabled(
            &store,
            params.genesis_hash,
            20,
            false,
            Some("1"),
        )
        .unwrap();
        assert!(armed.is_none(), "env kill-switch must not arm P2P backfill");
        assert!(store.historical_backfill_floor().unwrap().is_none());

        // Default still arms and persists so turning the switch off later resumes.
        let armed = HistoricalBackfill::detect_unless_disabled(
            &store,
            params.genesis_hash,
            20,
            false,
            None,
        )
        .unwrap();
        assert!(armed.is_some());
        assert_eq!(store.historical_backfill_floor().unwrap(), Some(10));
    }

    fn fake_hash(height: u32) -> Hash256 {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&height.to_be_bytes());
        b[31] = 0xbf;
        Hash256(b)
    }

    /// 2026-09-26 mainnet wedge (gdb: main thread in `next_body_hashes` ->
    /// `ChainDb::contains_key` -> pread for ~15 min, every tokio worker idle,
    /// P2P watchdog exit). With the body at the cursor missing or in flight,
    /// `advance_body_cursor` cannot move, and every call re-walked every
    /// height from the cursor to `genesis_tip` (~118k on mainnet): two
    /// RocksDB point reads per height, synchronously on async_main.
    ///
    /// Shape here: hole `1..=50_000`, every body held except height 1 (at the
    /// cursor) and height 40_000. Asserts each call's point reads are bounded
    /// by a constant independent of `genesis_tip`, AND that correctness
    /// holds: every missing body is eventually requested, nothing in flight
    /// is re-requested, `clear_in_flight` makes undelivered bodies eligible
    /// again, and once bodies land the cursor still reaches completion.
    #[test]
    fn historical_backfill_body_scan_is_bounded_per_call() {
        const N: u32 = 50_000;
        const FAR: u32 = 40_000;
        // Generous fixed ceiling: a few thousand reads, vs ~2*N unbounded.
        const MAX_READS_PER_CALL: u64 = 5_000;
        const MAX_CALLS: usize = 1_000;

        let (_dir, db) = temp_store();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        store.init_genesis(&params).unwrap();
        let body = params.genesis_block.clone();
        for h in 1..=N + 1 {
            store.put_height_index(h, &fake_hash(h)).unwrap();
            if h != 1 && h != FAR && h <= N {
                store.put_block(&fake_hash(h), &body).unwrap();
            }
        }
        store.set_historical_backfill_floor(N + 1).unwrap();
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 1)
            .unwrap()
            .expect("hole");
        assert_eq!(bf.genesis_tip(), N);
        assert!(bf.headers_complete());
        assert!(!bf.bodies_complete());

        let call = |bf: &mut HistoricalBackfill| {
            let before = crate::db::test_read_counter::get();
            let out = bf
                .next_body_hashes(&store, BACKFILL_BODIES_PER_REQUEST)
                .unwrap();
            let reads = crate::db::test_read_counter::get() - before;
            assert!(
                reads <= MAX_READS_PER_CALL,
                "next_body_hashes did {reads} RocksDB reads in one call \
                 (bound {MAX_READS_PER_CALL}); genesis_tip={N}"
            );
            out
        };

        // Phase 1: both missing bodies get requested, each exactly once.
        let mut requested: Vec<u32> = Vec::new();
        for _ in 0..MAX_CALLS {
            for (h, hash) in call(&mut bf) {
                assert_eq!(hash, fake_hash(h));
                assert!(
                    !requested.contains(&h),
                    "height {h} double-requested while in flight"
                );
                requested.push(h);
            }
            if requested.contains(&1) && requested.contains(&FAR) {
                break;
            }
        }
        requested.sort_unstable();
        assert_eq!(
            requested,
            vec![1, FAR],
            "every missing body must be requested"
        );

        // Phase 2: both in flight, nothing else missing -> empty, still bounded.
        for _ in 0..50 {
            assert!(
                call(&mut bf).is_empty(),
                "in-flight bodies must not be re-requested"
            );
        }

        // Phase 3: peer gone -> clear_in_flight -> both eligible again.
        bf.clear_in_flight();
        let mut again: Vec<u32> = Vec::new();
        for _ in 0..MAX_CALLS {
            again.extend(call(&mut bf).into_iter().map(|(h, _)| h));
            if again.contains(&1) && again.contains(&FAR) {
                break;
            }
        }
        again.sort_unstable();
        assert_eq!(
            again,
            vec![1, FAR],
            "undelivered bodies must be re-requested after clear_in_flight"
        );

        // Phase 4: bodies land; cursor must still reach completion and clear the floor.
        store.put_block(&fake_hash(1), &body).unwrap();
        store.put_block(&fake_hash(FAR), &body).unwrap();
        for _ in 0..MAX_CALLS {
            if bf.bodies_complete() {
                break;
            }
            assert!(call(&mut bf).is_empty());
        }
        assert!(bf.bodies_complete(), "cursor must advance to the floor");
        assert!(bf.is_complete());
        assert_eq!(store.historical_backfill_floor().unwrap(), None);
    }

    /// Hole 1..=59 with all headers stored, no bodies. Returns (store dir, db, blocks, bf).
    fn body_hole(n: u32) -> (TempDir, ChainDb, Vec<Block>) {
        let (dir, db) = temp_store();
        let params = ChainParams::regtest();
        let blocks = build_regtest_chain(&params, n + 10);
        {
            let store = BlockStore::new(&db);
            seed_snapshot_hole(&store, &blocks, n, n + 10);
        }
        (dir, db, blocks)
    }

    fn armed(store: &BlockStore<'_>, blocks: &[Block], n: u32) -> HistoricalBackfill {
        let params = ChainParams::regtest();
        let mut bf = HistoricalBackfill::detect(store, params.genesis_hash, n + 10)
            .unwrap()
            .unwrap();
        let hole: Vec<BlockHeader> = (1..n as usize).map(|h| blocks[h].header.clone()).collect();
        bf.accept_headers(&hole, store, &params).unwrap();
        assert!(bf.headers_complete());
        bf
    }

    /// 2026-09-28 main-loop starvation: every received body re-ran the scan
    /// and asked for up to 16 MORE, so outstanding bodies grew ~15 per body
    /// received and flooded the priority event lane. The window is global:
    /// however often the P2P loop drives (every Connected, every block,
    /// every tick), at most BACKFILL_MAX_BODIES_OUTSTANDING are outstanding,
    /// and each delivered body frees exactly one slot.
    #[test]
    fn historical_backfill_body_window_is_global_and_bounded() {
        const N: u32 = 60;
        let params = ChainParams::regtest();
        let (_dir, db, blocks) = body_hole(N);
        let store = BlockStore::new(&db);
        let mut bf = armed(&store, &blocks, N);

        let mut requested: Vec<u32> = Vec::new();
        for _ in 0..50 {
            requested.extend(
                bf.next_body_hashes(&store, BACKFILL_BODIES_PER_REQUEST)
                    .unwrap()
                    .into_iter()
                    .map(|(h, _)| h),
            );
        }
        assert_eq!(
            requested.len(),
            BACKFILL_MAX_BODIES_OUTSTANDING,
            "50 drives must not put more than the window in flight"
        );
        assert_eq!(bf.bodies_outstanding(), BACKFILL_MAX_BODIES_OUTSTANDING);

        // The old amplification: deliver one body, drive again. Exactly one
        // slot is free, so exactly one new request -- not 16.
        let mut next_expected = BACKFILL_MAX_BODIES_OUTSTANDING as u32 + 1;
        for h in 1..=30u32 {
            assert!(bf.accept_block(&blocks[h as usize], &store, &params).unwrap());
            let more = bf.next_body_hashes(&store, BACKFILL_BODIES_PER_REQUEST).unwrap();
            assert!(more.len() <= 1, "one body in, at most one request out; got {}", more.len());
            if next_expected < N {
                assert_eq!(more.len(), 1);
                assert_eq!(more[0].0, next_expected);
                next_expected += 1;
            }
            assert!(bf.bodies_outstanding() <= BACKFILL_MAX_BODIES_OUTSTANDING);
        }

        // Drain: the window still completes the hole.
        for h in 31..N {
            bf.accept_block(&blocks[h as usize], &store, &params).unwrap();
            bf.next_body_hashes(&store, BACKFILL_BODIES_PER_REQUEST).unwrap();
        }
        assert!(bf.is_complete());
        assert_eq!(bf.bodies_outstanding(), 0);
    }

    /// The P2P loop's split path: admit (bookkeeping) -> write (writer
    /// thread) -> body_written (bookkeeping). A body being written keeps its
    /// slot and is neither re-requested nor written twice; a failed write is
    /// re-requested.
    #[test]
    fn historical_backfill_split_write_keeps_window_and_retries_failures() {
        const N: u32 = 30;
        let (_dir, db, blocks) = body_hole(N);
        let store = BlockStore::new(&db);
        let mut bf = armed(&store, &blocks, N);
        let first = bf.next_body_hashes(&store, BACKFILL_BODIES_PER_REQUEST).unwrap();
        assert_eq!(first.len(), BACKFILL_MAX_BODIES_OUTSTANDING);

        let b1 = &blocks[1];
        let h1 = b1.block_hash();
        let entry = match bf.admit_body(&h1, &store).unwrap() {
            BodyAdmission::Store(e) => e,
            other => panic!("expected Store, got {other:?}"),
        };
        assert_eq!(entry.height, 1);
        // Pending write still holds its slot: nothing new requested.
        assert_eq!(bf.bodies_outstanding(), BACKFILL_MAX_BODIES_OUTSTANDING);
        assert!(bf.next_body_hashes(&store, 16).unwrap().is_empty());
        // A second copy while the first is being written is a duplicate.
        assert!(matches!(bf.admit_body(&h1, &store).unwrap(), BodyAdmission::Duplicate));

        // Write fails: the slot frees and height 1 is asked for again.
        bf.body_written(&h1, 1, false, &store).unwrap();
        bf.expire_in_flight();
        bf.expire_in_flight(); // drop the other 15 so the rescan starts at 1
        let again = bf.next_body_hashes(&store, 16).unwrap();
        assert!(again.iter().any(|(h, _)| *h == 1), "failed write must be re-requested");

        // Write succeeds: stored with HAVE_DATA, cursor advances.
        let entry = match bf.admit_body(&h1, &store).unwrap() {
            BodyAdmission::Store(e) => e,
            other => panic!("expected Store, got {other:?}"),
        };
        HistoricalBackfill::write_body(&store, &h1, b1, entry, &ChainParams::regtest()).unwrap();
        bf.body_written(&h1, 1, true, &store).unwrap();
        assert!(store.has_block(&h1).unwrap());
        let e = store.get_block_index(&h1).unwrap().unwrap();
        assert!(e.status.has(BlockStatus::HAVE_DATA));
        assert_eq!(e.n_tx, 1);
        assert!(matches!(bf.admit_body(&h1, &store).unwrap(), BodyAdmission::Duplicate));
    }

    /// Requests survive one maintenance tick and expire on the second, so a
    /// request is retried after 45-90 s instead of being duplicated while
    /// the first copy is still on the wire.
    #[test]
    fn historical_backfill_expire_in_flight_is_two_generation() {
        const N: u32 = 20;
        let (_dir, db, blocks) = body_hole(N);
        let store = BlockStore::new(&db);
        let mut bf = armed(&store, &blocks, N);
        let n = bf.next_body_hashes(&store, 16).unwrap().len();
        assert_eq!(n, BACKFILL_MAX_BODIES_OUTSTANDING, "window-capped");
        assert_eq!(bf.expire_in_flight(), 0, "fresh requests survive the first tick");
        assert!(bf.next_body_hashes(&store, 16).unwrap().is_empty());
        assert_eq!(bf.expire_in_flight(), n, "unanswered after a full tick: dropped");
        assert_eq!(bf.next_body_hashes(&store, 16).unwrap().len(), n);
    }

    /// One genesis-side getheaders outstanding at a time.
    #[test]
    fn historical_backfill_one_getheaders_outstanding() {
        const N: u32 = 20;
        let (_dir, db, blocks) = body_hole(N);
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 10)
            .unwrap()
            .unwrap();
        assert!(bf.should_request_headers());
        bf.note_headers_requested();
        assert!(!bf.should_request_headers(), "unanswered getheaders blocks another");
        let part: Vec<BlockHeader> = (1..5).map(|h| blocks[h].header.clone()).collect();
        assert_eq!(bf.accept_headers(&part, &store, &params).unwrap(), 4);
        assert!(bf.should_request_headers(), "the reply re-opens the slot");
        bf.note_headers_requested();
        bf.clear_getheaders_cooldown();
        assert!(bf.should_request_headers(), "the tick forgets an unanswered request");
    }

    /// The writer thread persists bodies and reports back.
    #[test]
    fn body_writer_thread_stores_and_reports() {
        const N: u32 = 10;
        let (_dir, db, blocks) = body_hole(N);
        let db = Arc::new(db);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let writer = BodyWriter::spawn(Arc::clone(&db), ChainParams::regtest(), move |d| {
            let _ = done_tx.send(d);
        })
        .unwrap();
        let store = BlockStore::new(&db);
        let mut bf = armed(&store, &blocks, N);
        bf.next_body_hashes(&store, 16).unwrap();
        for h in 1..N as usize {
            let hash = blocks[h].block_hash();
            let BodyAdmission::Store(entry) = bf.admit_body(&hash, &store).unwrap() else {
                panic!("height {h} should be admitted");
            };
            writer
                .try_submit(BodyWriteJob { hash, block: blocks[h].clone(), entry, tag: 7 })
                .map_err(|_| ())
                .expect("queue has room for the window");
        }
        for _ in 1..N {
            let d = done_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            assert_eq!(d.tag, 7);
            assert!(d.result.is_ok());
            bf.body_written(&d.hash, d.height, true, &store).unwrap();
        }
        assert!(bf.is_complete());
        assert_eq!(bf.bodies_outstanding(), 0);
        drop(writer);
    }

    /// Store shaped like live mainnet mid-backfill (2026-10-01): header hole
    /// closed (rows 1..floor-1), bodies 1..=bodies_top, floor marker set, NO
    /// progress markers (a datadir from before they existed).
    fn legacy_mid_backfill_store(n: u32, bodies_top: u32) -> (TempDir, ChainDb) {
        let (dir, db) = temp_store();
        {
            let store = BlockStore::new(&db);
            let params = ChainParams::regtest();
            store.init_genesis(&params).unwrap();
            let body = params.genesis_block.clone();
            for h in 1..=n + 1 {
                store.put_height_index(h, &fake_hash(h)).unwrap();
                if h <= bodies_top {
                    store.put_block(&fake_hash(h), &body).unwrap();
                }
            }
            store.set_historical_backfill_floor(n + 1).unwrap();
            assert_eq!(store.historical_backfill_header_tip().unwrap(), None);
            assert_eq!(store.historical_backfill_next_body().unwrap(), None);
        }
        (dir, db)
    }

    fn detect_reads(store: &BlockStore<'_>, tip: u32) -> (HistoricalBackfill, u64) {
        let params = ChainParams::regtest();
        let before = crate::db::test_read_counter::get();
        let bf = HistoricalBackfill::detect(store, params.genesis_hash, tip)
            .unwrap()
            .expect("hole");
        (bf, crate::db::test_read_counter::get() - before)
    }

    /// 2026-10-01 mainnet: every boot spent 20+ min in `detect` before P2P
    /// started, because detect re-derived the backfill frontier from scratch
    /// (one read per indexed height, then one full-body read per stored
    /// body). With the persisted progress markers, the walk is done once;
    /// every later detect costs a constant number of reads, however large
    /// the history. On master (no markers) the second detect below does
    /// ~N + M reads again and this test fails.
    #[test]
    fn historical_backfill_detect_is_constant_reads_once_markers_exist() {
        const N: u32 = 60_000;
        const M: u32 = 25_000;
        const MAX_READS: u64 = 32;
        let (_dir, db) = legacy_mid_backfill_store(N, M);
        let store = BlockStore::new(&db);

        // First detect on a legacy datadir: the one-time walk. It must agree
        // with the frontier, and it leaves the markers behind.
        let (bf, first_reads) = detect_reads(&store, N + 1);
        assert_eq!(bf.genesis_tip(), N);
        assert_eq!(bf.next_body_height(), M + 1);
        assert!(first_reads > M as u64, "legacy walk reads the bodies once ({first_reads})");
        assert_eq!(store.historical_backfill_header_tip().unwrap(), Some(N));
        assert_eq!(store.historical_backfill_next_body().unwrap(), Some(M + 1));

        // Every later boot: constant.
        for _ in 0..3 {
            let (bf, reads) = detect_reads(&store, N + 1);
            assert_eq!(bf.genesis_tip(), N);
            assert_eq!(bf.next_body_height(), M + 1);
            assert!(
                reads <= MAX_READS,
                "detect did {reads} reads with markers present (bound {MAX_READS}); \
                 history is {N} heights / {M} bodies"
            );
        }
    }

    /// The markers are lower bounds, never trusted past what is stored: a
    /// marker that lags (crash before it was rewritten) is walked forward to
    /// the true frontier, and a marker whose vouching body is gone falls
    /// back to the full walk instead of skipping a hole.
    #[test]
    fn historical_backfill_detect_markers_are_verified_lower_bounds() {
        const N: u32 = 5_000;
        const M: u32 = 3_000;
        let (_dir, db) = legacy_mid_backfill_store(N, M);
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();

        // Lagging markers: walked forward.
        store.set_historical_backfill_header_tip(100).unwrap();
        store.set_historical_backfill_next_body(200).unwrap();
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 1).unwrap().unwrap();
        assert_eq!((bf.genesis_tip(), bf.next_body_height()), (N, M + 1));
        assert_eq!(store.historical_backfill_next_body().unwrap(), Some(M + 1));

        // A body below the marker disappeared (e.g. pruned): the marker's
        // vouching body (marker-1) is missing -> full walk -> real gap found.
        db.delete_cf(crate::columns::CF_BLOCKS, fake_hash(M).as_bytes()).unwrap();
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 1).unwrap().unwrap();
        assert_eq!(bf.next_body_height(), M);

        // Overstated marker past the stored rows/bodies: rejected, not trusted.
        store.set_historical_backfill_next_body(N).unwrap();
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 1).unwrap().unwrap();
        assert_eq!(bf.next_body_height(), M);
        store.set_historical_backfill_header_tip(N + 5).unwrap();
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 1).unwrap().unwrap();
        assert_eq!(bf.genesis_tip(), N);
    }

    /// The running backfill keeps the markers current: accept_headers after
    /// its rows, the body cursor after the bodies it read back.
    #[test]
    fn historical_backfill_progress_markers_follow_the_backfill() {
        const N: u32 = 30;
        let (_dir, db, blocks) = body_hole(N);
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let mut bf = HistoricalBackfill::detect(&store, params.genesis_hash, N + 10)
            .unwrap()
            .unwrap();
        let part: Vec<BlockHeader> = (1..12).map(|h| blocks[h].header.clone()).collect();
        assert_eq!(bf.accept_headers(&part, &store, &params).unwrap(), 11);
        assert_eq!(store.historical_backfill_header_tip().unwrap(), Some(11));
        let rest: Vec<BlockHeader> = (12..N as usize).map(|h| blocks[h].header.clone()).collect();
        bf.accept_headers(&rest, &store, &params).unwrap();
        assert_eq!(store.historical_backfill_header_tip().unwrap(), Some(N - 1));

        bf.next_body_hashes(&store, 16).unwrap();
        for h in 1..=5 {
            assert!(bf.accept_block(&blocks[h], &store, &params).unwrap());
        }
        assert_eq!(store.historical_backfill_next_body().unwrap(), Some(6));

        // Restart: resumes at the markers.
        let bf2 = HistoricalBackfill::detect(&store, params.genesis_hash, N + 10).unwrap().unwrap();
        assert_eq!((bf2.genesis_tip(), bf2.next_body_height()), (N - 1, 6));

        // Completion clears the floor and both markers.
        for h in 6..N as usize {
            bf.accept_block(&blocks[h], &store, &params).unwrap();
        }
        assert!(bf.is_complete());
        assert_eq!(store.historical_backfill_floor().unwrap(), None);
        assert_eq!(store.historical_backfill_header_tip().unwrap(), None);
        assert_eq!(store.historical_backfill_next_body().unwrap(), None);
    }

    /// Shutdown during the one-time legacy walk: detect gives up at once and
    /// keeps its progress, so the next boot resumes rather than restarts.
    #[test]
    fn historical_backfill_detect_cancel_keeps_progress() {
        let (_dir, db) = legacy_mid_backfill_store(1_000, 800);
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let cancel = AtomicBool::new(true);
        let r = HistoricalBackfill::detect_cancellable(&store, params.genesis_hash, 1_001, &cancel)
            .unwrap();
        assert!(r.is_none(), "cancelled detect arms nothing");
        assert!(store.historical_backfill_next_body().unwrap().is_some());
        let bf = HistoricalBackfill::detect(&store, params.genesis_hash, 1_001).unwrap().unwrap();
        assert_eq!(bf.next_body_height(), 801);
    }

    /// Q:91: a historical body whose transactions do not match its header
    /// (same block hash, different txs) was stored and then served. Core's
    /// AcceptBlock runs CheckBlock + ContextualCheckBlock before WriteBlock.
    #[test]
    fn historical_backfill_refuses_mutated_bodies() {
        const N: u32 = 10;
        let (_dir, db, blocks) = body_hole(N);
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        let mut bf = armed(&store, &blocks, N);
        bf.next_body_hashes(&store, 16).unwrap();

        // Merkle mismatch: change a tx, keep the header (so the hash).
        let mut bad = blocks[1].clone();
        bad.transactions[0].outputs[0].value -= 1;
        let h1 = blocks[1].block_hash();
        assert_eq!(bad.block_hash(), h1);
        let err = bf.accept_block(&bad, &store, &params).unwrap_err();
        assert!(
            matches!(err, BackfillError::InvalidBody { err: ValidationError::BadMerkleRoot, .. }),
            "{err:?}"
        );
        assert!(!store.has_block(&h1).unwrap(), "mutated body must not be stored");

        // Witness malleation: witness data does not change the txid, so the
        // merkle root still matches; there is no commitment.
        let mut bad = blocks[2].clone();
        bad.transactions[0].inputs[0].witness = vec![vec![0u8; 32]];
        let h2 = blocks[2].block_hash();
        assert_eq!(bad.block_hash(), h2);
        let err = bf.accept_block(&bad, &store, &params).unwrap_err();
        assert!(
            matches!(err, BackfillError::InvalidBody { err: ValidationError::UnexpectedWitness, .. }),
            "{err:?}"
        );
        assert!(!store.has_block(&h2).unwrap());

        // The honest bodies are still accepted afterwards.
        assert!(bf.accept_block(&blocks[1], &store, &params).unwrap());
        assert!(bf.accept_block(&blocks[2], &store, &params).unwrap());
    }
}
