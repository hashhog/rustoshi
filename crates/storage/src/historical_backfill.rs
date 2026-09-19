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
//! UTXO re-derivation of genesis→base (Core's in-memory/disk background
//! coins view) is a separate concern: `ChainstateManager` already does it
//! for small chains. Replaying ~942k mainnet blocks into a RAM `HashMap`
//! would OOM; this backfill is the operator-visible historical index.

use std::collections::HashSet;

use rustoshi_consensus::params::ChainParams;
use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_primitives::{Block, BlockHeader, Hash256};

use crate::block_store::{BlockIndexEntry, BlockStatus, BlockStore};
use crate::db::StorageError;
use crate::header_context::{expected_bits_for_child, HeaderCache};

/// Maximum bodies requested in one getdata burst. Matches Core's default
/// per-peer in-flight cap so historical download cannot starve tip sync.
pub const BACKFILL_BODIES_PER_REQUEST: usize = 16;

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
    /// Hashes we have asked a peer for and not yet received.
    in_flight_bodies: HashSet<Hash256>,
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
    pub fn detect(
        store: &BlockStore<'_>,
        genesis_hash: Hash256,
        tip: u32,
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

        let mut genesis_tip = 0u32;
        let mut genesis_tip_hash = genesis_hash;
        while genesis_tip + 1 < target_floor {
            match store.get_hash_by_height(genesis_tip + 1)? {
                Some(h) => {
                    genesis_tip += 1;
                    genesis_tip_hash = h;
                }
                None => break,
            }
        }

        let mut next_body_height = 1u32;
        while next_body_height <= genesis_tip && next_body_height < target_floor {
            match store.get_hash_by_height(next_body_height)? {
                Some(h) if store.has_block(&h)? => next_body_height += 1,
                _ => break,
            }
        }

        Ok(Some(Self {
            genesis_hash,
            genesis_tip,
            genesis_tip_hash,
            target_floor,
            floor_hash,
            next_body_height,
            in_flight_bodies: HashSet::new(),
            getheaders_cooldown: false,
        }))
    }

    /// Whether historical backfill may send getheaders/getdata on the shared
    /// peer. False while forward header-sync is occupying getheaders, or
    /// while the validated tip is behind the header tip (forward block
    /// download still needs the connection).
    ///
    /// rustoshi has one P2P pipeline; Core's snapshot chainstate does not
    /// share that constraint. Yielding is how we keep `--load-snapshot`
    /// boot able to request blocks past the base.
    pub fn may_use_peer(
        forward_header_sync_idle: bool,
        validated_tip: u32,
        header_tip: u32,
    ) -> bool {
        forward_header_sync_idle && validated_tip >= header_tip
    }

    /// True when the P2P loop should send a genesis-side getheaders.
    /// False once the header hole is closed, or during the stored-0 cooldown.
    pub fn should_request_headers(&self) -> bool {
        !self.headers_complete() && !self.getheaders_cooldown
    }

    /// Allow getheaders again (maintenance tick / peer reconnect).
    pub fn clear_getheaders_cooldown(&mut self) {
        self.getheaders_cooldown = false;
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

        if self.headers_complete() {
            self.verify_floor_link(store)?;
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

    /// Store a historical block body. Does not connect UTXO / does not move
    /// the active tip. Updates `n_tx` and `HAVE_DATA` on the index entry.
    pub fn accept_block(
        &mut self,
        block: &Block,
        store: &BlockStore<'_>,
    ) -> Result<bool, BackfillError> {
        let hash = block.block_hash();
        self.in_flight_bodies.remove(&hash);
        let Some(entry) = store.get_block_index(&hash)? else {
            return Err(BackfillError::UnexpectedBlock(hash));
        };
        if entry.height == 0 || entry.height >= self.target_floor {
            return Err(BackfillError::UnexpectedBlock(hash));
        }
        if store.has_block(&hash)? {
            self.advance_body_cursor(store)?;
            return Ok(false);
        }
        store.put_block(&hash, block)?;
        let mut entry = entry;
        entry.n_tx = block.transactions.len() as u32;
        entry.status.set(BlockStatus::HAVE_DATA);
        store.put_block_index(&hash, &entry)?;
        self.advance_body_cursor(store)?;
        if self.is_complete() {
            store.clear_historical_backfill_floor()?;
        }
        Ok(true)
    }

    /// Next historical bodies to request, up to `limit`. Records them as
    /// in-flight so a subsequent call does not re-request the same hashes.
    pub fn next_body_hashes(
        &mut self,
        store: &BlockStore<'_>,
        limit: usize,
    ) -> Result<Vec<(u32, Hash256)>, StorageError> {
        if self.bodies_complete() || limit == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(limit);
        let mut h = self.next_body_height;
        while out.len() < limit && h < self.target_floor && h <= self.genesis_tip {
            if let Some(hash) = store.get_hash_by_height(h)? {
                if !store.has_block(&hash)? && !self.in_flight_bodies.contains(&hash) {
                    self.in_flight_bodies.insert(hash);
                    out.push((h, hash));
                }
            }
            h += 1;
        }
        Ok(out)
    }

    /// Drop in-flight markers (peer gone / timeout). Next `next_body_hashes`
    /// will re-request.
    pub fn clear_in_flight(&mut self) {
        self.in_flight_bodies.clear();
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

    fn advance_body_cursor(&mut self, store: &BlockStore<'_>) -> Result<(), StorageError> {
        while self.next_body_height < self.target_floor {
            match store.get_hash_by_height(self.next_body_height)? {
                Some(h) if store.has_block(&h)? => self.next_body_height += 1,
                _ => break,
            }
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
                script_sig: vec![
                    0x03,
                    (height & 0xff) as u8,
                    ((height >> 8) & 0xff) as u8,
                    ((height >> 16) & 0xff) as u8,
                ],
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
            assert!(bf.accept_block(&blocks[h], &store).unwrap());
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
            !HistoricalBackfill::may_use_peer(false, 900_000, 900_000),
            "DownloadingHeaders must not share the getheaders slot with backfill"
        );
        assert!(
            !HistoricalBackfill::may_use_peer(true, 900_000, 906_000),
            "validated tip behind header tip: forward block download needs the peer"
        );
        assert!(
            HistoricalBackfill::may_use_peer(true, 906_000, 906_000),
            "caught up: backfill may use the peer"
        );
        assert!(
            HistoricalBackfill::may_use_peer(true, 910_000, 906_000),
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
}
