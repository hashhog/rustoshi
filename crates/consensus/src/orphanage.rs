//! Orphan transaction pool.
//!
//! When a transaction arrives whose inputs are not present in the chainstate
//! or the mempool ("orphan"), Bitcoin Core temporarily caches it in case the
//! parent shows up shortly after.  Without this, valid orphans are silently
//! dropped — a correctness gap for fast tx propagation — and there is no
//! DoS-bound on memory if any path inadvertently buffers them.
//!
//! This is a lean Rust port of `bitcoin-core/src/node/txorphanage.cpp`'s
//! pre-2024 shape:
//!
//! - Per-orphan size cap (`MAX_ORPHAN_TX_SIZE` = 100_000 bytes) to bound the
//!   maximum memory of a single orphan.
//! - Global count cap (`MAX_ORPHAN_TRANSACTIONS` = 100) — when full, evict
//!   the oldest entry (FIFO; randomized ordering would also be acceptable
//!   per Core's documentation but determinism makes tests easier).
//! - Per-peer count cap (`MAX_ORPHANS_PER_PEER` = 100, matching the global
//!   cap so that one well-behaved peer can fill the pool, but a single peer
//!   pinning the pool full of garbage loses ground to evictions caused by
//!   the next peer's submissions because we evict-on-insert).
//! - Lookup-and-promote: when a parent transaction arrives, the caller can
//!   ask the orphanage for orphans whose `prev_hash` matches the parent's
//!   txid and re-attempt admission.
//! - `EraseForBlock` and `EraseForPeer` for housekeeping after a new block
//!   or a peer disconnect.
//!
//! Thread-safety: this struct is *not* internally locked; callers (the main
//! event loop and RPC paths) must serialize access.  In rustoshi the
//! mempool is protected by the same `RwLock<RpcState>` that the orphanage
//! lives inside.

use rustoshi_primitives::{Hash256, OutPoint, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Maximum size of an orphan transaction in bytes (Core constant).
///
/// Reference: `bitcoin-core/src/node/txdownloadman_impl.h` —
/// `MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR / 4` ≈ 100_000.
pub const MAX_ORPHAN_TX_SIZE: usize = 100_000;

/// Maximum number of orphan transactions held globally (Core constant).
///
/// Reference: `bitcoin-core/src/node/txdownloadman_impl.h` —
/// `DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100`.
pub const MAX_ORPHAN_TRANSACTIONS: usize = 100;

/// Maximum number of orphan transactions a single peer can announce.
///
/// Matches the global cap so that an honest peer can fully populate the
/// orphanage during a normal burst.  Per-peer accounting still prevents a
/// misbehaving peer from getting *more* than its share even with multiple
/// peers contributing.
pub const MAX_ORPHANS_PER_PEER: usize = 100;

/// A single orphan entry.
///
/// Wraps the transaction in `Arc` so the same tx can be referenced from the
/// peer-side and the txid-side maps without copying.
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    /// The orphan transaction.
    pub tx: Arc<Transaction>,
    /// Peer that announced this orphan (used for per-peer accounting +
    /// `EraseForPeer`).
    pub from_peer: u64,
    /// Wall-clock insertion order (FIFO eviction key).  Monotonically
    /// increasing across the orphanage's lifetime.
    pub seq: u64,
}

/// Reasons an `add` call can fail.  None of these are protocol errors —
/// they're soft bounds enforced by the orphanage itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrphanError {
    /// Tx exceeds `MAX_ORPHAN_TX_SIZE` after serialization.
    TooLarge { size: usize },
    /// Per-peer cap reached (`MAX_ORPHANS_PER_PEER`).
    PeerCap,
    /// Already present (by txid).
    AlreadyKnown,
}

/// Orphan transaction pool.
///
/// Tracks unconfirmed transactions whose inputs cannot be resolved against
/// the chainstate + mempool *yet*, so they may become valid as soon as
/// their missing parent arrives.
#[derive(Debug, Default)]
pub struct TxOrphanage {
    /// Primary index: txid → OrphanEntry.
    by_txid: HashMap<Hash256, OrphanEntry>,
    /// Per-peer txid set, used for the per-peer cap and `erase_for_peer`.
    by_peer: HashMap<u64, HashSet<Hash256>>,
    /// FIFO queue of txids in insertion order; used by the eviction policy.
    /// Stale entries (txids no longer in `by_txid`) are skipped lazily.
    fifo: VecDeque<Hash256>,
    /// Insertion-order counter; assigned to `OrphanEntry::seq` and
    /// monotonically increases across the orphanage's lifetime.
    next_seq: u64,
}

impl TxOrphanage {
    /// Create an empty orphanage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of orphans currently stored.
    pub fn len(&self) -> usize {
        self.by_txid.len()
    }

    /// `true` if the orphanage holds no transactions.
    pub fn is_empty(&self) -> bool {
        self.by_txid.is_empty()
    }

    /// `true` if a transaction with this txid is currently stored.
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.by_txid.contains_key(txid)
    }

    /// Number of orphans currently stored from a specific peer.
    pub fn count_from_peer(&self, peer: u64) -> usize {
        self.by_peer.get(&peer).map(|s| s.len()).unwrap_or(0)
    }

    /// Insert a new orphan.
    ///
    /// Returns `Ok(())` if the orphan was inserted (which may have triggered
    /// an eviction), or `Err(OrphanError)` if a soft bound was hit.  If the
    /// global cap is exceeded, the oldest entry is evicted to make room.
    ///
    /// `serialized_size` is the byte length of the wire encoding; callers
    /// should pass the value from the deserializer rather than re-serialize.
    pub fn add(
        &mut self,
        tx: Arc<Transaction>,
        from_peer: u64,
        serialized_size: usize,
    ) -> Result<(), OrphanError> {
        if serialized_size > MAX_ORPHAN_TX_SIZE {
            return Err(OrphanError::TooLarge {
                size: serialized_size,
            });
        }

        let txid = tx.txid();
        if self.by_txid.contains_key(&txid) {
            return Err(OrphanError::AlreadyKnown);
        }

        // Per-peer cap.  Reject before evicting global FIFO so a single
        // peer cannot churn the orphanage by spamming + flooding everyone
        // else's orphans.
        if self.count_from_peer(from_peer) >= MAX_ORPHANS_PER_PEER {
            return Err(OrphanError::PeerCap);
        }

        // Evict oldest entries until we have room for this one.
        while self.by_txid.len() >= MAX_ORPHAN_TRANSACTIONS {
            if !self.evict_oldest() {
                // FIFO somehow drained without freeing room.  Defensive:
                // shouldn't happen, but bail rather than spin.
                break;
            }
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        self.by_txid.insert(
            txid,
            OrphanEntry {
                tx,
                from_peer,
                seq,
            },
        );
        self.by_peer
            .entry(from_peer)
            .or_default()
            .insert(txid);
        self.fifo.push_back(txid);

        Ok(())
    }

    /// Remove a single orphan by txid.  Returns the entry if present.
    pub fn erase(&mut self, txid: &Hash256) -> Option<OrphanEntry> {
        let entry = self.by_txid.remove(txid)?;
        if let Some(set) = self.by_peer.get_mut(&entry.from_peer) {
            set.remove(txid);
            if set.is_empty() {
                self.by_peer.remove(&entry.from_peer);
            }
        }
        // We don't proactively scan `fifo` — stale entries are skipped on
        // pop in `evict_oldest`.
        Some(entry)
    }

    /// Remove every orphan announced by a given peer.  Called on disconnect.
    pub fn erase_for_peer(&mut self, peer: u64) -> usize {
        let txids: Vec<Hash256> = match self.by_peer.remove(&peer) {
            Some(set) => set.into_iter().collect(),
            None => return 0,
        };
        let mut removed = 0;
        for txid in &txids {
            if self.by_txid.remove(txid).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Remove orphans whose inputs were spent by a newly-connected block, or
    /// that were themselves included in the block.
    ///
    /// Mirrors `TxOrphanage::EraseForBlock`.  After a block lands, any
    /// orphan that depended on a (now-spent) UTXO is permanently invalid;
    /// keeping it around just wastes an orphanage slot.
    pub fn erase_for_block(&mut self, block_txids: &[Hash256], spent: &[OutPoint]) -> usize {
        let included: HashSet<&Hash256> = block_txids.iter().collect();
        let spent_set: HashSet<&OutPoint> = spent.iter().collect();

        let mut to_remove = Vec::new();
        for (txid, entry) in &self.by_txid {
            if included.contains(txid) {
                to_remove.push(*txid);
                continue;
            }
            if entry
                .tx
                .inputs
                .iter()
                .any(|i| spent_set.contains(&i.previous_output))
            {
                to_remove.push(*txid);
            }
        }
        let n = to_remove.len();
        for txid in to_remove {
            self.erase(&txid);
        }
        n
    }

    /// Find orphans whose inputs reference `parent_txid`.  Used when a new
    /// transaction arrives in the mempool: any orphan that lists the new tx
    /// as a parent should be re-tried for admission.
    ///
    /// Returns owned clones of the matching entries.  The caller is
    /// responsible for `erase`-ing successfully admitted ones; rejected
    /// orphans should also be erased to avoid retrying them on every parent
    /// arrival (the caller can record a "tried-and-failed" set if desired).
    pub fn find_children(&self, parent_txid: &Hash256) -> Vec<OrphanEntry> {
        let mut out = Vec::new();
        for entry in self.by_txid.values() {
            if entry
                .tx
                .inputs
                .iter()
                .any(|inp| &inp.previous_output.txid == parent_txid)
            {
                out.push(entry.clone());
            }
        }
        // Stable order (oldest-first) so behavior is reproducible.
        out.sort_by_key(|e| e.seq);
        out
    }

    /// Drop the oldest orphan in FIFO order.  Called when the global cap is
    /// reached.  Returns `true` if something was evicted.
    fn evict_oldest(&mut self) -> bool {
        while let Some(txid) = self.fifo.pop_front() {
            if self.by_txid.contains_key(&txid) {
                self.erase(&txid);
                return true;
            }
            // else: stale FIFO entry from a prior `erase`; keep popping.
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};

    fn make_tx(prev: Hash256, prev_vout: u32) -> Arc<Transaction> {
        Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev,
                    vout: prev_vout,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x6a, 0x00], // OP_RETURN, dummy
            }],
            lock_time: 0,
        })
    }

    fn make_unique_tx(seed: u32) -> Arc<Transaction> {
        // Tweak prev_index so the txid changes per call.
        make_tx(Hash256([0xaa; 32]), seed)
    }

    #[test]
    fn add_lookup_remove_round_trip() {
        let mut o = TxOrphanage::new();
        let tx = make_unique_tx(1);
        let txid = tx.txid();

        assert_eq!(o.len(), 0);
        assert!(!o.contains(&txid));
        assert!(o.add(tx.clone(), 7, 250).is_ok());
        assert_eq!(o.len(), 1);
        assert!(o.contains(&txid));
        assert_eq!(o.count_from_peer(7), 1);

        let entry = o.erase(&txid).expect("present");
        assert_eq!(entry.from_peer, 7);
        assert_eq!(o.len(), 0);
        assert_eq!(o.count_from_peer(7), 0);
    }

    #[test]
    fn rejects_too_large_tx() {
        let mut o = TxOrphanage::new();
        let tx = make_unique_tx(2);
        let err = o
            .add(tx.clone(), 1, MAX_ORPHAN_TX_SIZE + 1)
            .expect_err("should reject");
        assert!(matches!(err, OrphanError::TooLarge { size } if size == MAX_ORPHAN_TX_SIZE + 1));
        assert_eq!(o.len(), 0);
    }

    #[test]
    fn rejects_already_known() {
        let mut o = TxOrphanage::new();
        let tx = make_unique_tx(3);
        assert!(o.add(tx.clone(), 1, 100).is_ok());
        let err = o.add(tx, 1, 100).expect_err("dup");
        assert_eq!(err, OrphanError::AlreadyKnown);
    }

    #[test]
    fn enforces_per_peer_cap() {
        let mut o = TxOrphanage::new();
        for i in 0..MAX_ORPHANS_PER_PEER as u32 {
            let tx = make_unique_tx(i);
            o.add(tx, 42, 200).unwrap();
        }
        let extra = make_unique_tx(MAX_ORPHANS_PER_PEER as u32);
        let err = o.add(extra, 42, 200).expect_err("peer cap");
        assert_eq!(err, OrphanError::PeerCap);
        assert_eq!(o.count_from_peer(42), MAX_ORPHANS_PER_PEER);
    }

    #[test]
    fn evicts_oldest_at_global_cap() {
        let mut o = TxOrphanage::new();
        // Fill up using DIFFERENT peers so the per-peer cap doesn't block.
        for i in 0..MAX_ORPHAN_TRANSACTIONS as u32 {
            let tx = make_unique_tx(i);
            // peer = i so each peer has 1 orphan.
            o.add(tx, i as u64, 200).unwrap();
        }
        assert_eq!(o.len(), MAX_ORPHAN_TRANSACTIONS);

        // First inserted txid (the oldest) must get evicted next.
        let first_txid = make_unique_tx(0).txid();
        assert!(o.contains(&first_txid));

        let new_tx = make_unique_tx(MAX_ORPHAN_TRANSACTIONS as u32);
        o.add(new_tx, 9999, 200).unwrap();

        assert_eq!(o.len(), MAX_ORPHAN_TRANSACTIONS);
        assert!(!o.contains(&first_txid), "oldest should be evicted");
    }

    #[test]
    fn erase_for_peer_drops_all_their_entries() {
        let mut o = TxOrphanage::new();
        for i in 0..5 {
            o.add(make_unique_tx(i), 1, 200).unwrap();
        }
        for i in 5..8 {
            o.add(make_unique_tx(i), 2, 200).unwrap();
        }
        assert_eq!(o.len(), 8);

        let removed = o.erase_for_peer(1);
        assert_eq!(removed, 5);
        assert_eq!(o.len(), 3);
        assert_eq!(o.count_from_peer(1), 0);
        assert_eq!(o.count_from_peer(2), 3);
    }

    #[test]
    fn find_children_returns_orphans_pointing_at_parent() {
        let mut o = TxOrphanage::new();
        // parent_txid is the prev_hash of these orphans.
        let parent_txid = Hash256([0xaa; 32]);

        // Three orphans all spending from parent_txid (different output indexes).
        let a = make_tx(parent_txid, 0);
        let b = make_tx(parent_txid, 1);
        let c = make_tx(parent_txid, 2);
        o.add(a.clone(), 1, 200).unwrap();
        o.add(b.clone(), 1, 200).unwrap();
        o.add(c.clone(), 1, 200).unwrap();

        // One unrelated orphan (different parent).
        let unrelated = make_tx(Hash256([0xbb; 32]), 0);
        o.add(unrelated.clone(), 1, 200).unwrap();

        let children = o.find_children(&parent_txid);
        assert_eq!(children.len(), 3);
        let returned: HashSet<Hash256> = children.iter().map(|e| e.tx.txid()).collect();
        assert!(returned.contains(&a.txid()));
        assert!(returned.contains(&b.txid()));
        assert!(returned.contains(&c.txid()));
        assert!(!returned.contains(&unrelated.txid()));
    }

    #[test]
    fn erase_for_block_drops_included_and_double_spent() {
        let mut o = TxOrphanage::new();
        let parent_txid = Hash256([0xaa; 32]);

        // Orphan A spends parent_txid:0  (will be invalidated by block-spent)
        let a = make_tx(parent_txid, 0);
        // Orphan B spends parent_txid:7  (untouched by the block)
        let b = make_tx(parent_txid, 7);
        // Orphan C is itself included in the block (will be removed)
        let c = make_unique_tx(99);
        o.add(a.clone(), 1, 200).unwrap();
        o.add(b.clone(), 1, 200).unwrap();
        o.add(c.clone(), 1, 200).unwrap();

        let block_txids = vec![c.txid()];
        let spent_outpoints = vec![OutPoint {
            txid: parent_txid,
            vout: 0,
        }];

        let n = o.erase_for_block(&block_txids, &spent_outpoints);
        assert_eq!(n, 2); // A (spent) + C (included); B survives.
        assert!(o.contains(&b.txid()));
        assert!(!o.contains(&a.txid()));
        assert!(!o.contains(&c.txid()));
    }
}
