//! Recompute `chain_work` from the node's own header chain.
//!
//! Bitcoin Core defines `nChainWork = (pprev ? pprev->nChainWork : 0) +
//! GetBlockProof(*this)` (chain.cpp / validation.cpp `AddToBlockIndex`), so a
//! block's chain work is a pure function of its ancestors' `nBits`. Core always
//! has the full header chain (it refuses `loadtxoutset` until the base header
//! is in its index), so its `chainwork` is exact for every block, including an
//! assumeutxo snapshot base.
//!
//! rustoshi's `--load-snapshot` / `loadtxoutset` activation runs BEFORE the
//! genesis→base headers exist, so it seeds the base entry with
//! `minimum_chain_work` as a placeholder and every later block accumulates on
//! top of that. The historical backfill later downloads the genesis→floor
//! headers and stores exact cumulative work for them, but nothing ever went
//! back to correct the base and its descendants. `getblockheader` hid that by
//! asking a live Bitcoin Core for `chainwork` (removed: R3).
//!
//! [`reconcile_chain_work`] closes the gap: once the header chain from genesis
//! to the snapshot base is complete in the node's own store, it rewrites
//! `chain_work` for every block-index entry above the last exactly-known
//! ancestor, in ascending height order, as parent work + block proof. It also
//! creates index entries for the base-tail header band (headers stored without
//! entries), so those headers get a chain work too. It is idempotent and cheap
//! when there is nothing to fix (one base-entry check plus a walk over the
//! entry-less tail band).
//!
//! It is meant to run at startup, before any chain state is built in memory.

use std::collections::HashMap;

use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_primitives::Hash256;

use crate::block_store::{BlockIndexEntry, BlockStatus, BlockStore};
use crate::db::StorageError;

/// Outcome of [`reconcile_chain_work`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainWorkReconcile {
    /// Every checked entry already carries exact chain work.
    Clean,
    /// The header chain below the snapshot base is not complete yet (the
    /// historical backfill has not reached it), so exact work is unknowable.
    NotReady {
        /// Height of the lowest header reached before the gap.
        gap_above: u32,
    },
    /// Entries were rewritten.
    Reconciled {
        /// Lowest height whose work was recomputed.
        from_height: u32,
        /// Entries whose stored `chain_work` changed.
        rewritten: u64,
        /// Index entries created for headers that had none (tail band).
        created: u64,
        /// Entries skipped because their parent has no index entry.
        orphaned: u64,
    },
}

fn header_only_status() -> BlockStatus {
    let mut s = BlockStatus::new();
    s.set(BlockStatus::VALID_HEADER);
    s.set(BlockStatus::VALID_TREE);
    s
}

/// Reconcile stored `chain_work` with the node's own header chain.
///
/// * If the genesis entry's work is not `GetBlockProof(genesis)` (datadirs
///   written before the genesis-work fix stored 0), every entry is recomputed
///   from genesis.
/// * Otherwise, if `snapshot_base` is given, the base's ancestors are walked
///   down (through headers that have no index entry, i.e. the base-tail band)
///   to the first ancestor that has an index entry; that entry was written by
///   the genesis-anchored historical backfill and is exact. If the base's work
///   differs from `anchor + Σ proofs`, or tail headers lack entries, every
///   entry above the anchor is recomputed.
pub fn reconcile_chain_work(
    store: &BlockStore<'_>,
    snapshot_base: Option<Hash256>,
) -> Result<ChainWorkReconcile, StorageError> {
    let Some(genesis_hash) = store.get_hash_by_height(0)? else {
        return Ok(ChainWorkReconcile::Clean);
    };
    let Some(genesis) = store.get_block_index(&genesis_hash)? else {
        return Ok(ChainWorkReconcile::Clean);
    };
    let genesis_work = get_block_proof(genesis.bits);
    if genesis.chain_work != genesis_work.0 {
        let mut fixed = genesis.clone();
        fixed.chain_work = genesis_work.0;
        store.put_block_index(&genesis_hash, &fixed)?;
        let (rewritten, orphaned) = recompute_above(store, 0)?;
        return Ok(ChainWorkReconcile::Reconciled {
            from_height: 0,
            rewritten: rewritten + 1,
            created: 0,
            orphaned,
        });
    }

    let Some(base_hash) = snapshot_base else {
        return Ok(ChainWorkReconcile::Clean);
    };
    let Some(base) = store.get_block_index(&base_hash)? else {
        return Ok(ChainWorkReconcile::Clean);
    };
    if base.height == 0 {
        return Ok(ChainWorkReconcile::Clean);
    }

    // The base entry's parent link must match its header. A base activated
    // before its header was stored carries prev_hash = ZERO; recompute_above
    // then cannot find its parent, skips it as orphaned, and every descendant
    // inherits the seeded placeholder (mainnet 2026-09-28: headers complete,
    // work exact to 944182, wrong from the base 944183 to the tip).
    // The same activation path defaulted bits/timestamp/nonce/version to 0,
    // and bits = 0 contributes zero proof: after the link repair the tip was
    // still exactly one block's work (the base's) below Core.
    let mut base = base;
    if let Some(h) = store.get_header(&base_hash)? {
        if base.prev_hash != h.prev_block_hash
            || base.bits != h.bits
            || base.timestamp != h.timestamp
            || base.nonce != h.nonce
            || base.version != h.version
        {
            base.prev_hash = h.prev_block_hash;
            base.bits = h.bits;
            base.timestamp = h.timestamp;
            base.nonce = h.nonce;
            base.version = h.version;
            store.put_block_index(&base_hash, &base)?;
        }
    }

    // Walk down from the base's parent through entry-less headers.
    let mut band: Vec<(Hash256, u32, u32)> = Vec::new(); // (hash, height, bits), descending
    let mut cursor = base.prev_hash;
    let mut height = base.height - 1;
    let anchor = loop {
        if let Some(e) = store.get_block_index(&cursor)? {
            break e;
        }
        let Some(hdr) = store.get_header(&cursor)? else {
            return Ok(ChainWorkReconcile::NotReady { gap_above: height });
        };
        band.push((cursor, height, hdr.bits));
        if height == 0 {
            // Reached height 0 without an entry: genesis is always indexed,
            // so this is not the chain we think it is.
            return Ok(ChainWorkReconcile::NotReady { gap_above: 0 });
        }
        cursor = hdr.prev_block_hash;
        height -= 1;
    };
    if anchor.height != height {
        // The ancestor's recorded height disagrees with its position below
        // the base: an inconsistent index. Do not rewrite anything.
        tracing::warn!(
            "chain-work reconcile: ancestor {} of snapshot base at walk height {} \
             has index height {}; leaving chain work unchanged",
            cursor,
            height,
            anchor.height
        );
        return Ok(ChainWorkReconcile::Clean);
    }

    let mut expected = ChainWork(anchor.chain_work);
    for (_, _, bits) in band.iter().rev() {
        expected = expected.saturating_add(&get_block_proof(*bits));
    }
    expected = expected.saturating_add(&get_block_proof(base.bits));
    if band.is_empty() && expected.0 == base.chain_work {
        return Ok(ChainWorkReconcile::Clean);
    }

    // Create index entries for the entry-less tail band (headers only).
    let mut created = 0u64;
    for (hash, h, _) in band.iter().rev() {
        let hdr = store
            .get_header(hash)?
            .expect("band header was read above");
        store.put_block_index(
            hash,
            &BlockIndexEntry {
                height: *h,
                status: header_only_status(),
                n_tx: 0,
                timestamp: hdr.timestamp,
                bits: hdr.bits,
                nonce: hdr.nonce,
                version: hdr.version,
                prev_hash: hdr.prev_block_hash,
                // Filled by recompute_above.
                chain_work: [0u8; 32],
            },
        )?;
        created += 1;
    }

    let (rewritten, orphaned) = recompute_above(store, anchor.height)?;
    Ok(ChainWorkReconcile::Reconciled {
        from_height: anchor.height + 1,
        rewritten,
        created,
        orphaned,
    })
}

/// Recompute `chain_work` for every index entry with height > `floor`, in
/// ascending height order (a parent always has a lower height, so it is fixed
/// before its children). Entries at `floor` and below are trusted as-is.
/// Returns (rewritten, orphaned).
fn recompute_above(store: &BlockStore<'_>, floor: u32) -> Result<(u64, u64), StorageError> {
    let mut above: Vec<(u32, Hash256, BlockIndexEntry)> = store
        .iter_block_index()?
        .filter(|(_, e)| e.height > floor)
        .map(|(h, e)| (e.height, h, e))
        .collect();
    above.sort_by_key(|(height, _, _)| *height);

    // Work already settled in this pass, keyed by hash.
    let mut settled: HashMap<Hash256, [u8; 32]> = HashMap::with_capacity(above.len());
    let mut rewritten = 0u64;
    let mut orphaned = 0u64;
    for (_, hash, mut entry) in above {
        let mut parent_work = match settled.get(&entry.prev_hash) {
            Some(w) => Some(*w),
            None => store.get_block_index(&entry.prev_hash)?.map(|p| p.chain_work),
        };
        if parent_work.is_none() {
            // A stale/zero parent link in the index: trust the stored header.
            if let Some(hdr) = store.get_header(&hash)? {
                if hdr.prev_block_hash != entry.prev_hash {
                    let pw = match settled.get(&hdr.prev_block_hash) {
                        Some(w) => Some(*w),
                        None => store
                            .get_block_index(&hdr.prev_block_hash)?
                            .map(|p| p.chain_work),
                    };
                    if pw.is_some() {
                        entry.prev_hash = hdr.prev_block_hash;
                        parent_work = pw;
                    }
                }
            }
        }
        let Some(parent_work) = parent_work else {
            orphaned += 1;
            continue;
        };
        let work = ChainWork(parent_work).saturating_add(&get_block_proof(entry.bits));
        let stored = store.get_block_index(&hash)?;
        let link_repaired = stored.as_ref().is_some_and(|e| e.prev_hash != entry.prev_hash);
        if entry.chain_work != work.0 || link_repaired {
            entry.chain_work = work.0;
            store.put_block_index(&hash, &entry)?;
            rewritten += 1;
        }
        settled.insert(hash, work.0);
    }
    Ok((rewritten, orphaned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ChainDb;
    use rustoshi_consensus::params::ChainParams;
    use rustoshi_primitives::BlockHeader;
    use tempfile::TempDir;

    fn temp_db() -> (TempDir, ChainDb) {
        let dir = TempDir::new().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        (dir, db)
    }

    /// Unmined, linked headers above genesis with varying nBits so every
    /// height contributes a different proof.
    fn headers(genesis: Hash256, n: u32) -> Vec<BlockHeader> {
        let mut prev = genesis;
        let bits_cycle = [0x207f_ffffu32, 0x1d00_ffff, 0x1b04_864c, 0x1a0f_fff0];
        (1..=n)
            .map(|h| {
                let hdr = BlockHeader {
                    version: 1,
                    prev_block_hash: prev,
                    merkle_root: Hash256::ZERO,
                    timestamp: 1_600_000_000 + h,
                    bits: bits_cycle[(h as usize) % bits_cycle.len()],
                    nonce: h,
                };
                prev = hdr.block_hash();
                hdr
            })
            .collect()
    }

    fn put_entry(store: &BlockStore<'_>, h: u32, hdr: &BlockHeader, work: [u8; 32]) {
        let hash = hdr.block_hash();
        store.put_header(&hash, hdr).unwrap();
        store.put_height_index(h, &hash).unwrap();
        store
            .put_block_index(
                &hash,
                &BlockIndexEntry {
                    height: h,
                    status: header_only_status(),
                    n_tx: 0,
                    timestamp: hdr.timestamp,
                    bits: hdr.bits,
                    nonce: hdr.nonce,
                    version: hdr.version,
                    prev_hash: hdr.prev_block_hash,
                    chain_work: work,
                },
            )
            .unwrap();
    }

    /// Core's definition, computed independently of the code under test.
    fn core_work(params: &ChainParams, hdrs: &[BlockHeader], height: u32) -> [u8; 32] {
        let mut w = get_block_proof(params.genesis_block.header.bits);
        for hdr in &hdrs[..height as usize] {
            w = w.saturating_add(&get_block_proof(hdr.bits));
        }
        w.0
    }

    /// Lay out a snapshot-activated store: exact backfilled work for
    /// 1..floor-1, an entry-less tail band floor..base-1, the base seeded with
    /// `minimum_chain_work` (as main.rs does) and forward blocks base+1..=tip
    /// accumulating on that placeholder.
    fn snapshot_layout(
        store: &BlockStore<'_>,
        params: &ChainParams,
        hdrs: &[BlockHeader],
        floor: u32,
        base: u32,
        tip: u32,
        backfilled: bool,
    ) {
        store.init_genesis(params).unwrap();
        if backfilled {
            for h in 1..floor {
                put_entry(store, h, &hdrs[h as usize - 1], core_work(params, hdrs, h));
            }
        }
        for h in floor..base {
            let hdr = &hdrs[h as usize - 1];
            store.put_header(&hdr.block_hash(), hdr).unwrap();
            store.put_height_index(h, &hdr.block_hash()).unwrap();
        }
        let mut w = ChainWork(params.minimum_chain_work);
        put_entry(store, base, &hdrs[base as usize - 1], w.0);
        for h in base + 1..=tip {
            let hdr = &hdrs[h as usize - 1];
            w = w.saturating_add(&get_block_proof(hdr.bits));
            put_entry(store, h, hdr, w.0);
        }
    }

    #[test]
    fn snapshot_chain_work_reconciled_to_core_definition() {
        let (_d, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        let hdrs = headers(params.genesis_hash, 60);
        let (floor, base, tip) = (20u32, 40u32, 60u32);
        snapshot_layout(&store, &params, &hdrs, floor, base, tip, true);
        let base_hash = hdrs[base as usize - 1].block_hash();

        // Precondition: the placeholder really is wrong (else this test
        // would pass without the reconcile doing anything).
        let before = store.get_block_index(&base_hash).unwrap().unwrap();
        assert_ne!(before.chain_work, core_work(&params, &hdrs, base));

        let out = reconcile_chain_work(&store, Some(base_hash)).unwrap();
        match out {
            ChainWorkReconcile::Reconciled { from_height, created, orphaned, .. } => {
                assert_eq!(from_height, floor);
                assert_eq!(created, (base - floor) as u64);
                assert_eq!(orphaned, 0);
            }
            other => panic!("expected Reconciled, got {other:?}"),
        }
        for h in 1..=tip {
            let hash = hdrs[h as usize - 1].block_hash();
            let e = store.get_block_index(&hash).unwrap().unwrap();
            assert_eq!(e.chain_work, core_work(&params, &hdrs, h), "height {h}");
            assert_eq!(e.height, h);
        }
        // Idempotent.
        assert_eq!(
            reconcile_chain_work(&store, Some(base_hash)).unwrap(),
            ChainWorkReconcile::Clean
        );
    }

    /// Mainnet 2026-09-28: the snapshot base entry carried prev_hash = ZERO
    /// (activated before its header was stored). The reconcile fixed the tail
    /// band but skipped the base as orphaned, so base..tip kept the seeded
    /// placeholder. The base link must be repaired from its header.
    #[test]
    fn snapshot_base_with_zero_prev_link_is_reconciled_to_tip() {
        let (_d, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        let hdrs = headers(params.genesis_hash, 60);
        let (floor, base, tip) = (20u32, 40u32, 60u32);
        snapshot_layout(&store, &params, &hdrs, floor, base, tip, true);
        let base_hash = hdrs[base as usize - 1].block_hash();
        let mut b = store.get_block_index(&base_hash).unwrap().unwrap();
        b.prev_hash = Hash256::ZERO;
        b.bits = 0;
        b.timestamp = 0;
        b.nonce = 0;
        b.version = 0;
        store.put_block_index(&base_hash, &b).unwrap();

        let out = reconcile_chain_work(&store, Some(base_hash)).unwrap();
        match out {
            ChainWorkReconcile::Reconciled { orphaned, .. } => assert_eq!(orphaned, 0),
            other => panic!("expected Reconciled, got {other:?}"),
        }
        for h in 1..=tip {
            let hash = hdrs[h as usize - 1].block_hash();
            let e = store.get_block_index(&hash).unwrap().unwrap();
            assert_eq!(e.chain_work, core_work(&params, &hdrs, h), "height {h}");
        }
        let b = store.get_block_index(&base_hash).unwrap().unwrap();
        assert_eq!(b.prev_hash, hdrs[base as usize - 2].block_hash());
        assert_eq!(b.bits, hdrs[base as usize - 1].bits);
        assert_eq!(
            reconcile_chain_work(&store, Some(base_hash)).unwrap(),
            ChainWorkReconcile::Clean
        );
    }

    #[test]
    fn snapshot_chain_work_not_ready_until_headers_complete() {
        let (_d, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        let hdrs = headers(params.genesis_hash, 60);
        snapshot_layout(&store, &params, &hdrs, 20, 40, 60, false);
        let base_hash = hdrs[39].block_hash();
        let before = store.get_block_index(&base_hash).unwrap().unwrap();
        assert_eq!(
            reconcile_chain_work(&store, Some(base_hash)).unwrap(),
            ChainWorkReconcile::NotReady { gap_above: 19 }
        );
        // Nothing rewritten.
        assert_eq!(store.get_block_index(&base_hash).unwrap().unwrap().chain_work, before.chain_work);
    }

    #[test]
    fn side_branch_above_base_reconciled_from_its_parent() {
        let (_d, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        let hdrs = headers(params.genesis_hash, 50);
        snapshot_layout(&store, &params, &hdrs, 10, 30, 50, true);
        // A stale sibling of height 45 whose parent is 44, work derived from
        // the placeholder like everything else above the base.
        let parent = store.get_block_index(&hdrs[43].block_hash()).unwrap().unwrap();
        let sib = BlockHeader { nonce: 999_999, ..hdrs[44].clone() };
        let sib_hash = sib.block_hash();
        store.put_header(&sib_hash, &sib).unwrap();
        let wrong = ChainWork(parent.chain_work).saturating_add(&get_block_proof(sib.bits));
        store
            .put_block_index(
                &sib_hash,
                &BlockIndexEntry {
                    height: 45,
                    status: header_only_status(),
                    n_tx: 0,
                    timestamp: sib.timestamp,
                    bits: sib.bits,
                    nonce: sib.nonce,
                    version: sib.version,
                    prev_hash: sib.prev_block_hash,
                    chain_work: wrong.0,
                },
            )
            .unwrap();
        reconcile_chain_work(&store, Some(hdrs[29].block_hash())).unwrap();
        let got = store.get_block_index(&sib_hash).unwrap().unwrap().chain_work;
        assert_eq!(got, core_work(&params, &hdrs, 45), "sibling has same bits as 45");
    }

    #[test]
    fn genesis_zero_work_recomputed_from_genesis() {
        let (_d, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        store.init_genesis(&params).unwrap();
        let hdrs = headers(params.genesis_hash, 10);
        // Old-datadir layout: genesis stored with 0 work, descendants off by
        // exactly one genesis proof.
        let mut g = store.get_block_index(&params.genesis_hash).unwrap().unwrap();
        g.chain_work = [0u8; 32];
        store.put_block_index(&params.genesis_hash, &g).unwrap();
        let mut w = ChainWork([0u8; 32]);
        for h in 1..=10u32 {
            let hdr = &hdrs[h as usize - 1];
            w = w.saturating_add(&get_block_proof(hdr.bits));
            put_entry(&store, h, hdr, w.0);
        }
        let out = reconcile_chain_work(&store, None).unwrap();
        assert!(matches!(out, ChainWorkReconcile::Reconciled { from_height: 0, .. }), "{out:?}");
        for h in 1..=10u32 {
            let e = store.get_block_index(&hdrs[h as usize - 1].block_hash()).unwrap().unwrap();
            assert_eq!(e.chain_work, core_work(&params, &hdrs, h), "height {h}");
        }
    }

    #[test]
    fn clean_store_is_untouched() {
        let (_d, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        store.init_genesis(&params).unwrap();
        let hdrs = headers(params.genesis_hash, 10);
        for h in 1..=10u32 {
            put_entry(&store, h, &hdrs[h as usize - 1], core_work(&params, &hdrs, h));
        }
        assert_eq!(reconcile_chain_work(&store, None).unwrap(), ChainWorkReconcile::Clean);
        assert_eq!(
            reconcile_chain_work(&store, Some(hdrs[5].block_hash())).unwrap(),
            ChainWorkReconcile::Clean
        );
    }
}
