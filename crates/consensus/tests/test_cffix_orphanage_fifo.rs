//! cffix-rustoshi-orphanage-fifo-compaction.
//!
//! `TxOrphanage::add` pushes every wtxid onto its eviction FIFO, but
//! `erase`, `erase_for_peer` and `expire_orphans` never remove FIFO
//! entries; the only pop was in `evict_oldest`, which runs only at the
//! 100-orphan cap. A peer that keeps the live count under the cap (add 50,
//! disconnect, repeat) therefore grew the FIFO without bound, 32 bytes per
//! orphan ever added. Core keeps every index in step on each erase
//! (`TxOrphanageImpl::EraseTxInternal` / `EraseForPeer`,
//! bitcoin-core/src/node/txorphanage.cpp), so `LimitOrphans` never sees
//! stale entries.
//!
//! The FIFO length is read through `TxOrphanage::fifo_len` where it exists.
//! On a tree without that accessor, method resolution falls through to the
//! `FifoLenFallback` trait below, which counts the FIFO from the derived
//! `Debug` output, so the test compiles everywhere and fails on the
//! assertion rather than on compilation. (Inherent methods take precedence
//! over trait methods, so the accessor wins wherever it is defined.)

use std::sync::Arc;

use rustoshi_consensus::orphanage::{TxOrphanage, MAX_ORPHAN_TRANSACTIONS};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};

#[allow(dead_code)]
trait FifoLenFallback {
    fn fifo_len(&self) -> usize;
}

impl FifoLenFallback for TxOrphanage {
    fn fifo_len(&self) -> usize {
        let dbg = format!("{:?}", self);
        let start = dbg
            .find("fifo: [")
            .expect("TxOrphanage Debug has a fifo field")
            + 7;
        let end = start + dbg[start..].find(']').expect("fifo list is closed");
        dbg[start..end].matches("Hash256(").count()
    }
}

fn make_tx(seed: u32) -> Arc<Transaction> {
    Arc::new(Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xaa; 32]),
                vout: seed,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![0x6a, 0x00],
        }],
        lock_time: 0,
    })
}

#[test]
fn fifo_len_bounded_by_live_orphans() {
    let mut o = TxOrphanage::new();
    let mut seed = 0u32;
    for round in 0..1000u64 {
        for _ in 0..50 {
            o.add(make_tx(seed), round, 100)
                .expect("add under the caps");
            seed += 1;
        }
        assert_eq!(o.erase_for_peer(round), 50);
        assert!(o.is_empty());
    }
    let n = o.fifo_len();
    assert!(
        n <= 2 * MAX_ORPHAN_TRANSACTIONS + 1,
        "fifo holds {n} entries with 0 live orphans after 50,000 adds; \
         must stay <= 2*MAX_ORPHAN_TRANSACTIONS+1"
    );
}

/// Same churn through single-entry `erase`, and the FIFO order must still
/// drive eviction correctly afterwards: the oldest live orphan is the one
/// evicted at the cap.
#[test]
fn fifo_bounded_under_erase_and_eviction_order_kept() {
    let mut o = TxOrphanage::new();
    let mut seed = 0u32;
    for _ in 0..1000 {
        let tx = make_tx(seed);
        seed += 1;
        let w = tx.wtxid();
        o.add(tx, 1, 100).unwrap();
        assert!(o.erase(&w).is_some());
    }
    assert!(o.fifo_len() <= 2 * MAX_ORPHAN_TRANSACTIONS + 1);

    // Fill to the cap from several peers, then one more add must evict the
    // oldest live entry, not a newer one.
    let mut wtxids = Vec::new();
    for i in 0..MAX_ORPHAN_TRANSACTIONS {
        let tx = make_tx(seed);
        seed += 1;
        wtxids.push(tx.wtxid());
        o.add(tx, 10 + (i as u64 % 4), 100).unwrap();
    }
    let extra = make_tx(seed);
    let extra_w = extra.wtxid();
    o.add(extra, 99, 100).unwrap();
    assert_eq!(o.len(), MAX_ORPHAN_TRANSACTIONS);
    assert!(!o.contains(&wtxids[0]), "oldest live orphan evicted");
    assert!(o.contains(&wtxids[1]));
    assert!(o.contains(&extra_w));
    assert!(o.fifo_len() <= 2 * MAX_ORPHAN_TRANSACTIONS + 1);
}

/// The same transaction added, erased and added again leaves a stale FIFO
/// entry under a wtxid that is live again. Those duplicates must not
/// survive compaction (or the FIFO still grows without bound), and a stale
/// duplicate must not make `evict_oldest` evict the re-added orphan ahead
/// of orphans that are older than its re-add.
#[test]
fn fifo_bounded_when_same_tx_is_readded() {
    let mut o = TxOrphanage::new();
    let a = make_tx(7);
    let a_w = a.wtxid();
    for _ in 0..1000 {
        o.add(a.clone(), 1, 100).unwrap();
        assert_eq!(o.erase_for_peer(1), 1);
    }
    o.add(a.clone(), 1, 100).unwrap();
    assert!(o.fifo_len() <= 2 * MAX_ORPHAN_TRANSACTIONS + 1);

    // `a` is now the oldest live orphan. Erase it, add 99 others, re-add
    // `a` (newest), then overflow by one: the oldest of the 99 goes, `a`
    // stays.
    assert!(o.erase(&a_w).is_some());
    let mut others = Vec::new();
    for i in 0..MAX_ORPHAN_TRANSACTIONS - 1 {
        let tx = make_tx(1000 + i as u32);
        others.push(tx.wtxid());
        o.add(tx, 2 + (i as u64 % 4), 100).unwrap();
    }
    o.add(a, 1, 100).unwrap();
    assert_eq!(o.len(), MAX_ORPHAN_TRANSACTIONS);
    o.add(make_tx(5000), 9, 100).unwrap();
    assert!(
        o.contains(&a_w),
        "re-added orphan is the newest; must not be evicted"
    );
    assert!(!o.contains(&others[0]), "oldest live orphan evicted");
}
