//! sm-fix-rustoshi-reorg-index-walk: the reorg height-index rewrite and the
//! disconnected-block collection stop at the fork point (Core
//! `CChain::SetTip`, `LastCommonAncestor`) instead of walking to genesis.
//!
//! The height index feeds BIP-68 lookups and every height->hash RPC, so these
//! tests pin that stopping early never leaves a wrong row: deep forks
//! (disconnect 5, fork at genesis), a fork well above genesis with a longer
//! new branch, and a stale row above the old tip that already names a
//! new-branch block (a match there must not stop the walk).

use super::*;
use rustoshi_storage::ChainDb;

/// Active chain G -> A1..A{old_len}; side chain off the block at
/// `fork_h` with `new_len - fork_h - 1` stored side blocks; returns the
/// arriving tip block of height `new_len`. Coinbase txids of the active
/// chain are written to the tx index so the disconnect side is observable.
struct Fork {
    _tmp: tempfile::TempDir,
    db: Arc<ChainDb>,
    st: RpcState,
    active: Vec<(Hash256, Hash256)>, // (block hash, coinbase txid) by height
    side: Vec<(u32, Hash256, Hash256)>, // (height, block hash, coinbase txid)
    tip_block: Block,
    tip_hash: Hash256,
}

fn build_fork(old_tip_h: u32, fork_h: u32, new_tip_h: u32) -> Fork {
    use rustoshi_storage::block_store::TxIndexEntry;
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut st = RpcState::new(db.clone(), mainnet_params_for_synth_blocks());
    st.txindex_enabled = true;
    let store = BlockStore::new(&db);
    let mut active = Vec::new();
    let mut works = Vec::new();
    let mut prev = Hash256::ZERO;
    let mut work = [0u8; 32];
    for h in 0..=old_tip_h {
        let (hash, block, w) =
            synth_append_with_work(&store, h, prev, work, 0xA0u8.wrapping_add(h as u8));
        let txid = block.transactions[0].txid();
        store
            .put_tx_index(
                &txid,
                &TxIndexEntry {
                    block_hash: hash,
                    tx_offset: 0,
                    tx_length: 0,
                },
            )
            .unwrap();
        active.push((hash, txid));
        works.push(w);
        prev = hash;
        work = w;
    }
    st.best_hash = prev;
    st.best_height = old_tip_h;
    let mut side = Vec::new();
    let mut prev = active[fork_h as usize].0;
    let mut work = works[fork_h as usize];
    for h in fork_h + 1..new_tip_h {
        let (hash, block, w) =
            synth_persist_side_block(&store, h, prev, work, 0x50u8.wrapping_add(h as u8));
        side.push((h, hash, block.transactions[0].txid()));
        prev = hash;
        work = w;
    }
    let tip_block = mine_synth_block(new_tip_h, prev, 0x50u8.wrapping_add(new_tip_h as u8));
    let tip_hash = tip_block.block_hash();
    side.push((new_tip_h, tip_hash, tip_block.transactions[0].txid()));
    drop(store);
    Fork {
        _tmp: tmp,
        db,
        st,
        active,
        side,
        tip_block,
        tip_hash,
    }
}

/// Every height 0..=new tip names the new active chain, nothing remains
/// above it, disconnected coinbases left the tx index, connected ones are in.
fn assert_index_is_new_chain(f: &Fork, fork_h: u32, old_tip_h: u32) {
    let store = BlockStore::new(&f.db);
    for h in 0..=fork_h {
        assert_eq!(
            store.get_hash_by_height(h).unwrap(),
            Some(f.active[h as usize].0),
            "height {h} (at/below fork) must still name the shared ancestor"
        );
    }
    for (h, hash, txid) in &f.side {
        assert_eq!(
            store.get_hash_by_height(*h).unwrap(),
            Some(*hash),
            "height {h} must name the new branch"
        );
        assert_eq!(
            store.get_tx_index(txid).unwrap().map(|e| e.block_hash),
            Some(*hash),
            "connected coinbase at height {h} must be in the tx index"
        );
    }
    let new_tip_h = f.side.last().unwrap().0;
    for h in new_tip_h + 1..=old_tip_h.max(new_tip_h) {
        assert_eq!(
            store.get_hash_by_height(h).unwrap(),
            None,
            "height {h} above the new tip must be gone"
        );
    }
    for h in fork_h + 1..=old_tip_h {
        assert!(
            store.get_tx_index(&f.active[h as usize].1).unwrap().is_none(),
            "disconnected coinbase at height {h} must leave the tx index (disconnect set found the fork)"
        );
    }
    for h in 0..=fork_h {
        assert!(
            store
                .get_tx_index(&f.active[h as usize].1)
                .unwrap()
                .is_some(),
            "shared coinbase at height {h} must stay in the tx index"
        );
    }
    assert_eq!(store.get_best_block_hash().unwrap(), Some(f.tip_hash));
    assert_eq!(store.get_best_height().unwrap(), Some(new_tip_h));
}

/// Deep fork at genesis: disconnect A1..A5, connect B1..B6.
#[test]
fn reorg_index_walk_deep_fork_at_genesis() {
    let mut f = build_fork(5, 0, 6);
    let (b, h) = (f.tip_block.clone(), f.tip_hash);
    assert!(try_attach_and_reorg_detailed(&mut f.st, &b, &h).expect("reorg"));
    assert_eq!((f.st.best_hash, f.st.best_height), (h, 6));
    assert_index_is_new_chain(&f, 0, 5);
}

/// Fork well above genesis, new branch much longer than the old suffix:
/// G..A8 active, fork at A3, B4..B12 connect. Rows 0..3 are untouched (a
/// sentinel-free check: they still equal the shared ancestors).
#[test]
fn reorg_index_walk_mid_fork_longer_branch() {
    let mut f = build_fork(8, 3, 12);
    let (b, h) = (f.tip_block.clone(), f.tip_hash);
    assert!(try_attach_and_reorg_detailed(&mut f.st, &b, &h).expect("reorg"));
    assert_eq!((f.st.best_hash, f.st.best_height), (h, 12));
    assert_index_is_new_chain(&f, 3, 8);
}

/// A stale row above the old tip that already names a new-branch block
/// (e.g. left by an earlier invalidateblock) must not stop the walk: the
/// rows between the fork and that height still need rewriting.
#[test]
fn reorg_index_walk_ignores_matching_stale_row_above_old_tip() {
    let mut f = build_fork(2, 0, 4);
    let (h3, b3hash) = (f.side[2].0, f.side[2].1);
    assert_eq!(h3, 3);
    BlockStore::new(&f.db).put_height_index(3, &b3hash).unwrap();
    let (b, h) = (f.tip_block.clone(), f.tip_hash);
    assert!(try_attach_and_reorg_detailed(&mut f.st, &b, &h).expect("reorg"));
    assert_eq!((f.st.best_hash, f.st.best_height), (h, 4));
    assert_index_is_new_chain(&f, 0, 2);
}
