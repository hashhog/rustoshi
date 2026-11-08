//! State-machine sweep (sm-sweep-rustoshi), path c: reorg and
//! invalidateblock.
//!
//! Child of `server::tests`, so it reuses the synthetic-chain helpers there
//! (`synth_append_with_work`, `synth_persist_side_block`, `mine_synth_block`).
//! Every gap test fails on master by design (the sweep confirms gaps, it does
//! not fix them); they are `#[ignore]`d so CI stays green. Run with
//! `cargo test -p rustoshi-rpc sm_sweep -- --include-ignored`.

use super::*;
use rustoshi_storage::block_store::BlockStatus;
use rustoshi_storage::ChainDb;

/// G -> A1 -> A2 active (tip A2), side branch G -> B1 -> B2 stored, and the
/// arriving block B3 that makes the B branch heavier. Same setup as
/// `try_attach_and_reorg_switches_to_heavier_branch`.
fn reorg_fixture() -> (tempfile::TempDir, Arc<ChainDb>, RpcState, Block, Hash256, Hash256) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut st = RpcState::new(db.clone(), mainnet_params_for_synth_blocks());
    let store = BlockStore::new(&db);
    let (hash_g, _, work_g) = synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA);
    let (hash_a1, _, work_a1) = synth_append_with_work(&store, 1, hash_g, work_g, 0xA1);
    let (hash_a2, _, _) = synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2);
    st.best_hash = hash_a2;
    st.best_height = 2;
    let (hash_b1, _, work_b1) = synth_persist_side_block(&store, 1, hash_g, work_g, 0xB1);
    let (hash_b2, _, _) = synth_persist_side_block(&store, 2, hash_b1, work_b1, 0xB2);
    let b3 = mine_synth_block(3, hash_b2, 0xB3);
    let h3 = b3.block_hash();
    (tmp, db, st, b3, h3, hash_g)
}

/// Control: the fixture reorgs onto B3 (passes on master). Proves the gap
/// tests below reach the reorg commit.
#[test]
fn sm_sweep_control_reorg_fixture_switches_tip() {
    let (_t, _db, mut st, b3, h3, _g) = reorg_fixture();
    assert!(try_attach_and_reorg_detailed(&mut st, &b3, &h3).expect("reorg"));
    assert_eq!((st.best_hash, st.best_height), (h3, 3));
}

/// Gap C-1: a tip change made by the attach-and-reorg path skips the
/// per-tip housekeeping the linear connect does.
///
/// The linear P2P connect (main.rs, after `remove_for_block`) runs
/// `mempool.on_block_connected`, `fee_estimator.process_block`,
/// `orphanage.erase_for_block` and `recently_rejected.clear()` for every
/// block. `try_attach_and_reorg_detailed` (used by the P2P reorg arm in
/// main.rs and by submitblock) and its callers' success arms do none of them.
/// Core resets the recent-rejects filter on every tip change
/// (PeerManagerImpl::ActiveTipChange -> TxDownloadManager::ActiveTipChange)
/// and erases orphans per connected block (BlockConnected). A tx rejected
/// against the old chain (e.g. missing inputs that the new branch creates)
/// stays rejected after the reorg, so it is not re-requested from peers.
#[test]
#[ignore = "sm-sweep-rustoshi gap C-1: fails on master until sm-fix-rustoshi-reorg-tip-housekeeping"]
fn sm_sweep_reorg_clears_recently_rejected() {
    let (_t, _db, mut st, b3, h3, _g) = reorg_fixture();
    st.recently_rejected.insert(Hash256([0x42; 32]));
    assert!(try_attach_and_reorg_detailed(&mut st, &b3, &h3).expect("reorg"));
    assert_eq!(st.best_hash, h3, "control: the tip changed");
    assert!(
        st.recently_rejected.is_empty(),
        "recently_rejected survived a tip change by reorg ({} entries); Core resets it \
         on ActiveTipChange",
        st.recently_rejected.len()
    );
}

/// Gap C-2: every reorg rewrites the height index all the way down to
/// genesis.
///
/// `try_attach_and_reorg_detailed` rewrites CF_HEIGHT_INDEX by walking from
/// the new tip back to height 0 with no stop at the fork point (server.rs,
/// "Update height index for the new branch", loop breaks only at
/// `walk_h == 0`), and the disconnected-block collection first builds a hash
/// set of the whole new chain back to genesis. On mainnet that is ~975k index
/// reads and ~975k height-index writes in one batch, synchronously, under the
/// RpcState write lock and the chain lock, on every reorg. Core only touches
/// entries above the fork (CChain::SetTip, chain.cpp, walks back only while
/// the entry differs).
///
/// Fixture: G -> A1 -> A2 active; B2 -> B3 -> B4 branch off A1 (fork point A1
/// at height 1, first differing height 2). A sentinel planted at height 0,
/// strictly below the fork point, must survive the reorg. A walk that stops
/// at the fork point (Core) never reaches height 0; the walk to genesis
/// overwrites it today.
#[test]
#[ignore = "sm-sweep-rustoshi gap C-2: fails on master until sm-fix-rustoshi-reorg-index-walk"]
fn sm_sweep_reorg_does_not_rewrite_height_index_below_fork() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut st = RpcState::new(db.clone(), mainnet_params_for_synth_blocks());
    let store = BlockStore::new(&db);
    let (hash_g, _, work_g) = synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xAA);
    let (hash_a1, _, work_a1) = synth_append_with_work(&store, 1, hash_g, work_g, 0xA1);
    let (hash_a2, _, _) = synth_append_with_work(&store, 2, hash_a1, work_a1, 0xA2);
    st.best_hash = hash_a2;
    st.best_height = 2;
    let (hash_b2, _, work_b2) = synth_persist_side_block(&store, 2, hash_a1, work_a1, 0xB2);
    let (hash_b3, _, _) = synth_persist_side_block(&store, 3, hash_b2, work_b2, 0xB3);
    let b4 = mine_synth_block(4, hash_b3, 0xB4);
    let h4 = b4.block_hash();
    let sentinel = Hash256([0xEE; 32]);
    store.put_height_index(0, &sentinel).unwrap();
    drop(store);

    assert!(try_attach_and_reorg_detailed(&mut st, &b4, &h4).expect("reorg"));
    let store = BlockStore::new(&db);
    // Controls: the reorg happened and the index moved above the fork.
    assert_eq!((st.best_hash, st.best_height), (h4, 4));
    assert_eq!(store.get_hash_by_height(2).unwrap(), Some(hash_b2));
    assert_eq!(store.get_hash_by_height(4).unwrap(), Some(h4));
    assert_eq!(store.get_hash_by_height(1).unwrap(), Some(hash_a1), "fork point kept");
    assert_eq!(
        store.get_hash_by_height(0).unwrap(),
        Some(sentinel),
        "reorg rewrote the height index below the fork point (walked to genesis)"
    );
}

/// Gap C-3: `invalidateblock` marks the block and its descendants failed and
/// tells the P2P loop BEFORE it disconnects them; when the disconnect fails,
/// the RPC errors out with the ACTIVE tip flagged failed.
///
/// server.rs `invalidate_block`: `mark_block_invalid` (block and every
/// descendant) and `push_event(Invalidated)` run first, `disconnect_to`
/// after. `disconnect_to` fails on missing undo (blocks at or below an
/// assumeutxo base, prune depth, a lost undo record). The error path leaves
/// the marks, so the node's own tip is FAILED_VALIDITY and the P2P loop drops
/// every header whose parent is that tip: it stops following the chain until
/// someone runs reconsiderblock. Core disconnects first and returns before
/// marking anything when DisconnectTip fails (validation.cpp
/// Chainstate::InvalidateBlock).
#[tokio::test]
#[ignore = "sm-sweep-rustoshi gap C-3: fails on master until sm-fix-rustoshi-invalidate-mark-order"]
async fn sm_sweep_invalidate_with_failed_disconnect_leaves_no_marks() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut st = RpcState::new(db.clone(), mainnet_params_for_synth_blocks());
    let store = BlockStore::new(&db);
    let (hash_g, _, work_g) = synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], 0xC1);
    let (hash_a, _, work_a) = synth_append_with_work(&store, 1, hash_g, work_g, 0xC1);
    let (hash_b, _, work_b) = synth_append_with_work(&store, 2, hash_a, work_a, 0xC1);
    let (hash_c, _, _) = synth_append_with_work(&store, 3, hash_b, work_b, 0xC1);
    // The tip's undo record is gone, so the disconnect must fail.
    store.delete_undo(&hash_c).unwrap();
    drop(store);
    st.best_hash = hash_c;
    st.best_height = 3;
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));

    let r = RustoshiRpcServer::invalidate_block(&server, hash_b.to_hex()).await;
    assert!(r.is_err(), "control: invalidateblock must fail when the disconnect fails");
    {
        let s = state.read().await;
        assert_eq!((s.best_hash, s.best_height), (hash_c, 3), "control: tip unchanged");
    }
    let store = BlockStore::new(&db);
    for (name, h) in [("B", hash_b), ("C (active tip)", hash_c)] {
        let st = store.get_block_index(&h).unwrap().unwrap().status;
        assert!(
            !st.has(BlockStatus::FAILED_VALIDITY) && !st.has(BlockStatus::FAILED_CHILD),
            "{name} left marked failed after invalidateblock failed to disconnect it"
        );
    }
}
