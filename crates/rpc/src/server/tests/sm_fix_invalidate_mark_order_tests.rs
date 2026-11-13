//! sm-fix-rustoshi-invalidate-mark-order: invalidateblock disconnects first
//! and marks blocks failed only once the disconnect has succeeded, as in
//! Core's `Chainstate::InvalidateBlock` (validation.cpp), which returns
//! before marking anything when `DisconnectTip` fails.
//!
//! The pinned sweep test `sm_sweep_invalidate_with_failed_disconnect_leaves_no_marks`
//! (sm_sweep_reorg_tests.rs) covers the block-index marks on the failure
//! path. The tests here cover the rest of the contract:
//!   * the failure path tells the P2P connect loop nothing (no `Invalidated`
//!     event), so it keeps following headers that build on the live tip;
//!   * the success path still marks the block and its descendants and still
//!     sends the event (the reorder must not lose the marks);
//!   * the marks still land before best-chain selection runs, so the
//!     invalidated branch cannot be picked straight back up;
//!   * a block off the active chain is still marked with no disconnect.

use super::*;
use crate::chain_lock::ChainEvent;
use rustoshi_storage::block_store::BlockStatus;
use rustoshi_storage::ChainDb;

fn failed(db: &Arc<ChainDb>, h: &Hash256) -> bool {
    let st = BlockStore::new(db).get_block_index(h).unwrap().unwrap().status;
    st.has(BlockStatus::FAILED_VALIDITY) || st.has(BlockStatus::FAILED_CHILD)
}

/// Every hash the RPC reported to the connect loop as invalidated.
fn invalidated_events(events: Option<Vec<ChainEvent>>) -> Vec<Hash256> {
    let mut out = Vec::new();
    for ev in events.unwrap_or_default() {
        if let ChainEvent::Invalidated(v) = ev {
            out.extend(v);
        }
    }
    out
}

/// G -> A -> B -> C active (tip C).
fn active_chain(marker: u8) -> (tempfile::TempDir, Arc<ChainDb>, RpcState, [Hash256; 4]) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut st = RpcState::new(db.clone(), mainnet_params_for_synth_blocks());
    let store = BlockStore::new(&db);
    let (hash_g, _, work_g) = synth_append_with_work(&store, 0, Hash256::ZERO, [0u8; 32], marker);
    let (hash_a, _, work_a) = synth_append_with_work(&store, 1, hash_g, work_g, marker);
    let (hash_b, _, work_b) = synth_append_with_work(&store, 2, hash_a, work_a, marker);
    let (hash_c, _, _) = synth_append_with_work(&store, 3, hash_b, work_b, marker);
    drop(store);
    st.best_hash = hash_c;
    st.best_height = 3;
    (tmp, db, st, [hash_g, hash_a, hash_b, hash_c])
}

/// Failure path: the disconnect of C fails (its undo record is gone). The
/// connect loop must not be told B and C are invalid, or it drops every
/// header building on the tip it is still on.
#[tokio::test]
async fn sm_fix_invalidate_failed_disconnect_sends_no_invalidated_event() {
    let (_t, db, st, [_g, _a, hash_b, hash_c]) = active_chain(0xD1);
    BlockStore::new(&db).delete_undo(&hash_c).unwrap();
    let cl = st.chain_lock.clone();
    let mut seen = cl.epoch();
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));

    let r = RustoshiRpcServer::invalidate_block(&server, hash_b.to_hex()).await;
    assert!(r.is_err(), "control: invalidateblock must fail when the disconnect fails");
    let inv = invalidated_events(cl.take_changes(&mut seen));
    assert!(
        inv.is_empty(),
        "invalidateblock failed to disconnect but told the connect loop {} blocks are invalid",
        inv.len()
    );
    let s = state.read().await;
    assert_eq!((s.best_hash, s.best_height), (hash_c, 3), "control: tip unchanged");
}

/// Success path: B and C are disconnected, then marked, and the connect loop
/// is told about both. Guards against the reorder dropping the marks.
#[tokio::test]
async fn sm_fix_invalidate_success_still_marks_block_and_descendants() {
    let (_t, db, st, [_g, hash_a, hash_b, hash_c]) = active_chain(0xD2);
    let cl = st.chain_lock.clone();
    let mut seen = cl.epoch();
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));

    RustoshiRpcServer::invalidate_block(&server, hash_b.to_hex())
        .await
        .expect("invalidateblock");
    {
        let s = state.read().await;
        assert_eq!((s.best_hash, s.best_height), (hash_a, 1), "rolled back to A");
    }
    assert!(failed(&db, &hash_b), "B not marked failed");
    assert!(failed(&db, &hash_c), "descendant C not marked failed");
    assert!(!failed(&db, &hash_a), "parent A must stay valid");
    let inv = invalidated_events(cl.take_changes(&mut seen));
    assert!(inv.contains(&hash_b) && inv.contains(&hash_c), "connect loop not told: {inv:?}");
}

/// The marks must still land before best-chain selection: G -> A -> B -> C
/// active, plus a stored side block B' on A with less work than C. After
/// invalidating B the tip must move to B', not back onto C. If the marks
/// were applied after `activate_best_chain`, C (most work, data present)
/// would be reconnected and an invalidated block would be active again.
#[tokio::test]
async fn sm_fix_invalidate_marks_before_best_chain_selection() {
    let (_t, db, st, [_g, hash_a, hash_b, hash_c]) = active_chain(0xD3);
    let store = BlockStore::new(&db);
    let work_a = store.get_block_index(&hash_a).unwrap().unwrap().chain_work;
    let (hash_b2, _, _) = synth_persist_side_block(&store, 2, hash_a, work_a, 0xE3);
    drop(store);
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));

    RustoshiRpcServer::invalidate_block(&server, hash_b.to_hex())
        .await
        .expect("invalidateblock");
    let s = state.read().await;
    assert_ne!(s.best_hash, hash_c, "invalidated branch reconnected");
    assert_ne!(s.best_hash, hash_b, "invalidated block reconnected");
    assert_eq!((s.best_hash, s.best_height), (hash_b2, 2), "tip must move to the side block B'");
    assert!(failed(&db, &hash_b) && failed(&db, &hash_c));
}

/// A block off the active chain needs no disconnect and is still marked;
/// the active tip is untouched.
#[tokio::test]
async fn sm_fix_invalidate_off_chain_block_marked_without_disconnect() {
    let (_t, db, st, [_g, hash_a, _b, hash_c]) = active_chain(0xD4);
    let store = BlockStore::new(&db);
    let work_a = store.get_block_index(&hash_a).unwrap().unwrap().chain_work;
    let (hash_b2, _, _) = synth_persist_side_block(&store, 2, hash_a, work_a, 0xE4);
    drop(store);
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));

    RustoshiRpcServer::invalidate_block(&server, hash_b2.to_hex())
        .await
        .expect("invalidateblock");
    let s = state.read().await;
    assert_eq!((s.best_hash, s.best_height), (hash_c, 3), "active tip untouched");
    assert!(failed(&db, &hash_b2), "side block not marked failed");
    assert!(!failed(&db, &hash_c), "active tip must stay valid");
}
