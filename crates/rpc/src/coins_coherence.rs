//! F0: every coin reader outside the connect loop sees the chain's coins.
//!
//! # The hazard
//!
//! The P2P connect loop (`rustoshi/src/main.rs`) owns the node's one
//! long-lived coin view, a write-back [`BlockStoreUtxoView`] over RocksDB. It
//! flushes on a coarse schedule (cache CRITICAL/LARGE, every 2000 blocks,
//! every 60 min, or when the connected block is the announced header tip), and
//! it publishes `RpcState::best_hash/best_height` after EVERY block. Between
//! flushes, the spends of the connected blocks exist only in that cache.
//!
//! The RPC handlers hold only `Arc<ChainDb>` and read `CF_UTXO` directly
//! (`gettxout`, mempool admission for `sendrawtransaction` /
//! `testmempoolaccept` / `submitpackage` / wallet broadcast, REST
//! `getutxos`), and `submitblock` / `generate*` / `invalidateblock` /
//! `reconsiderblock` / `preciousblock` build a FRESH `store.utxo_view()` over
//! that same disk set. A coin spent by an unflushed block therefore reads as
//! UNSPENT there, under a tip that already includes the spend:
//!
//!   * `submitblock` CONNECTED a block re-spending it (consensus);
//!   * the mempool admitted a tx re-spending it (and `getblocktemplate` would
//!     then build an invalid block);
//!   * `gettxout` reported it unspent.
//!
//! # Core
//!
//! Core has one coin view: `CoinsTip()` (`coins.cpp` `FetchCoin` 63-82,
//! `SpendCoin` 142-171 — a spend stays a DIRTY spent entry until
//! `BatchWrite` reaches the parent). Block connection (`ConnectTip` /
//! `ConnectBlock`), mempool admission (`CCoinsViewMemPool` over `CoinsTip()`),
//! `gettxout` and `submitblock` all run under `cs_main`, so no reader can
//! observe the chain tip without the spends that produced it.
//!
//! # The rule here
//!
//! rustoshi cannot hand the connect loop's `&mut` view to another task. It
//! gets the same guarantee from the coins DB's own best-block pointer, which
//! is written in the same atomic batch as the coins (`flush_with_tip*`):
//!
//! > A coin read that bypasses the connect loop's view happens only while the
//! > `RpcState` lock is held AND the coins DB's best block equals
//! > `RpcState::best_hash`.
//!
//! The connect loop publishes `best_hash` under that same lock, so while the
//! lock is held the published tip cannot move; if the coins DB names the same
//! block, every spend of every block up to that tip is on disk. When the two
//! disagree, the reader asks the connect loop for a flush (the existing
//! [`ChainstateFlushSignal`] handshake that `gettxoutsetinfo` and
//! `dumptxoutset` already use — Core's `ForceFlushStateToDisk`) and re-checks.
//!
//! With no connect loop behind the state (an UNARMED signal: unit tests,
//! RPC-only rigs) there is no write-back cache, so there is nothing to be
//! stale against and the check is skipped.
//!
//! [`BlockStoreUtxoView`]: rustoshi_storage::BlockStoreUtxoView
//! [`ChainstateFlushSignal`]: rustoshi_storage::ChainstateFlushSignal

use std::sync::Arc;
use std::time::Duration;

use rustoshi_primitives::Hash256;
use rustoshi_storage::{BlockStore, ChainstateFlushSignal};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::server::RpcState;

/// How many flush-and-recheck rounds a reader makes before giving up. Each
/// serviced flush leaves the connect loop idle for the rest of its tick
/// (see `main.rs`), so in practice the second check already holds.
pub const COHERENCE_ATTEMPTS: usize = 8;

/// How long one round waits for the connect loop to service the flush. The
/// loop services between blocks on a 100 ms tick; this only bounds a wedged
/// loop.
pub const FLUSH_WAIT: Duration = Duration::from_secs(120);

/// The error a reader reports when the coins DB never caught up with the
/// published tip.
pub const INCOHERENT_MSG: &str =
    "the coins database has not caught up with the chain tip yet; retry";

/// Whether a coin read from the coins DB right now describes the published
/// tip `state.best_hash`. Caller must hold the `RpcState` lock.
pub fn coins_db_matches_tip(state: &RpcState) -> bool {
    if !state.chainstate_flush.is_armed() {
        // No connect loop, no write-back cache: the disk set is the only set.
        return true;
    }
    let store = BlockStore::new(&state.db);
    match store.get_best_block_hash() {
        Ok(Some(h)) if h == state.best_hash => true,
        // A fresh datadir seeds the pointer with 32 zero bytes (`db.rs`); at
        // height 0 there are no spendable coins for it to be stale about.
        Ok(Some(h)) if h == Hash256::ZERO => state.best_height == 0,
        Ok(None) => state.best_height == 0,
        _ => false,
    }
}

/// Ask the connect loop to flush its coin cache and wait until it has.
///
/// Core's `ForceFlushStateToDisk`. Returns immediately on an unarmed signal
/// and gives up after [`FLUSH_WAIT`] (callers re-check coherence either way).
/// MUST be called without the `RpcState` lock held: the connect loop takes
/// the write lock on every block-connect.
pub async fn force_flush(signal: &Arc<ChainstateFlushSignal>) {
    if !signal.is_armed() {
        return;
    }
    let ticket = signal.request();
    let started = std::time::Instant::now();
    let mut backoff = Duration::from_millis(2);
    while !signal.is_satisfied(ticket) {
        if started.elapsed() >= FLUSH_WAIT {
            tracing::warn!(
                "force-flush of the chainstate was not serviced within {:?}",
                FLUSH_WAIT
            );
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

/// Take the `RpcState` WRITE lock at a moment when the coins DB describes the
/// published tip. See the module docs.
pub async fn write_coherent(
    state: &RwLock<RpcState>,
) -> Result<RwLockWriteGuard<'_, RpcState>, &'static str> {
    for _ in 0..COHERENCE_ATTEMPTS {
        let guard = state.write().await;
        if coins_db_matches_tip(&guard) {
            return Ok(guard);
        }
        let signal = guard.chainstate_flush.clone();
        drop(guard);
        force_flush(&signal).await;
    }
    tracing::warn!("coin reader refused: {}", INCOHERENT_MSG);
    Err(INCOHERENT_MSG)
}

/// [`write_coherent`] for readers that only need the READ lock.
pub async fn read_coherent(
    state: &RwLock<RpcState>,
) -> Result<RwLockReadGuard<'_, RpcState>, &'static str> {
    for _ in 0..COHERENCE_ATTEMPTS {
        let guard = state.read().await;
        if coins_db_matches_tip(&guard) {
            return Ok(guard);
        }
        let signal = guard.chainstate_flush.clone();
        drop(guard);
        force_flush(&signal).await;
    }
    tracing::warn!("coin reader refused: {}", INCOHERENT_MSG);
    Err(INCOHERENT_MSG)
}
