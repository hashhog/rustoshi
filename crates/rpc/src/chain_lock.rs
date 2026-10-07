//! `cs_main` for rustoshi: one lock that every chainstate writer holds.
//!
//! # The hazard (2026-10-07 concurrency audit, RU-1 / RU-2)
//!
//! The P2P connect loop (`rustoshi/src/main.rs`) owns the node's in-memory
//! chainstate: its `ChainState` tip, its write-back coin view, the header
//! chain and the block downloader. The RPC chain writers (`submitblock`,
//! `generate*`, `invalidateblock`, `reconsiderblock`, `preciousblock`,
//! `loadtxoutset`, the `dumptxoutset rollback` dance) write the coins DB
//! directly through fresh views. Nothing serialized the two:
//!
//! * `submitblock X` could connect X between the loop taking X from the
//!   downloader and connecting it. The loop then connected X a second time on
//!   top of itself, failed BIP30 / missing-inputs, and persisted
//!   `FAILED_VALIDITY` on a valid block (`mark_connect_failed_block_invalid`).
//! * `invalidateblock N` rewound the DB to N-1, but the loop's `ChainState`
//!   still said N, so the next P2P block N+1 passed `prev == tip` and was
//!   connected over the N-1 coins: N's spends came back, N's outputs vanished,
//!   and the at-tip flush wrote that set as tip N+1.
//! * the `dumptxoutset rollback` pause flag was read only by `submitblock`; the
//!   loop connected P2P blocks over the rewound DB.
//!
//! # Core
//!
//! `ProcessNewBlock` / `ActivateBestChain` / `InvalidateBlock` /
//! `FlushStateToDisk` all run under `cs_main` (validation.cpp 2707, 3359,
//! 3545, 4409), and `InvalidateBlock` / `ActivateBestChain` additionally take
//! `m_chainstate_mutex` so only one of them moves the tip at a time
//! (validation.cpp 3337, 3533). There is one chainstate, so whoever moves the
//! tip moves it for everyone.
//!
//! # The rule here
//!
//! [`ChainLock`] is that mutex. The connect loop holds it across each block's
//! connect → flush → publish (and around its force-flush service and the
//! attach-and-reorg path); every RPC chain writer holds it for its whole
//! write (`coins_coherence::chain_write_coherent`). The loop only ever
//! `try_lock`s it, so an RPC writer — even a long rollback — defers block
//! connection instead of freezing the event loop (Core's `NetworkDisable`).
//!
//! The loop cannot see an RPC writer's changes on its own, so every writer
//! bumps [`ChainLock::epoch`] when it releases the lock, and records the block
//! sets it (in)validated as [`ChainEvent`]s. The loop compares the epoch each
//! time it takes the lock and, when it moved, re-reads its tip from the coins
//! DB, drops its coin view and realigns the header chain and downloader before
//! it connects anything.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustoshi_primitives::Hash256;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// A change an RPC chain writer made that the connect loop must adopt beyond
/// "re-read the tip".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEvent {
    /// `invalidateblock`: these blocks are now `FAILED_*`.
    Invalidated(Vec<Hash256>),
    /// `reconsiderblock`: these blocks lost their `FAILED_*` flags.
    Reconsidered(Vec<Hash256>),
}

/// The chainstate mutex plus the RPC → connect-loop change feed.
#[derive(Debug, Default)]
pub struct ChainLock {
    mutex: Arc<Mutex<()>>,
    epoch: AtomicU64,
    events: std::sync::Mutex<Vec<ChainEvent>>,
}

impl ChainLock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Wait for the lock (RPC writers).
    pub async fn lock(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.mutex).lock_owned().await
    }

    /// Take the lock only if it is free (the connect loop: it must never
    /// block its event loop on an RPC writer). tokio's mutex is fair, so a
    /// queued RPC writer is never starved by the loop re-taking it.
    pub fn try_lock(&self) -> Option<OwnedMutexGuard<()>> {
        Arc::clone(&self.mutex).try_lock_owned().ok()
    }

    /// Whether some task holds the lock right now (diagnostics only).
    pub fn is_locked(&self) -> bool {
        self.mutex.try_lock().is_err()
    }

    /// Record that an RPC writer may have changed the chainstate. Called
    /// while the lock is still held.
    pub fn note_write(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Record a change the loop must act on. Called while the lock is held.
    pub fn push_event(&self, ev: ChainEvent) {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).push(ev);
    }

    /// Current write epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// For the connect loop, holding the lock: if any writer ran since
    /// `seen`, advance `seen` and return the events it recorded (possibly
    /// none — "re-read the tip" is implied).
    pub fn take_changes(&self, seen: &mut u64) -> Option<Vec<ChainEvent>> {
        let now = self.epoch();
        if now == *seen {
            return None;
        }
        *seen = now;
        Some(std::mem::take(
            &mut *self.events.lock().unwrap_or_else(|p| p.into_inner()),
        ))
    }
}

/// Holding the chain lock on behalf of an RPC writer. Bumps the write epoch
/// before the lock is released, on every exit path (success, error, panic).
pub struct ChainHeld {
    // Field order matters: `chain` is still alive while `Drop::drop` bumps
    // the epoch, and the mutex guard is released after that.
    chain: Arc<ChainLock>,
    _guard: OwnedMutexGuard<()>,
}

impl ChainHeld {
    pub fn new(chain: Arc<ChainLock>, guard: OwnedMutexGuard<()>) -> Self {
        Self { chain, _guard: guard }
    }

    pub fn push_event(&self, ev: ChainEvent) {
        self.chain.push_event(ev);
    }
}

impl Drop for ChainHeld {
    fn drop(&mut self) {
        self.chain.note_write();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writer_release_bumps_epoch_and_hands_over_events() {
        let cl = ChainLock::new();
        let mut seen = cl.epoch();
        assert!(cl.take_changes(&mut seen).is_none());
        {
            let held = ChainHeld::new(cl.clone(), cl.lock().await);
            assert!(cl.try_lock().is_none(), "the loop must not get the lock while a writer holds it");
            held.push_event(ChainEvent::Invalidated(vec![Hash256::ZERO]));
        }
        let ev = cl.take_changes(&mut seen).expect("writer ran");
        assert_eq!(ev, vec![ChainEvent::Invalidated(vec![Hash256::ZERO])]);
        assert!(cl.take_changes(&mut seen).is_none());
        assert!(cl.try_lock().is_some());
    }

    #[tokio::test]
    async fn queued_writer_is_not_starved_by_try_lock() {
        let cl = ChainLock::new();
        let loop_guard = cl.try_lock().unwrap();
        let cl2 = cl.clone();
        let w = tokio::spawn(async move {
            let _g = cl2.lock().await;
        });
        tokio::task::yield_now().await;
        drop(loop_guard);
        // The waiting writer was handed the permit: the loop's next try fails
        // until the writer is done.
        assert!(cl.try_lock().is_none() || w.is_finished());
        w.await.unwrap();
        assert!(cl.try_lock().is_some());
    }
}
