//! Tip-change notification primitive for the wait-family RPCs
//! (`waitfornewblock` / `waitforblock` / `waitforblockheight`).
//!
//! Bitcoin Core registers a `WaitTipChanged` condition variable
//! (kernel `Notifications` / `KernelNotifications::blockTip`) that is signalled
//! on every active-chain tip update. The wait-family RPCs
//! (`bitcoin-core/src/rpc/blockchain.cpp` `waitfornewblock` @290,
//! `waitforblock` @349, `waitforblockheight` @410) block on it with a deadline,
//! re-checking their predicate (new tip / hash match / height >=) after each
//! wake and returning the current tip `{hash, height}` on match OR timeout.
//!
//! `TipNotifier` is the rustoshi analogue. It mirrors the proven ouroboros
//! pilot (`ouroboros/src/ouroboros/tip_notifier.py`): a monotonic generation
//! counter plus a wake mechanism, made lost-wakeup-safe.
//!
//! ## Design (lost-wakeup safety)
//!
//! * The waiter's predicate is always evaluated against the **authoritative**
//!   in-memory tip (`RpcState.best_hash` / `best_height`, which every connect /
//!   reorg chokepoint writes under the `RpcState` write lock and every other
//!   RPC reads), never against state carried inside this object. The notifier
//!   only provides a prompt wake-up; correctness does not depend on a notify
//!   ever firing for a specific tip value. This makes the primitive robust to
//!   coalesced / missed notifications (e.g. two blocks connected back-to-back
//!   before a waiter wakes): the waiter re-reads the real tip after every wake
//!   and after the timeout, exactly like Core.
//!
//! * A monotonically increasing `generation` counter lets a waiter detect a tip
//!   change that happened *between* its predicate check and its `wait` call (the
//!   classic lost-wakeup race). A waiter captures the generation, checks its
//!   predicate, then awaits a generation bump — so a notify that races in after
//!   the check but before the await is not lost.
//!
//! * `tokio::sync::Notify` is the wake mechanism. `notify()` bumps the
//!   generation and calls `notify_waiters()` to release every coroutine
//!   currently parked in `wait`. Because `notify_waiters()` (unlike
//!   `notify_one`) does **not** store a permit, a future `wait` call cannot
//!   consume a stale wakeup — combined with the generation re-check, this gives
//!   the same edge-triggered "set-then-clear pulse" semantics as the ouroboros
//!   `asyncio.Event`.
//!
//! `notify()` is `&self` and lock-free, safe to call from any connect / reorg
//! chokepoint while the `RpcState` write lock is held.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

/// Wake-on-tip-advance primitive shared by the wait-family RPCs.
#[derive(Debug)]
pub struct TipNotifier {
    /// Wake mechanism. `notify_waiters()` releases all currently-parked
    /// waiters and (deliberately) stores no permit, so a later `wait` blocks
    /// again rather than consuming a stale wakeup.
    notify: Notify,
    /// Monotonic counter bumped on every [`TipNotifier::notify`]. Waiters
    /// snapshot it before checking their predicate so a notify that races in
    /// between the check and the await is observed (no lost wakeup).
    generation: AtomicU64,
}

impl Default for TipNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl TipNotifier {
    /// Create a fresh notifier with generation 0 and no parked waiters.
    pub fn new() -> Self {
        Self {
            notify: Notify::new(),
            generation: AtomicU64::new(0),
        }
    }

    /// Convenience constructor returning a shareable handle.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Current tip-change generation (bumped on every [`TipNotifier::notify`]).
    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Signal that the active-chain tip advanced.
    ///
    /// Bumps the generation counter and releases every coroutine currently in
    /// [`TipNotifier::wait`] so each re-evaluates its predicate. Safe to call
    /// from any connect / reorg chokepoint (`&self`, lock-free, never blocks).
    ///
    /// The generation is incremented with `Release` ordering BEFORE
    /// `notify_waiters()` so a waiter that wakes is guaranteed to observe the
    /// new generation (and therefore re-read the new tip).
    pub fn notify(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Await the next tip change after `last_generation`.
    ///
    /// `last_generation` is the generation observed by the caller *before* it
    /// last checked its predicate. If the generation has already advanced past
    /// this (a notify raced in), this returns immediately (`true`) without
    /// parking. Otherwise it parks until the next [`TipNotifier::notify`] or,
    /// if `timeout` is `Some`, until the deadline elapses.
    ///
    /// Returns `true` if a tip change (or spurious wake) was observed within
    /// the deadline, `false` if the wait timed out. Either way the caller MUST
    /// re-evaluate its predicate against the authoritative tip.
    ///
    /// NOTE on ordering: `Notify::notified()` must be constructed (it enqueues
    /// the waiter) and only THEN may we re-check the generation. We register
    /// the future first via `tokio::pin!`, then do the lost-wakeup fast-path
    /// check, so a `notify()` that fires after the check still wakes the
    /// already-registered future.
    pub async fn wait(&self, last_generation: u64, timeout: Option<Duration>) -> bool {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Enable the waiter (idempotent): after this, a notify_waiters() that
        // races in is guaranteed to wake `notified`.
        notified.as_mut().enable();

        // Fast path: a notify already raced in since the caller's snapshot.
        // Because `enable()` ran first, even a notify between the snapshot and
        // here is captured by the pinned future, but this short-circuits the
        // common already-advanced case without parking.
        if self.generation.load(Ordering::Acquire) != last_generation {
            return true;
        }

        match timeout {
            None => {
                notified.await;
                true
            }
            Some(dur) => {
                // A zero/elapsed deadline must not park.
                if dur.is_zero() {
                    return false;
                }
                tokio::time::timeout(dur, notified).await.is_ok()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn notify_wakes_a_parked_waiter() {
        let n = TipNotifier::shared();
        let gen = n.generation();
        let n2 = n.clone();
        let h = tokio::spawn(async move { n2.wait(gen, Some(Duration::from_secs(5))).await });
        // Give the waiter a moment to park, then notify.
        tokio::time::sleep(Duration::from_millis(20)).await;
        n.notify();
        let start = Instant::now();
        let woke = h.await.unwrap();
        assert!(woke, "waiter should have woken on notify, not timed out");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(n.generation(), gen + 1);
    }

    #[tokio::test]
    async fn lost_wakeup_is_not_lost() {
        // A notify that races in between the caller's generation snapshot and
        // its wait() call must NOT be lost: wait() returns immediately.
        let n = TipNotifier::new();
        let gen = n.generation();
        n.notify(); // races in after the snapshot, before wait()
        let woke = n.wait(gen, Some(Duration::from_secs(5))).await;
        assert!(woke, "a notify after the gen snapshot must wake immediately");
    }

    #[tokio::test]
    async fn wait_times_out_without_notify() {
        let n = TipNotifier::new();
        let gen = n.generation();
        let start = Instant::now();
        let woke = n.wait(gen, Some(Duration::from_millis(100))).await;
        assert!(!woke, "no notify => must time out");
        assert!(start.elapsed() >= Duration::from_millis(90));
    }

    #[tokio::test]
    async fn coalesced_notifies_still_wake() {
        // Two notifies before the waiter parks: it must still wake (and the
        // caller re-reads the tip — handled by the RPC loop, not here).
        let n = TipNotifier::shared();
        let gen = n.generation();
        n.notify();
        n.notify();
        let woke = n.wait(gen, Some(Duration::from_secs(5))).await;
        assert!(woke);
        assert_eq!(n.generation(), gen + 2);
    }
}
