//! Cross-task force-flush handshake for the live chainstate.
//!
//! # Why this exists
//!
//! Bitcoin Core's UTXO-set surfaces do not read whatever happens to be on
//! disk — they force the chainstate down first:
//!
//!   * `gettxoutsetinfo` — `rpc/blockchain.cpp:1075`,
//!     `active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false)`
//!     immediately before `GetUTXOStats(&active_chainstate.CoinsDB(), ...)`;
//!   * `dumptxoutset`    — the same call inside `PrepareUTXOSnapshot`
//!     (`rpc/blockchain.cpp:3257`), before the stats pass and the coins
//!     cursor.
//!
//! Core can do that inline because its RPC thread reaches the one
//! authoritative `CCoinsViewCache` under `cs_main`. rustoshi cannot: the
//! write-back coin cache ([`crate::BlockStoreUtxoView`]) is a `&mut` local
//! owned by the P2P connect loop in `rustoshi/src/main.rs`, while the RPC
//! handlers only hold an `Arc<ChainDb>` and read `CF_UTXO` straight out of
//! RocksDB. Everything the connect loop has not flushed is therefore
//! INVISIBLE to `gettxoutsetinfo` / `dumptxoutset`.
//!
//! That is not a theoretical gap. The connect loop flushes on the
//! Core-parity schedule (cache CRITICAL / LARGE, every 2000 blocks, every
//! 60 min, or on reaching the announced header tip). Syncing a ladder range
//! over P2P — 30 blocks, tiny cache, header tip hundreds of thousands of
//! blocks ahead because the peer serves headers past the block cap — trips
//! NONE of them, so 30 blocks' worth of coins sat in RAM and
//! `gettxoutsetinfo` answered with the set of the height the node STARTED
//! at. `submitblock` hid the bug: that path owns its own view and flushes
//! per block (`crates/rpc/src/server.rs`), so block-at-a-time harnesses
//! always saw a coherent surface.
//!
//! # The handshake
//!
//! A ticket counter, not a flag, so a request is never coalesced into a
//! flush that had already started before it was made:
//!
//! 1. the RPC calls [`request`](Self::request) and gets a monotonically
//!    increasing ticket;
//! 2. the connect loop, between blocks, calls [`pending`](Self::pending),
//!    performs the atomic UTXO+tip flush, then [`complete`](Self::complete)
//!    with the sequence number it observed BEFORE flushing;
//! 3. the RPC polls [`is_satisfied`](Self::is_satisfied) and proceeds once
//!    its ticket is covered.
//!
//! A request made while a flush is in flight gets a higher ticket than the
//! one that flush completes, so it waits for the next round rather than
//! being satisfied by a flush that may have missed its coins.
//!
//! [`arm`](Self::arm) exists because not every `RpcState` has a connect loop
//! behind it (unit tests, the RPC-only harnesses, `submitblock`-driven
//! regtest rigs). An unarmed signal makes the RPC-side wait a no-op instead
//! of blocking until the timeout on a node where nothing will ever answer.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Shared force-flush handshake between the RPC handlers and the owner of
/// the live UTXO write-back cache. See the module docs.
#[derive(Debug, Default)]
pub struct ChainstateFlushSignal {
    /// Highest ticket handed out by [`ChainstateFlushSignal::request`].
    requested: AtomicU64,
    /// Highest ticket the flush owner has satisfied.
    completed: AtomicU64,
    /// Whether a connect loop is actually servicing this signal.
    armed: AtomicBool,
}

impl ChainstateFlushSignal {
    /// Create an unarmed signal. Requests against it are no-ops until
    /// [`arm`](Self::arm) is called by whoever owns the coin cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare that a connect loop will service pending requests.
    ///
    /// Called once by `main.rs` just before entering the event loop.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Whether anybody is servicing this signal.
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    /// Ask the owner to flush. Returns the ticket to wait on.
    pub fn request(&self) -> u64 {
        self.requested.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Whether every flush up to `ticket` has landed.
    pub fn is_satisfied(&self, ticket: u64) -> bool {
        self.completed.load(Ordering::SeqCst) >= ticket
    }

    /// Owner side: the highest outstanding ticket, or `None` when there is
    /// nothing to do. Must be called BEFORE the flush; the returned value is
    /// what gets passed to [`complete`](Self::complete) afterwards.
    pub fn pending(&self) -> Option<u64> {
        let requested = self.requested.load(Ordering::SeqCst);
        if requested > self.completed.load(Ordering::SeqCst) {
            Some(requested)
        } else {
            None
        }
    }

    /// Owner side: mark every ticket up to `ticket` satisfied.
    ///
    /// `fetch_max` rather than `store` so an out-of-order completion can
    /// never move the watermark backwards.
    pub fn complete(&self, ticket: u64) {
        self.completed.fetch_max(ticket, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_by_default() {
        assert!(!ChainstateFlushSignal::new().is_armed());
    }

    #[test]
    fn ticket_is_only_satisfied_by_a_later_flush() {
        let s = ChainstateFlushSignal::new();
        s.arm();
        assert!(s.is_armed());
        assert_eq!(s.pending(), None);

        let t1 = s.request();
        assert_eq!(t1, 1);
        assert!(!s.is_satisfied(t1));

        // Owner observes the pending sequence, then flushes, then completes.
        let seq = s.pending().expect("request outstanding");
        // A request racing IN during the flush must NOT be satisfied by it.
        let t2 = s.request();
        s.complete(seq);
        assert!(s.is_satisfied(t1));
        assert!(!s.is_satisfied(t2), "t2 arrived mid-flush; needs the next round");

        let seq2 = s.pending().expect("t2 still outstanding");
        s.complete(seq2);
        assert!(s.is_satisfied(t2));
        assert_eq!(s.pending(), None);
    }

    #[test]
    fn complete_never_regresses() {
        let s = ChainstateFlushSignal::new();
        let t1 = s.request();
        let t2 = s.request();
        s.complete(t2);
        s.complete(t1);
        assert!(s.is_satisfied(t2));
    }
}
