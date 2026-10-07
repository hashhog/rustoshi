//! Fault-injection hooks for the chain-lock reproducers.
//!
//! Every hook is inert unless its environment variable is set, and none of
//! them changes behaviour beyond sleeping at a fixed point. They exist so the
//! races in the 2026-10-07 concurrency audit (RU-1/RU-2/RU-3) can be driven
//! deterministically from a regtest harness
//! (`tools/chain-lock-rustoshi-proof.py` in the meta-repo) instead of by
//! hoping two threads interleave:
//!
//! * `RUSTOSHI_TEST_PAUSE_CONNECT_HEIGHT=H` (+ `RUSTOSHI_TEST_PAUSE_CONNECT_MS`,
//!   default 8000): the connect loop sleeps once, after it has taken block H
//!   from the downloader and before it connects and flushes it.
//! * `RUSTOSHI_TEST_TXOUTSET_WALK_SLEEP_MS`: `scantxoutset` and the
//!   `gettxoutsetinfo` full walk sleep once at the start of the coin walk.
//! * `RUSTOSHI_TEST_ROLLBACK_PAUSE_MS`: `dumptxoutset rollback` sleeps once
//!   between the rewind and the dump.
//! * `RUSTOSHI_TEST_COHERENT_READ_SLEEP_MS`: a coherent coin reader
//!   (`read_coherent`: `gettxout`, REST `getutxos`) sleeps once, holding the
//!   `RpcState` lock, after the coherence check passed and before it reads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

/// Connect-loop pause before block `height` is connected (fires once).
pub async fn pause_before_connect(height: u32) {
    static FIRED: AtomicBool = AtomicBool::new(false);
    let Some(h) = env_u64("RUSTOSHI_TEST_PAUSE_CONNECT_HEIGHT") else {
        return;
    };
    if h != height as u64 || FIRED.swap(true, Ordering::SeqCst) {
        return;
    }
    let ms = env_u64("RUSTOSHI_TEST_PAUSE_CONNECT_MS").unwrap_or(8000);
    tracing::warn!("TEST HOOK: connect loop pausing {} ms before connecting height {}", ms, height);
    tokio::time::sleep(Duration::from_millis(ms)).await;
    tracing::warn!("TEST HOOK: connect loop resuming at height {}", height);
}

/// Sleep at the start of a UTXO-set walk (blocking; walks are synchronous).
pub fn txoutset_walk_sleep(which: &str) {
    if let Some(ms) = env_u64("RUSTOSHI_TEST_TXOUTSET_WALK_SLEEP_MS") {
        tracing::warn!("TEST HOOK: {} walk sleeping {} ms", which, ms);
        std::thread::sleep(Duration::from_millis(ms));
        tracing::warn!("TEST HOOK: {} walk resuming", which);
    }
}

/// Pause between the rollback rewind and the dump (fires once).
pub async fn rollback_pause() {
    static FIRED: AtomicBool = AtomicBool::new(false);
    let Some(ms) = env_u64("RUSTOSHI_TEST_ROLLBACK_PAUSE_MS") else {
        return;
    };
    if FIRED.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::warn!("TEST HOOK: dumptxoutset rollback pausing {} ms after the rewind", ms);
    tokio::time::sleep(Duration::from_millis(ms)).await;
    tracing::warn!("TEST HOOK: dumptxoutset rollback resuming");
}

/// Pause inside a coherent read, after the check and before the read (fires once).
pub async fn coherent_read_pause() {
    static FIRED: AtomicBool = AtomicBool::new(false);
    let Some(ms) = env_u64("RUSTOSHI_TEST_COHERENT_READ_SLEEP_MS") else {
        return;
    };
    if FIRED.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::warn!("TEST HOOK: coherent reader pausing {} ms after its check", ms);
    tokio::time::sleep(Duration::from_millis(ms)).await;
    tracing::warn!("TEST HOOK: coherent reader resuming");
}
