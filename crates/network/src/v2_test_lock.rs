//! Process-wide serializer for tests that mutate global BIP-324 v2
//! state — the v1-only LRU cache (`peer::v1_only_cache`) and the
//! `RUSTOSHI_BIP324_V2_*` env vars.  Both are shared across all tokio
//! tasks in the test process; without serialization the v1-only cache
//! reads in `run_outbound_peer` race with the LRU eviction test's
//! `clear_v1_only_cache`, and env-var reads in
//! `bip324_v2_outbound_enabled` / `bip324_v2_inbound_enabled` race with
//! the env-var toggling tests.
//!
//! Tests that touch this state should call `lock()` and bind the
//! returned `MutexGuard` to a local; the lock is released when the
//! guard drops at end of scope.  Tests that only touch local state
//! don't need this lock.
//!
//! Compiled only under `#[cfg(test)]`.

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Acquire the process-wide v2-test lock.  Returns a guard; the lock
/// is held until the guard drops.  Poisoned-mutex recovery via
/// `into_inner` is intentional — a panicking test should not corrupt
/// the env-var/cache state for subsequent tests.
pub(crate) fn lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
