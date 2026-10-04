//! Process-wide fatal latch: rustoshi's `AbortNode` (gate 6).
//!
//! Gate 6 (docs/RELEASE-CHECKLIST.md): a resource limit or system fault
//! (disk full, I/O error, a failed coins-DB read) leads to *retry or halt*,
//! never to a reject or an accept. Bitcoin Core's model:
//!
//! * a coins-DB read error goes through `CCoinsViewErrorCatcher`
//!   (coins.cpp:415-427), whose callback aborts the node;
//! * a failed block/undo/chainstate write or flush is `FatalError` ->
//!   `AbortNode` (validation.cpp:2136, :2779, :2812, :2836): the block is
//!   never marked invalid and the peer is never punished;
//! * after the abort nothing more is connected and the node shuts down.
//!
//! [`abort_node`] sets the latch. It is set AT THE SOURCE by the storage
//! layer (`ChainDb` read/write errors, after one retry), so no caller can
//! forget it. Every consumer that would otherwise act on state that may now
//! be torn checks [`is_aborted`]:
//!
//! * the block-connect loops stop connecting and the process exits non-zero
//!   (systemd `Restart=on-failure` brings it back on the last durable state);
//! * no verdict reached after the latch is persisted, and no peer is punished;
//! * `submitblock` answers `RPC_VERIFY_ERROR`, never a BIP-22 reject token;
//! * the mempool refuses without caching a reject or scoring the sender;
//! * the graceful-shutdown UTXO flush is SKIPPED (Core: after AbortNode the
//!   chainstate is not written again).
//!
//! System faults that reach a verdict-producing site without going through
//! the latch are carried as [`crate::validation::ValidationError::SystemFault`]
//! or, on string-typed paths (the header closure), prefixed with
//! [`SYSTEM_FAULT_TAG`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Prefix for string-typed errors that are a local system fault (I/O, disk
/// full, a failed DB read) rather than a property of the peer's data. A
/// classifier that sees it must never punish and never mark.
pub const SYSTEM_FAULT_TAG: &str = "system-fault";

static ABORTED: AtomicBool = AtomicBool::new(false);
static REASON: Mutex<Option<String>> = Mutex::new(None);

/// Latch the process into the aborting state. The first reason wins; later
/// calls only log. Never panics.
pub fn abort_node(reason: &str) {
    let first = !ABORTED.swap(true, Ordering::SeqCst);
    if first {
        if let Ok(mut r) = REASON.lock() {
            *r = Some(reason.to_string());
        }
        tracing::error!(
            "*** FATAL (AbortNode): {} -- no further blocks will be connected, no verdict \
             will be recorded and the chainstate will not be flushed again; the node is \
             shutting down and will exit non-zero",
            reason
        );
    } else {
        tracing::error!("*** FATAL (AbortNode, already latched): {}", reason);
    }
}

/// Whether [`abort_node`] has been called in this process.
pub fn is_aborted() -> bool {
    ABORTED.load(Ordering::SeqCst)
}

/// The first reason passed to [`abort_node`], if any.
pub fn abort_reason() -> Option<String> {
    REASON.lock().ok().and_then(|r| r.clone())
}

/// Whether a string-typed error is a tagged local system fault.
pub fn is_system_fault_str(e: &str) -> bool {
    e.contains(SYSTEM_FAULT_TAG)
}

/// Clear the latch. Tests only: production never un-latches (the only way
/// out of AbortNode is a process restart).
#[doc(hidden)]
pub fn reset_for_tests() {
    ABORTED.store(false, Ordering::SeqCst);
    if let Ok(mut r) = REASON.lock() {
        *r = None;
    }
}

/// Serialises tests that set or observe the process-wide latch, so a test
/// that latches cannot make an unrelated test in the same binary see an
/// aborting process.
#[doc(hidden)]
pub fn test_serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: Mutex<()> = Mutex::new(());
    GUARD.lock().unwrap_or_else(|p| p.into_inner())
}
