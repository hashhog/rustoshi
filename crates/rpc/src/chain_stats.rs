//! Chain-wide figures that `getblockchaininfo` (and its siblings) report but
//! that need a walk of the block index: `size_on_disk` and the active chain's
//! transaction count (Core `nChainTx`, the input of `verificationprogress`).
//!
//! Core keeps both as running values (`BlockManager::CalculateCurrentUsage`
//! sums file sizes it tracks as it writes; `CBlockIndex::m_chain_tx_count` is
//! set when a block's data arrives), so its RPC never walks the chain.
//! rustoshi derived both by walking on every call (ab47814e): on mainnet the
//! `size_on_disk` walk reads every block body and undo record, ~20 minutes of
//! I/O, and it ran under the `RpcState` write lock on a tokio worker, which
//! froze RPC, block connection and P2P until the watchdog exited the node
//! (2026-10-19).
//!
//! Both are memoized here, and the `size_on_disk` walk runs on the blocking
//! pool with no state lock held:
//!
//! * `size_on_disk`: per-block byte counts are cached by hash together with
//!   the `HAVE_DATA` / `HAVE_UNDO` bits they were counted under, so a pass
//!   only reads the blocks that are new or changed status (pruned, newly
//!   connected) and otherwise just iterates the index. Passes are
//!   single-flight. A caller waits at most [`SIZE_ON_DISK_WAIT`] for a pass
//!   that started after it arrived; if that pass is still running (the first
//!   pass after a mainnet start), it reports the last finished total, or the
//!   bytes counted so far, and the pass carries on in the background.
//! * chain tx count: a block's cumulative count is final once every block
//!   below it has its data (`n_tx > 0`), so those values are cached and a
//!   walk from a new tip stops at the first cached ancestor.

use rustoshi_primitives::Hash256;
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
use rustoshi_storage::{BlockStore, ChainDb};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// How long `getblockchaininfo` waits for a `size_on_disk` pass before it
/// answers with the last finished total. Regtest and an already-warm cache
/// finish well inside this; only a cold mainnet walk exceeds it.
pub const SIZE_ON_DISK_WAIT: Duration = Duration::from_secs(2);

/// Walk cap, as in the uncached walk this replaces.
const CHAIN_TX_WALK_LIMIT: u32 = 1_000_000;

/// Cached chain-tx entries: every tip that was asked about, plus every
/// 1000th height on a walked path, so a walk after a reorg stops near the
/// fork. Cleared when it grows past this.
const CHAIN_TX_MEMO_MAX: usize = 8192;

#[derive(Default)]
struct UsageState {
    /// Block hash -> (HAVE_DATA, HAVE_UNDO counted, bytes).
    memo: HashMap<Hash256, (bool, bool, u64)>,
    /// A pass is running on the blocking pool.
    running: bool,
    /// Someone asked while a pass was running: run one more after it.
    rerun: bool,
    /// Total of the last finished pass.
    last_total: Option<u64>,
    /// Bytes counted so far by the pass in progress.
    partial: u64,
}

/// See the module docs. One per node, shared through `RpcState`.
pub struct ChainStatsCache {
    usage: Mutex<UsageState>,
    /// Number of finished `size_on_disk` passes.
    passes_tx: watch::Sender<u64>,
    passes_rx: watch::Receiver<u64>,
    chain_tx: Mutex<HashMap<Hash256, u64>>,
}

impl Default for ChainStatsCache {
    fn default() -> Self {
        let (passes_tx, passes_rx) = watch::channel(0);
        Self {
            usage: Mutex::new(UsageState::default()),
            passes_tx,
            passes_rx,
            chain_tx: Mutex::new(HashMap::new()),
        }
    }
}

/// Clears `running` if a pass panics, so later callers start a new one.
struct PassGuard<'a>(&'a ChainStatsCache);

impl Drop for PassGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(mut u) = self.0.usage.lock() {
                u.running = false;
                u.rerun = false;
            }
        }
    }
}

impl ChainStatsCache {
    /// A fresh cache behind an `Arc`.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Core `BlockManager::CalculateCurrentUsage`: logical bytes of every
    /// blk*.dat record (magic + size + block) plus every rev*.dat record
    /// (magic + size + undo payload + 32-byte checksum). Genesis has no undo.
    /// Headers-only blocks are not in the block files. Invalidate does not
    /// delete the records, so a failed block still counts.
    ///
    /// Never holds the `RpcState` lock; waits at most `wait` (see the module
    /// docs for what it reports when the pass is not done by then).
    pub async fn size_on_disk(self: &Arc<Self>, db: Arc<ChainDb>, wait: Duration) -> u64 {
        let mut passes = self.passes_rx.clone();
        let target = {
            let mut u = self.usage.lock().unwrap();
            // Read under the same lock the finishing pass bumps it under, so
            // the pass running now (if any) is exactly `done + 1`.
            let done = *passes.borrow();
            if u.running {
                // The running pass may have read the index before the
                // caller's latest block: wait for the next one.
                u.rerun = true;
                done + 2
            } else {
                u.running = true;
                u.partial = 0;
                let me = Arc::clone(self);
                tokio::task::spawn_blocking(move || me.run_passes(&db));
                done + 1
            }
        };
        // Drop the watch borrow before taking `usage`: a finishing pass
        // bumps the counter while holding `usage`.
        let _finished = tokio::time::timeout(wait, async {
            passes.wait_for(|n| *n >= target).await.is_ok()
        })
        .await;
        let u = self.usage.lock().unwrap();
        // Done in time: `last_total` is that pass (or a later one). Not done:
        // the last finished total, or what the first pass has counted so far.
        u.last_total.unwrap_or(u.partial)
    }

    fn run_passes(&self, db: &ChainDb) {
        let _guard = PassGuard(self);
        loop {
            let total = self.usage_pass(db);
            let mut u = self.usage.lock().unwrap();
            u.last_total = Some(total);
            self.passes_tx.send_modify(|n| *n += 1);
            if u.rerun {
                u.rerun = false;
                u.partial = 0;
                continue;
            }
            u.running = false;
            return;
        }
    }

    /// One walk of the block index. Blocks whose status bits match their
    /// memo entry are not read again.
    fn usage_pass(&self, db: &ChainDb) -> u64 {
        crate::test_hooks::disk_usage_walk_sleep();
        #[cfg(test)]
        crate::server::disk_usage_walk_test_hook(db);
        let store = BlockStore::new(db);
        let Ok(iter) = store.iter_block_index() else {
            return 0;
        };
        let mut total = 0u64;
        for (hash, entry) in iter {
            let data = entry.status.has(BlockStatus::HAVE_DATA);
            let undo = entry.height > 0 && entry.status.has(BlockStatus::HAVE_UNDO);
            if !data && !undo {
                self.usage.lock().unwrap().memo.remove(&hash);
                continue;
            }
            let cached = self
                .usage
                .lock()
                .unwrap()
                .memo
                .get(&hash)
                .filter(|m| m.0 == data && m.1 == undo)
                .map(|m| m.2);
            let bytes = match cached {
                Some(b) => b,
                None => {
                    let (b, complete) = block_file_usage(&store, &hash, data, undo);
                    if complete {
                        self.usage
                            .lock()
                            .unwrap()
                            .memo
                            .insert(hash, (data, undo, b));
                    }
                    b
                }
            };
            total = total.saturating_add(bytes);
            self.usage.lock().unwrap().partial = total;
        }
        total
    }

    /// Chain-tx total of the active chain (Core `nChainTx` at the tip): the
    /// sum of `n_tx` from `tip` down to genesis. Same result as the plain
    /// walk; cached prefixes stop it early.
    pub fn active_chain_tx(&self, store: &BlockStore, tip: &Hash256) -> u64 {
        // Walk down until genesis, a missing entry, or a cached ancestor.
        let mut path: Vec<(Hash256, BlockIndexEntry)> = Vec::new();
        let mut base = 0u64;
        // `base` is final: the walk ended at genesis or at a cached block.
        let mut base_final = false;
        let mut walk = *tip;
        let mut budget = CHAIN_TX_WALK_LIMIT;
        while walk != Hash256::ZERO && budget > 0 {
            if let Some(&cached) = self.chain_tx.lock().unwrap().get(&walk) {
                base = cached;
                base_final = true;
                break;
            }
            budget -= 1;
            let Some(entry) = store.get_block_index(&walk).ok().flatten() else {
                break;
            };
            let next = entry.prev_hash;
            let at_genesis = entry.height == 0;
            path.push((walk, entry));
            if at_genesis {
                base_final = true;
                break;
            }
            walk = next;
        }

        let mut total = base;
        let mut memoize = base_final;
        let mut fresh: Vec<(Hash256, u64)> = Vec::new();
        for (i, (hash, entry)) in path.iter().enumerate().rev() {
            total = total.saturating_add(u64::from(entry.n_tx));
            // A block without data has n_tx 0 until its body arrives, which
            // changes every count above it: nothing above it is final.
            if entry.n_tx == 0 {
                memoize = false;
            }
            if memoize && (i == 0 || entry.height % 1000 == 0) {
                fresh.push((*hash, total));
            }
        }
        if !fresh.is_empty() {
            let mut memo = self.chain_tx.lock().unwrap();
            if memo.len() + fresh.len() > CHAIN_TX_MEMO_MAX {
                memo.clear();
            }
            memo.extend(fresh);
        }
        total
    }
}

/// Bytes one block contributes to `size_on_disk`, and whether every read it
/// needed succeeded (only then is the figure cached).
fn block_file_usage(store: &BlockStore, hash: &Hash256, data: bool, undo: bool) -> (u64, bool) {
    use rustoshi_primitives::Encodable;
    let block = match store.get_block(hash) {
        Ok(Some(b)) => Some(b),
        _ => None,
    };
    let mut complete = block.is_some();
    let mut total = 0u64;
    if data {
        if let Some(block) = &block {
            let mut buf = Vec::new();
            if block.encode(&mut buf).is_ok() {
                total = total.saturating_add(8 + buf.len() as u64);
            }
        }
    }
    if undo {
        let input_counts = block
            .as_ref()
            .map(|block| {
                block
                    .transactions
                    .iter()
                    .skip(1)
                    .map(|tx| tx.inputs.len())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let coins = match store.get_undo(hash) {
            Ok(Some(u)) => u.spent_coins,
            _ => {
                complete = false;
                Vec::new()
            }
        };
        let payload = rustoshi_storage::core_block_undo_payload(&input_counts, &coins);
        total = total.saturating_add(8 + payload.len() as u64 + 32);
    }
    (total, complete)
}
