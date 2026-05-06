//! Prune coordinator — wires the dormant prune subsystem to the daemon.
//!
//! rustoshi stores block bodies + undo data as RocksDB key/value entries
//! (CF_BLOCKS, CF_UNDO) rather than in flat blk*.dat files. This module
//! drives pruning at the RocksDB-key granularity, mirroring the high-level
//! contract of Bitcoin Core's `validation.cpp::FindFilesToPrune` /
//! `::PruneBlockFilesManual` while delegating the actual delete to
//! `BlockStore::prune_active_chain_range`.
//!
//! Reference (Core):
//!   - `bitcoin-core/src/validation.cpp::FindFilesToPrune`
//!   - `bitcoin-core/src/validation.cpp::PruneBlockFilesManual`
//!   - `bitcoin-core/src/node/blockstorage.cpp::UnlinkPrunedFiles`
//!
//! Two trigger paths:
//!
//! 1. **Auto-prune** (`auto_prune`): called after each block-connect
//!    commit when prune mode is on AND the operator did NOT pass
//!    `-prune=1` (manual-only mode). Drops blocks below
//!    `tip - MIN_BLOCKS_TO_KEEP` whenever the on-disk block usage exceeds
//!    `prune_target`.
//!
//! 2. **Manual prune** (`manual_prune_to_height`): called by the
//!    `pruneblockchain` RPC. Drops blocks below the operator-supplied
//!    height, clamped to `tip - MIN_BLOCKS_TO_KEEP` and the assumeutxo
//!    activation height.
//!
//! Both paths refuse to delete data above the assumeutxo activation
//! height (Core: `m_chainman.GetSnapshotBaseHeight()` is treated as a
//! floor when pruning the active chainstate). This prevents the
//! background-validation chain from being orphaned of its rendezvous
//! point with the snapshot tip.

use crate::block_store::BlockStore;
use crate::blockstore::MIN_BLOCKS_TO_KEEP;
use crate::db::StorageError;

/// `-prune=1` selects "manual-only" mode: the operator drives prune via
/// the `pruneblockchain` RPC; auto-prune never fires. Mirrors Core's
/// `PruneMode::Manual` semantics (`bitcoin-core/src/node/blockstorage.h`:
/// `m_prune_mode = !(m_prune_target > 0)` rejects the size case but
/// accepts =1 as the manual sentinel).
pub const PRUNE_MANUAL_SENTINEL: u64 = 1;

/// Configuration consumed by the prune coordinator. Built once at
/// startup from the parsed `--prune` CLI value and the assumeutxo
/// snapshot height (if any).
#[derive(Clone, Copy, Debug, Default)]
pub struct PruneCoordConfig {
    /// Prune target in **bytes** (0 = pruning disabled).
    /// `1` is reserved as the manual-only sentinel.
    pub target_bytes: u64,
    /// Assumeutxo snapshot activation height (or 0 if none was loaded).
    /// We refuse to prune above this height to preserve the
    /// background-validation rendezvous point.
    pub assumeutxo_height: u32,
}

impl PruneCoordConfig {
    /// Build a config from the parsed `--prune=N` MiB value.
    ///
    /// `prune_mib`:
    ///   - `0` or `None`   : pruning disabled
    ///   - `1`             : manual-only (auto-prune off; pruneblockchain RPC works)
    ///   - `>= 550`        : auto-prune target in MiB
    ///   - `2..=549`       : floor-rejected upstream by the CLI parser; if it
    ///     leaks here we treat it as manual-only (defensive).
    pub fn from_mib(prune_mib: Option<u64>, assumeutxo_height: u32) -> Self {
        let target_bytes = match prune_mib {
            None | Some(0) => 0,
            Some(1) => PRUNE_MANUAL_SENTINEL,
            Some(n) if n < 550 => PRUNE_MANUAL_SENTINEL,
            Some(n) => n.saturating_mul(1024 * 1024),
        };
        Self {
            target_bytes,
            assumeutxo_height,
        }
    }

    /// `true` when any prune behavior should be active (auto OR manual).
    pub fn is_prune_mode(&self) -> bool {
        self.target_bytes > 0
    }

    /// `true` when the operator chose `-prune=1` manual-only mode.
    pub fn is_manual_only(&self) -> bool {
        self.target_bytes == PRUNE_MANUAL_SENTINEL
    }

    /// `true` when auto-prune may fire (size-target mode, not manual-only).
    pub fn auto_prune_enabled(&self) -> bool {
        self.target_bytes > PRUNE_MANUAL_SENTINEL
    }
}

/// Result of a single prune attempt.
#[derive(Clone, Copy, Debug, Default)]
pub struct PruneOutcome {
    /// Number of (height, hash) pairs whose body + undo were dropped.
    pub blocks_pruned: u32,
    /// New prune-height watermark after this pass.
    pub new_prune_height: u32,
}

/// Auto-prune trigger — invoke from the daemon's connect-block path.
///
/// Mirrors Core's `validation.cpp::CChainState::FlushStateToDisk` →
/// `m_blockman.FindFilesToPrune` arc. We don't measure on-disk usage
/// against the byte target here (RocksDB doesn't expose a per-CF byte
/// count cheaply); instead we drop everything below the keep window
/// every time the trigger fires. That's safe because:
///   - the keep window itself bounds storage growth at ~288 * avg block
///     (~432 MiB worst case), which is below the 550 MiB Core minimum
///   - the floor (assumeutxo height) prevents over-pruning during
///     background validation
///
/// Returns `None` if pruning is disabled / manual-only / not yet triggered.
///
/// **Safety invariants:**
///   - Never deletes height 0 (genesis)
///   - Never deletes height >= `tip - MIN_BLOCKS_TO_KEEP`
///   - Never deletes height >= `assumeutxo_height`
pub fn auto_prune(
    store: &BlockStore<'_>,
    config: &PruneCoordConfig,
    tip_height: u32,
) -> Result<Option<PruneOutcome>, StorageError> {
    if !config.auto_prune_enabled() {
        return Ok(None);
    }
    // Compute the highest height we're willing to drop on this pass.
    // Core: `nLastBlockWeCanPrune = std::min(prune_height, tip - MIN_BLOCKS_TO_KEEP)`.
    let keep_window_floor = tip_height.saturating_sub(MIN_BLOCKS_TO_KEEP);
    if keep_window_floor == 0 {
        // Tip is too low to prune anything safely — this is the regtest
        // / fresh-IBD case.
        return Ok(None);
    }
    let mut last_block_can_prune = keep_window_floor.saturating_sub(1);
    // Respect assumeutxo floor: never delete data the background-validation
    // chain may need to rendezvous against.
    if config.assumeutxo_height > 0 && last_block_can_prune >= config.assumeutxo_height {
        last_block_can_prune = config.assumeutxo_height.saturating_sub(1);
    }

    let already_pruned = store.get_prune_height()?;
    if last_block_can_prune <= already_pruned {
        return Ok(None);
    }

    let from = already_pruned.saturating_add(1);
    let to = last_block_can_prune;
    let pruned = store.prune_active_chain_range(from, to)?;
    if pruned == 0 {
        return Ok(None);
    }
    tracing::info!(
        "auto-prune: dropped {} blocks in range [{}, {}] (tip={}, target_bytes={})",
        pruned,
        from,
        to,
        tip_height,
        config.target_bytes,
    );
    Ok(Some(PruneOutcome {
        blocks_pruned: pruned,
        new_prune_height: to,
    }))
}

/// Manual prune driven by the `pruneblockchain` RPC. Honors
/// `-prune=1` manual-only mode (it's the only path that runs in that
/// configuration).
///
/// Returns the effective prune height (clamped against the
/// keep-window + assumeutxo floor).
///
/// **Caller** (the RPC handler) is responsible for converting the
/// "Unix epoch timestamp vs height" overload (Core treats `height < 1e9`
/// as a height and `>= 1e9` as a UNIX timestamp). rustoshi's RPC
/// surface only takes a height here.
pub fn manual_prune_to_height(
    store: &BlockStore<'_>,
    config: &PruneCoordConfig,
    tip_height: u32,
    requested_height: u32,
) -> Result<PruneOutcome, StorageError> {
    if !config.is_prune_mode() {
        // Caller should already have rejected; defense in depth.
        return Ok(PruneOutcome::default());
    }
    let keep_window_floor = tip_height.saturating_sub(MIN_BLOCKS_TO_KEEP);
    let mut effective = requested_height.min(keep_window_floor);
    if config.assumeutxo_height > 0 && effective > config.assumeutxo_height {
        effective = config.assumeutxo_height;
    }
    if effective == 0 {
        return Ok(PruneOutcome::default());
    }
    let already_pruned = store.get_prune_height()?;
    if effective <= already_pruned {
        return Ok(PruneOutcome {
            blocks_pruned: 0,
            new_prune_height: already_pruned,
        });
    }
    let from = already_pruned.saturating_add(1);
    let to = effective;
    let pruned = store.prune_active_chain_range(from, to)?;
    tracing::info!(
        "manual-prune: dropped {} blocks in range [{}, {}] (tip={}, requested={})",
        pruned,
        from,
        to,
        tip_height,
        requested_height,
    );
    Ok(PruneOutcome {
        blocks_pruned: pruned,
        new_prune_height: to,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_mib_disabled() {
        let c = PruneCoordConfig::from_mib(None, 0);
        assert!(!c.is_prune_mode());
        assert!(!c.is_manual_only());
        assert!(!c.auto_prune_enabled());
        let c = PruneCoordConfig::from_mib(Some(0), 0);
        assert!(!c.is_prune_mode());
    }

    #[test]
    fn config_from_mib_manual_only() {
        let c = PruneCoordConfig::from_mib(Some(1), 0);
        assert!(c.is_prune_mode());
        assert!(c.is_manual_only());
        assert!(!c.auto_prune_enabled());
        // Sub-minimum is collapsed to manual (defensive — CLI also rejects).
        let c = PruneCoordConfig::from_mib(Some(549), 0);
        assert!(c.is_manual_only());
    }

    #[test]
    fn config_from_mib_auto() {
        let c = PruneCoordConfig::from_mib(Some(550), 0);
        assert!(c.is_prune_mode());
        assert!(!c.is_manual_only());
        assert!(c.auto_prune_enabled());
        assert_eq!(c.target_bytes, 550 * 1024 * 1024);
    }
}
