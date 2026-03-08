//! UTXO cache and chain state management.
//!
//! This module implements:
//!
//! - **UtxoCache**: An in-memory UTXO cache that wraps a database-backed UTXO set.
//!   During block validation, changes accumulate in memory. After successful validation,
//!   changes are flushed to disk atomically.
//!
//! - **ChainState**: The active chain state, tracking the best chain tip and managing
//!   reorganizations.
//!
//! # Performance
//!
//! The UTXO cache is the single most important performance optimization for IBD.
//! Millions of UTXOs are created and spent during initial sync; keeping them in
//! memory avoids millions of disk reads/writes.
//!
//! # Known Pitfalls
//!
//! - **Hash byte order**: Bitcoin uses little-endian internally but displays hashes
//!   in reversed byte order. Confusion between internal and display order causes
//!   UTXO lookup misses and sync failures.
//! - **header_tip vs chain_tip**: These must be stored as separate DB entries. The
//!   header sync process updates header_tip; block validation updates chain_tip.
//!   Mixing them up causes the sync coordinator to lose track of progress.

use crate::params::{ChainParams, MEDIAN_TIME_PAST_WINDOW};
use crate::validation::{
    check_block, connect_block, disconnect_block, BlockIndexEntry, CoinEntry, UndoData, UtxoView,
    ValidationError,
};
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint};
use std::collections::HashMap;

// ============================================================
// UTXO CACHE
// ============================================================

/// In-memory UTXO cache that wraps a database-backed UTXO set.
///
/// During block validation, changes are accumulated in memory.
/// After successful validation, the changes are flushed to disk atomically.
///
/// The cache uses `Option<CoinEntry>` where `None` represents a deletion.
/// This allows the flush operation to issue both puts and deletes in a
/// single WriteBatch.
pub struct UtxoCache<F>
where
    F: Fn(&OutPoint) -> Option<CoinEntry> + Send,
{
    /// New or modified entries (not yet flushed to disk).
    /// `None` means the entry was deleted.
    cache: HashMap<OutPoint, Option<CoinEntry>>,
    /// Reference to the database for cache misses.
    db_lookup: F,
    /// Number of cache entries.
    cache_size: usize,
    /// Maximum cache size before forced flush.
    max_cache_size: usize,
}

impl<F> UtxoCache<F>
where
    F: Fn(&OutPoint) -> Option<CoinEntry> + Send,
{
    /// Create a new UTXO cache.
    ///
    /// # Arguments
    /// * `db_lookup` - Closure to look up UTXOs from the database on cache miss.
    /// * `max_cache_size` - Maximum number of entries before requiring a flush.
    ///   A reasonable default is 5,000,000 entries (~450 MB).
    pub fn new(db_lookup: F, max_cache_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            db_lookup,
            cache_size: 0,
            max_cache_size,
        }
    }

    /// Check if the cache needs flushing.
    pub fn needs_flush(&self) -> bool {
        self.cache_size >= self.max_cache_size
    }

    /// Get the current number of cached entries.
    pub fn len(&self) -> usize {
        self.cache_size
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache_size == 0
    }

    /// Get all modified entries for flushing to database.
    /// Returns entries and clears the cache.
    ///
    /// The returned map contains:
    /// - `Some(CoinEntry)` for UTXOs that should be added/updated
    /// - `None` for UTXOs that should be deleted
    pub fn drain_for_flush(&mut self) -> HashMap<OutPoint, Option<CoinEntry>> {
        self.cache_size = 0;
        std::mem::take(&mut self.cache)
    }

    /// Clear the cache without flushing.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.cache_size = 0;
    }
}

impl<F> UtxoView for UtxoCache<F>
where
    F: Fn(&OutPoint) -> Option<CoinEntry> + Send,
{
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<CoinEntry> {
        // Check cache first
        if let Some(entry) = self.cache.get(outpoint) {
            return entry.clone();
        }
        // Fall back to database
        (self.db_lookup)(outpoint)
    }

    fn add_utxo(&mut self, outpoint: &OutPoint, coin: CoinEntry) {
        let was_absent = self.cache.insert(outpoint.clone(), Some(coin)).is_none();
        if was_absent {
            self.cache_size += 1;
        }
    }

    fn spend_utxo(&mut self, outpoint: &OutPoint) {
        let was_absent = self.cache.insert(outpoint.clone(), None).is_none();
        if was_absent {
            self.cache_size += 1;
        }
    }
}

// ============================================================
// CHAIN STATE
// ============================================================

/// The active chain state, tracking the best chain and managing reorganizations.
///
/// ChainState manages:
/// - The current chain tip (hash and height)
/// - Processing new blocks (extending the chain)
/// - Chain reorganizations (disconnecting old blocks, connecting new blocks)
/// - Median-time-past computation
pub struct ChainState {
    /// The hash of the current chain tip.
    tip_hash: Hash256,
    /// The height of the current chain tip.
    tip_height: u32,
    /// Chain parameters.
    params: ChainParams,
    /// Cached median-time-past for recent blocks.
    mtp_cache: HashMap<Hash256, u32>,
}

impl ChainState {
    /// Create a new ChainState.
    ///
    /// # Arguments
    /// * `tip_hash` - Hash of the current chain tip (genesis hash if starting fresh).
    /// * `tip_height` - Height of the current chain tip (0 for genesis).
    /// * `params` - Chain parameters.
    pub fn new(tip_hash: Hash256, tip_height: u32, params: ChainParams) -> Self {
        Self {
            tip_hash,
            tip_height,
            params,
            mtp_cache: HashMap::new(),
        }
    }

    /// Get the current tip hash.
    pub fn tip_hash(&self) -> Hash256 {
        self.tip_hash
    }

    /// Get the current tip height.
    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }

    /// Get a reference to the chain parameters.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// Process a new block, extending the active chain.
    ///
    /// Steps:
    /// 1. Verify the block's prev_hash matches our current tip
    /// 2. Run context-free validation (check_block)
    /// 3. Connect the block (connect_block) — validates scripts, updates UTXOs
    /// 4. Update chain tip metadata
    ///
    /// Returns the fees collected in the block and the undo data.
    ///
    /// # Errors
    /// Returns `ValidationError` if:
    /// - The block doesn't extend our chain (prev_hash mismatch)
    /// - The block fails context-free validation
    /// - The block fails script verification
    /// - The block subsidy is invalid
    pub fn process_block<U: UtxoView>(
        &mut self,
        block: &Block,
        utxo_cache: &mut U,
    ) -> Result<(UndoData, u64), ValidationError> {
        let hash = block.block_hash();
        let new_height = self.tip_height + 1;

        // Verify it extends our chain
        if block.header.prev_block_hash != self.tip_hash {
            // This might be a block on a fork — requires reorganization
            return Err(ValidationError::PrevBlockNotFound(
                block.header.prev_block_hash.to_hex(),
            ));
        }

        // Context-free validation
        check_block(block, &self.params)?;

        // Connect block (validates scripts and updates UTXOs)
        let (undo_data, fees) = connect_block(block, new_height, utxo_cache, &self.params)?;

        // Update tip
        self.tip_hash = hash;
        self.tip_height = new_height;

        // Invalidate MTP cache for blocks that might be affected
        self.mtp_cache.clear();

        tracing::info!(
            "Connected block {} at height {} ({} txs, {} satoshi fees)",
            hash,
            new_height,
            block.transactions.len(),
            fees
        );

        Ok((undo_data, fees))
    }

    /// Perform a chain reorganization.
    ///
    /// Steps:
    /// 1. Find the common ancestor between the current chain and the new chain
    /// 2. Disconnect blocks from the current tip back to the common ancestor
    /// 3. Connect blocks from the common ancestor to the new tip
    ///
    /// # Arguments
    /// * `new_tip_hash` - Hash of the new chain tip
    /// * `get_block` - Closure to retrieve block data by hash
    /// * `get_undo` - Closure to retrieve undo data by block hash
    /// * `get_block_index` - Closure to retrieve block index entry by hash
    /// * `utxo_cache` - UTXO view to update
    ///
    /// # Returns
    /// - On success: `Ok((disconnected_blocks, connected_blocks))` — the number of
    ///   blocks disconnected and connected.
    /// - On error: `ValidationError` if reorganization fails.
    pub fn reorganize<U, FB, FU, FI>(
        &mut self,
        new_tip_hash: Hash256,
        get_block: &FB,
        get_undo: &FU,
        get_block_index: &FI,
        utxo_cache: &mut U,
    ) -> Result<(usize, usize), ValidationError>
    where
        U: UtxoView,
        FB: Fn(&Hash256) -> Option<Block>,
        FU: Fn(&Hash256) -> Option<UndoData>,
        FI: Fn(&Hash256) -> Option<BlockIndexEntry>,
    {
        // Find the fork point
        let mut old_chain: Vec<Hash256> = Vec::new();
        let mut new_chain: Vec<Hash256> = Vec::new();

        let mut old_hash = self.tip_hash;
        let mut new_hash = new_tip_hash;

        // Walk both chains back to a common ancestor
        loop {
            if old_hash == new_hash {
                break; // Found common ancestor
            }

            let old_entry = get_block_index(&old_hash);
            let new_entry = get_block_index(&new_hash);

            match (old_entry, new_entry) {
                (Some(old_e), Some(new_e)) => {
                    if old_e.height >= new_e.height {
                        old_chain.push(old_hash);
                        old_hash = old_e.prev_hash;
                    }
                    if new_e.height >= old_e.height {
                        new_chain.push(new_hash);
                        new_hash = new_e.prev_hash;
                    }
                }
                (Some(_old_e), None) => {
                    // New chain block not found — error
                    return Err(ValidationError::PrevBlockNotFound(new_hash.to_hex()));
                }
                (None, Some(_)) => {
                    // Old chain block not found — error
                    return Err(ValidationError::PrevBlockNotFound(old_hash.to_hex()));
                }
                (None, None) => {
                    // Both blocks not found — error
                    return Err(ValidationError::InvalidChain);
                }
            }
        }

        tracing::info!(
            "Reorganizing: disconnecting {} blocks, connecting {} blocks",
            old_chain.len(),
            new_chain.len()
        );

        // Disconnect old blocks (tip to fork point)
        for hash in &old_chain {
            let block = get_block(hash).ok_or_else(|| {
                ValidationError::PrevBlockNotFound(format!("missing block for disconnect: {}", hash))
            })?;
            let undo = get_undo(hash).ok_or_else(|| {
                ValidationError::PrevBlockNotFound(format!("missing undo data for: {}", hash))
            })?;
            disconnect_block(&block, &undo, utxo_cache)?;
            self.tip_height -= 1;
        }

        // Update tip to fork point
        self.tip_hash = old_hash;

        // Connect new blocks (fork point to new tip)
        new_chain.reverse(); // Connect in ascending order
        for hash in &new_chain {
            let block = get_block(hash).ok_or_else(|| {
                ValidationError::PrevBlockNotFound(format!("missing block for connect: {}", hash))
            })?;
            let new_height = self.tip_height + 1;
            check_block(&block, &self.params)?;
            let (_undo, _fees) = connect_block(&block, new_height, utxo_cache, &self.params)?;
            self.tip_hash = *hash;
            self.tip_height = new_height;
        }

        // Clear MTP cache after reorg
        self.mtp_cache.clear();

        Ok((old_chain.len(), new_chain.len()))
    }

    /// Compute the median time past (MTP) for a block.
    ///
    /// MTP is the median of the timestamps of the previous 11 blocks.
    /// This provides a monotonically increasing time that prevents miners
    /// from using timestamps too far in the past.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block to compute MTP for (uses previous 11 blocks)
    /// * `get_header` - Closure to retrieve block headers by hash
    pub fn compute_mtp<F>(&mut self, block_hash: &Hash256, get_header: &F) -> u32
    where
        F: Fn(&Hash256) -> Option<BlockHeader>,
    {
        // Check cache first
        if let Some(&mtp) = self.mtp_cache.get(block_hash) {
            return mtp;
        }

        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
        let mut current = *block_hash;

        for _ in 0..MEDIAN_TIME_PAST_WINDOW {
            if let Some(header) = get_header(&current) {
                timestamps.push(header.timestamp);
                current = header.prev_block_hash;
            } else {
                break;
            }
        }

        if timestamps.is_empty() {
            return 0;
        }

        timestamps.sort_unstable();
        let mtp = timestamps[timestamps.len() / 2];

        // Cache the result
        self.mtp_cache.insert(*block_hash, mtp);

        mtp
    }

    /// Clear the MTP cache.
    pub fn clear_mtp_cache(&mut self) {
        self.mtp_cache.clear();
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ChainParams;
    use rustoshi_primitives::OutPoint;

    // Helper to create a simple UTXO cache with no database backing
    fn empty_cache() -> UtxoCache<impl Fn(&OutPoint) -> Option<CoinEntry> + Send> {
        UtxoCache::new(|_| None, 1000)
    }

    // Helper to create a UTXO cache with predefined entries
    fn cache_with_entries(
        entries: HashMap<OutPoint, CoinEntry>,
    ) -> UtxoCache<impl Fn(&OutPoint) -> Option<CoinEntry> + Send> {
        UtxoCache::new(move |outpoint| entries.get(outpoint).cloned(), 1000)
    }

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0] = txid_byte;
        OutPoint {
            txid: Hash256::from_bytes(bytes),
            vout,
        }
    }

    fn make_coin(height: u32, value: u64) -> CoinEntry {
        CoinEntry {
            height,
            is_coinbase: false,
            value,
            script_pubkey: vec![0x51], // OP_1
        }
    }

    // =========================
    // UtxoCache tests
    // =========================

    #[test]
    fn utxo_cache_add_and_retrieve() {
        let mut cache = empty_cache();
        let outpoint = make_outpoint(1, 0);
        let coin = make_coin(100, 50_000_000);

        cache.add_utxo(&outpoint, coin.clone());

        let retrieved = cache.get_utxo(&outpoint);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.height, 100);
        assert_eq!(retrieved.value, 50_000_000);
    }

    #[test]
    fn utxo_cache_spend_returns_none() {
        let mut cache = empty_cache();
        let outpoint = make_outpoint(1, 0);
        let coin = make_coin(100, 50_000_000);

        cache.add_utxo(&outpoint, coin);
        cache.spend_utxo(&outpoint);

        let retrieved = cache.get_utxo(&outpoint);
        assert!(retrieved.is_none(), "Spent UTXO should return None");
    }

    #[test]
    fn utxo_cache_fallback_to_db() {
        let outpoint = make_outpoint(1, 0);
        let coin = make_coin(100, 50_000_000);

        let mut db_entries = HashMap::new();
        db_entries.insert(outpoint.clone(), coin.clone());

        let cache = cache_with_entries(db_entries);

        // Should find it in the "database"
        let retrieved = cache.get_utxo(&outpoint);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, 50_000_000);
    }

    #[test]
    fn utxo_cache_cache_overrides_db() {
        let outpoint = make_outpoint(1, 0);
        let db_coin = make_coin(100, 50_000_000);
        let cache_coin = make_coin(200, 100_000_000);

        let mut db_entries = HashMap::new();
        db_entries.insert(outpoint.clone(), db_coin);

        let mut cache = cache_with_entries(db_entries);
        cache.add_utxo(&outpoint, cache_coin);

        // Cache should take precedence
        let retrieved = cache.get_utxo(&outpoint).unwrap();
        assert_eq!(retrieved.value, 100_000_000);
        assert_eq!(retrieved.height, 200);
    }

    #[test]
    fn utxo_cache_drain_returns_all_modifications() {
        let mut cache = empty_cache();

        let outpoint1 = make_outpoint(1, 0);
        let outpoint2 = make_outpoint(2, 0);
        let outpoint3 = make_outpoint(3, 0);
        let coin1 = make_coin(100, 50_000_000);
        let coin2 = make_coin(101, 60_000_000);

        cache.add_utxo(&outpoint1, coin1);
        cache.add_utxo(&outpoint2, coin2);
        cache.spend_utxo(&outpoint3);

        assert_eq!(cache.len(), 3);

        let drained = cache.drain_for_flush();

        assert_eq!(drained.len(), 3);
        assert!(drained.get(&outpoint1).unwrap().is_some());
        assert!(drained.get(&outpoint2).unwrap().is_some());
        assert!(drained.get(&outpoint3).unwrap().is_none()); // Deleted

        // Cache should be empty after drain
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn utxo_cache_needs_flush() {
        let mut cache = UtxoCache::new(|_| None, 3);

        assert!(!cache.needs_flush());

        cache.add_utxo(&make_outpoint(1, 0), make_coin(1, 100));
        cache.add_utxo(&make_outpoint(2, 0), make_coin(2, 200));
        assert!(!cache.needs_flush());

        cache.add_utxo(&make_outpoint(3, 0), make_coin(3, 300));
        assert!(cache.needs_flush());
    }

    #[test]
    fn utxo_cache_overwrite_updates_not_increments() {
        let mut cache = empty_cache();
        let outpoint = make_outpoint(1, 0);

        cache.add_utxo(&outpoint, make_coin(1, 100));
        assert_eq!(cache.len(), 1);

        // Overwriting should not increment count
        cache.add_utxo(&outpoint, make_coin(2, 200));
        assert_eq!(cache.len(), 1);
    }

    // =========================
    // ChainState tests
    // =========================

    #[test]
    fn chain_state_initial_tip() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let state = ChainState::new(genesis_hash, 0, params);

        assert_eq!(state.tip_hash(), genesis_hash);
        assert_eq!(state.tip_height(), 0);
    }

    #[test]
    fn chain_state_process_block_rejects_wrong_prev_hash() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let mut state = ChainState::new(genesis_hash, 0, params);

        // Create a block that doesn't extend our chain
        let wrong_prev = Hash256::from_bytes([0xff; 32]);
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: wrong_prev,
                merkle_root: Hash256::ZERO,
                timestamp: 1,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![],
        };

        let mut cache = empty_cache();
        let result = state.process_block(&block, &mut cache);

        assert!(result.is_err());
        match result {
            Err(ValidationError::PrevBlockNotFound(_)) => {}
            _ => panic!("Expected PrevBlockNotFound error"),
        }
    }

    // =========================
    // MTP computation tests
    // =========================

    #[test]
    fn mtp_with_11_blocks() {
        let params = ChainParams::regtest();
        let mut state = ChainState::new(params.genesis_hash, 0, params);

        // Create headers with known timestamps
        let timestamps: Vec<u32> = vec![100, 200, 300, 150, 250, 350, 400, 180, 220, 280, 320];
        // Sorted: 100, 150, 180, 200, 220, 250, 280, 300, 320, 350, 400
        // Median (index 5): 250

        let mut headers: HashMap<Hash256, BlockHeader> = HashMap::new();
        let mut prev_hash = Hash256::ZERO;

        for (i, &ts) in timestamps.iter().enumerate() {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0] = (i + 1) as u8;
            let hash = Hash256::from_bytes(hash_bytes);

            headers.insert(
                hash,
                BlockHeader {
                    version: 1,
                    prev_block_hash: prev_hash,
                    merkle_root: Hash256::ZERO,
                    timestamp: ts,
                    bits: 0x207fffff,
                    nonce: 0,
                },
            );
            prev_hash = hash;
        }

        let tip_hash = prev_hash;
        let get_header = |h: &Hash256| headers.get(h).cloned();

        let mtp = state.compute_mtp(&tip_hash, &get_header);
        assert_eq!(mtp, 250);
    }

    #[test]
    fn mtp_with_fewer_than_11_blocks() {
        let params = ChainParams::regtest();
        let mut state = ChainState::new(params.genesis_hash, 0, params);

        // Create only 5 headers
        let timestamps: Vec<u32> = vec![100, 200, 300, 150, 250];
        // Sorted: 100, 150, 200, 250, 300
        // Median (index 2): 200

        let mut headers: HashMap<Hash256, BlockHeader> = HashMap::new();
        let mut prev_hash = Hash256::ZERO;

        for (i, &ts) in timestamps.iter().enumerate() {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0] = (i + 1) as u8;
            let hash = Hash256::from_bytes(hash_bytes);

            headers.insert(
                hash,
                BlockHeader {
                    version: 1,
                    prev_block_hash: prev_hash,
                    merkle_root: Hash256::ZERO,
                    timestamp: ts,
                    bits: 0x207fffff,
                    nonce: 0,
                },
            );
            prev_hash = hash;
        }

        let tip_hash = prev_hash;
        let get_header = |h: &Hash256| headers.get(h).cloned();

        let mtp = state.compute_mtp(&tip_hash, &get_header);
        assert_eq!(mtp, 200);
    }

    #[test]
    fn mtp_genesis_block() {
        let params = ChainParams::regtest();
        let mut state = ChainState::new(params.genesis_hash, 0, params);

        // Genesis block has no previous blocks
        let genesis = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1296688602,
            bits: 0x207fffff,
            nonce: 2,
        };

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 1;
        let genesis_hash = Hash256::from_bytes(hash_bytes);

        let headers: HashMap<Hash256, BlockHeader> =
            [(genesis_hash, genesis)].into_iter().collect();

        let get_header = |h: &Hash256| headers.get(h).cloned();

        // MTP of a single block is just its timestamp
        let mtp = state.compute_mtp(&genesis_hash, &get_header);
        assert_eq!(mtp, 1296688602);
    }

    #[test]
    fn mtp_caching_works() {
        let params = ChainParams::regtest();
        let mut state = ChainState::new(params.genesis_hash, 0, params);

        let genesis = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1000,
            bits: 0x207fffff,
            nonce: 0,
        };

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 1;
        let genesis_hash = Hash256::from_bytes(hash_bytes);

        let headers: HashMap<Hash256, BlockHeader> =
            [(genesis_hash, genesis)].into_iter().collect();

        let get_header = |h: &Hash256| headers.get(h).cloned();

        // First call computes and caches
        let mtp1 = state.compute_mtp(&genesis_hash, &get_header);
        assert_eq!(mtp1, 1000);

        // Second call should use cache
        let mtp2 = state.compute_mtp(&genesis_hash, &get_header);
        assert_eq!(mtp2, 1000);

        // Clear cache
        state.clear_mtp_cache();

        // Should recompute
        let mtp3 = state.compute_mtp(&genesis_hash, &get_header);
        assert_eq!(mtp3, 1000);
    }

    // =========================
    // Reorganization tests
    // =========================

    #[test]
    fn reorganize_finds_fork_point() {
        // This test verifies the fork-finding logic without full block validation
        // by mocking the block index entries

        let params = ChainParams::regtest();

        // Build a chain: G -> A -> B (old chain)
        //                    \-> C -> D (new chain)

        let genesis_hash = Hash256::from_bytes([0u8; 32]);
        let hash_a = Hash256::from_bytes([1u8; 32]);
        let hash_b = Hash256::from_bytes([2u8; 32]);
        let hash_c = Hash256::from_bytes([3u8; 32]);
        let hash_d = Hash256::from_bytes([4u8; 32]);

        let mut index: HashMap<Hash256, BlockIndexEntry> = HashMap::new();
        index.insert(
            genesis_hash,
            BlockIndexEntry {
                height: 0,
                prev_hash: Hash256::ZERO,
                timestamp: 0,
                bits: 0x207fffff,
                chain_work: [0u8; 32],
            },
        );
        index.insert(
            hash_a,
            BlockIndexEntry {
                height: 1,
                prev_hash: genesis_hash,
                timestamp: 1,
                bits: 0x207fffff,
                chain_work: [0u8; 32],
            },
        );
        index.insert(
            hash_b,
            BlockIndexEntry {
                height: 2,
                prev_hash: hash_a,
                timestamp: 2,
                bits: 0x207fffff,
                chain_work: [0u8; 32],
            },
        );
        index.insert(
            hash_c,
            BlockIndexEntry {
                height: 2,
                prev_hash: hash_a,
                timestamp: 3,
                bits: 0x207fffff,
                chain_work: [0u8; 32],
            },
        );
        index.insert(
            hash_d,
            BlockIndexEntry {
                height: 3,
                prev_hash: hash_c,
                timestamp: 4,
                bits: 0x207fffff,
                chain_work: [0u8; 32],
            },
        );

        // Current chain is at B (height 2)
        let mut state = ChainState::new(hash_b, 2, params);

        // We'll get an error because we don't have full blocks/undo data,
        // but we can test that the fork-finding logic would have worked
        // by examining the error message

        let get_block_index = |h: &Hash256| index.get(h).cloned();
        let get_block = |_: &Hash256| -> Option<Block> { None };
        let get_undo = |_: &Hash256| -> Option<UndoData> { None };

        let mut cache = empty_cache();
        let result = state.reorganize(hash_d, &get_block, &get_undo, &get_block_index, &mut cache);

        // Should fail because we don't have block data, but should have found
        // that it needs to disconnect 1 block (B) and connect 2 blocks (C, D)
        assert!(result.is_err());
        match result {
            Err(ValidationError::PrevBlockNotFound(msg)) => {
                // Expected - we don't have actual block data
                assert!(msg.contains("disconnect") || msg.contains(&hash_b.to_hex()));
            }
            _ => panic!("Expected PrevBlockNotFound for missing block data"),
        }
    }

    #[test]
    fn block_index_entry_fields() {
        let entry = BlockIndexEntry {
            height: 500_000,
            prev_hash: Hash256::from_bytes([1u8; 32]),
            timestamp: 1600000000,
            bits: 0x1d00ffff,
            chain_work: [0xff; 32],
        };

        assert_eq!(entry.height, 500_000);
        assert_eq!(entry.timestamp, 1600000000);
        assert_eq!(entry.bits, 0x1d00ffff);
    }
}
