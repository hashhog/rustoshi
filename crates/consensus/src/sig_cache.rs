//! Signature verification cache.
//!
//! This module provides a thread-safe cache for script verification results,
//! avoiding redundant verification for transactions that have already been
//! validated (e.g., in the mempool before being included in a block).
//!
//! # Cache Key
//!
//! The cache key includes:
//! - `txid`: The transaction ID (32 bytes)
//! - `input_index`: The input being verified (4 bytes)
//! - `flags`: The verification flags used (4 bytes)
//!
//! Including flags ensures that stricter verification doesn't satisfy looser
//! checks and vice versa.
//!
//! # Thread Safety
//!
//! The cache uses `DashMap` for lock-free concurrent reads, which matches
//! well with rayon's parallel iteration during script validation.
//!
//! # Eviction
//!
//! When the cache reaches capacity, random eviction is used to make room
//! for new entries. This is simple and effective for a cache that will
//! typically have high hit rates during normal operation.
//!
//! # Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use rustoshi_consensus::sig_cache::SigCache;
//!
//! let cache = Arc::new(SigCache::new(50_000));
//!
//! // Check cache before verification
//! if !cache.contains(&txid, input_idx, flags) {
//!     // Verify script...
//!     if verification_succeeded {
//!         cache.insert(&txid, input_idx, flags);
//!     }
//! }
//!
//! // Clear on reorg
//! cache.clear();
//! ```

use dashmap::DashMap;
use std::hash::{Hash, Hasher};

/// Default maximum number of cache entries.
///
/// This matches Bitcoin Core's default of approximately 50,000 entries,
/// which provides a good balance between memory usage and cache hit rate.
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;

/// Cache key for script verification results.
///
/// The key uniquely identifies a script verification by combining:
/// - The transaction ID
/// - The input index within that transaction
/// - The verification flags used
///
/// This ensures that different flag combinations are cached separately,
/// preventing stricter verification from satisfying looser checks.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CacheKey {
    /// Transaction ID (SHA256d of the transaction without witness)
    txid: [u8; 32],
    /// Index of the input being verified
    input_index: u32,
    /// Script verification flags
    flags: u32,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash all fields together
        self.txid.hash(state);
        self.input_index.hash(state);
        self.flags.hash(state);
    }
}

impl CacheKey {
    /// Create a new cache key.
    #[inline]
    pub fn new(txid: &[u8; 32], input_index: u32, flags: u32) -> Self {
        Self {
            txid: *txid,
            input_index,
            flags,
        }
    }
}

/// Thread-safe signature/script verification cache.
///
/// This cache stores successful script verification results to avoid
/// redundant verification during block connection. It is particularly
/// useful during IBD when many transactions are verified both in mempool
/// validation and block validation.
///
/// # Thread Safety
///
/// Uses `DashMap` for lock-free concurrent access, making it suitable
/// for use with rayon's parallel iteration.
///
/// # Eviction Strategy
///
/// When the cache reaches capacity, random eviction is used. This is
/// implemented by picking an arbitrary entry from the map and removing it.
/// While not optimal, this approach is simple and performs well in practice.
pub struct SigCache {
    /// The underlying concurrent hash map.
    /// We store `()` as the value since we only care about presence.
    cache: DashMap<CacheKey, ()>,
    /// Maximum number of entries before eviction.
    max_entries: usize,
}

impl SigCache {
    /// Create a new signature cache with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of entries before eviction kicks in.
    ///   Use `DEFAULT_MAX_ENTRIES` for the recommended default (50,000).
    ///
    /// # Example
    ///
    /// ```
    /// use rustoshi_consensus::sig_cache::{SigCache, DEFAULT_MAX_ENTRIES};
    ///
    /// let cache = SigCache::new(DEFAULT_MAX_ENTRIES);
    /// ```
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: DashMap::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Check if a verification result is cached.
    ///
    /// Returns `true` if the script verification for the given txid,
    /// input index, and flags has already succeeded.
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID (32 bytes)
    /// * `input_index` - Input index within the transaction
    /// * `flags` - Script verification flags used
    #[inline]
    pub fn contains(&self, txid: &[u8; 32], input_index: u32, flags: u32) -> bool {
        let key = CacheKey::new(txid, input_index, flags);
        self.cache.contains_key(&key)
    }

    /// Insert a successful verification result into the cache.
    ///
    /// If the cache is at capacity, entries will be evicted to make room.
    /// Only call this after a script verification succeeds.
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID (32 bytes)
    /// * `input_index` - Input index within the transaction
    /// * `flags` - Script verification flags used
    pub fn insert(&self, txid: &[u8; 32], input_index: u32, flags: u32) {
        // Check if we need to evict (with some slack for concurrent inserts)
        if self.cache.len() >= self.max_entries {
            self.evict_batch();
        }

        let key = CacheKey::new(txid, input_index, flags);
        self.cache.insert(key, ());
    }

    /// Clear all entries from the cache.
    ///
    /// This should be called during chain reorganizations to invalidate
    /// cached results that may no longer be valid on the new chain.
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get the current number of entries in the cache.
    #[inline]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Evict a batch of entries from the cache.
    ///
    /// Removes at least 1 entry and approximately 10% of entries overall to
    /// avoid frequent eviction overhead. Guaranteeing at least 1 removal
    /// prevents the cache from growing without bound when the probabilistic
    /// retain would otherwise evict nothing (which has ~35% probability for
    /// a cache of 10 entries).
    fn evict_batch(&self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut evicted = 0usize;
        // Keep approximately 90% of entries (evict ~10%), but always evict at least 1.
        self.cache.retain(|_, _| {
            if !rng.gen_bool(0.9) {
                evicted += 1;
                false
            } else {
                true
            }
        });
        // If probabilistic eviction removed nothing, forcibly remove one entry.
        if evicted == 0 {
            if let Some(entry) = self.cache.iter().next().map(|e| *e.key()) {
                self.cache.remove(&entry);
            }
        }
    }
}

impl Default for SigCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cache_is_empty() {
        let cache = SigCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn insert_and_contains() {
        let cache = SigCache::new(100);
        let txid = [0xab; 32];
        let input_index = 0;
        let flags = 0x1234;

        assert!(!cache.contains(&txid, input_index, flags));

        cache.insert(&txid, input_index, flags);

        assert!(cache.contains(&txid, input_index, flags));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn different_txids_are_separate() {
        let cache = SigCache::new(100);
        let txid1 = [0xaa; 32];
        let txid2 = [0xbb; 32];
        let input_index = 0;
        let flags = 0x1234;

        cache.insert(&txid1, input_index, flags);

        assert!(cache.contains(&txid1, input_index, flags));
        assert!(!cache.contains(&txid2, input_index, flags));
    }

    #[test]
    fn different_input_indices_are_separate() {
        let cache = SigCache::new(100);
        let txid = [0xab; 32];
        let flags = 0x1234;

        cache.insert(&txid, 0, flags);

        assert!(cache.contains(&txid, 0, flags));
        assert!(!cache.contains(&txid, 1, flags));
        assert!(!cache.contains(&txid, 2, flags));
    }

    #[test]
    fn different_flags_are_separate() {
        let cache = SigCache::new(100);
        let txid = [0xab; 32];
        let input_index = 0;

        cache.insert(&txid, input_index, 0x0001);

        assert!(cache.contains(&txid, input_index, 0x0001));
        assert!(!cache.contains(&txid, input_index, 0x0002));
        assert!(!cache.contains(&txid, input_index, 0x0003));
    }

    #[test]
    fn clear_removes_all_entries() {
        let cache = SigCache::new(100);

        // Insert several entries
        for i in 0..10 {
            let mut txid = [0u8; 32];
            txid[0] = i;
            cache.insert(&txid, 0, 0);
        }

        assert_eq!(cache.len(), 10);

        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn eviction_when_full() {
        let max_entries = 10;
        let cache = SigCache::new(max_entries);

        // Insert max_entries + 5 items
        for i in 0..(max_entries + 5) as u8 {
            let mut txid = [0u8; 32];
            txid[0] = i;
            cache.insert(&txid, 0, 0);
        }

        // Cache should not exceed max_entries
        // Note: Due to the race-free nature of the check, we allow some slack
        assert!(cache.len() <= max_entries + 1);
    }

    #[test]
    fn default_creates_standard_cache() {
        let cache = SigCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.max_entries, DEFAULT_MAX_ENTRIES);
    }

    #[test]
    fn cache_key_hashing_is_consistent() {
        use std::collections::hash_map::DefaultHasher;

        let txid = [0xab; 32];
        let key1 = CacheKey::new(&txid, 5, 0x1234);
        let key2 = CacheKey::new(&txid, 5, 0x1234);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();

        key1.hash(&mut hasher1);
        key2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(SigCache::new(1000));
        let mut handles = vec![];

        // Spawn multiple threads that insert and check
        for thread_id in 0..4 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let mut txid = [0u8; 32];
                    txid[0] = thread_id;
                    txid[1] = i as u8;
                    cache.insert(&txid, 0, 0);
                    assert!(cache.contains(&txid, 0, 0));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 400 entries should be present (1000 > 400)
        assert_eq!(cache.len(), 400);
    }
}
