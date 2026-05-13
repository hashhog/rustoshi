//! Signature verification cache.
//!
//! This module provides a thread-safe cache for script verification results,
//! avoiding redundant verification for transactions that have already been
//! validated (e.g., in the mempool before being included in a block).
//!
//! # Cache Key
//!
//! The cache key is derived as:
//!
//! ```text
//! SHA256(nonce[32] || script_sig[..] || script_pubkey[..] || witness_flat[..] || flags_le[4])
//! ```
//!
//! where `nonce` is a 256-bit random value generated at cache creation time
//! (per process, per session).  The nonce ensures that cache entries from a
//! previous process instance cannot poison the current session even if an
//! attacker can predict or influence the inputs.  Using the actual
//! cryptographic material (script_sig + script_pubkey + witness) rather than
//! the logical identity (txid + input_index) means that two inputs with the
//! same transaction identity but different signatures map to different entries.
//!
//! This mirrors Bitcoin Core's `CSignatureCache` design in
//! `bitcoin-core/src/script/sigcache.h`:
//!
//! ```c++
//! // Entries are SHA256(nonce || 'E' or 'S' || 31 zero bytes
//! //                    || signature hash || public key || signature)
//! ```
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
//! if !cache.lookup(&script_sig, &script_pubkey, &witness, flags) {
//!     // Verify script...
//!     if verification_succeeded {
//!         cache.insert(&script_sig, &script_pubkey, &witness, flags);
//!     }
//! }
//!
//! // Clear on reorg
//! cache.clear();
//! ```

use dashmap::DashMap;
use sha2::{Digest, Sha256};

/// Force sha2's lazy CPU-feature detection (CPUID probe) to run at crate
/// load time rather than on the first `Sha256::digest` call.  Without this,
/// the initialization races against Rust's test-harness I/O-capture locking
/// when multiple tests call `SigCache::new()` concurrently, causing a
/// deadlock.  Touching `SHA2_INIT` once in `SigCache::new()` is sufficient
/// because `std::sync::OnceLock` guarantees the closure runs at most once.
static SHA2_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

#[inline(always)]
fn ensure_sha2_initialized() {
    SHA2_INIT.get_or_init(|| {
        let _ = Sha256::digest(b"init");
    });
}

/// Default maximum number of cache entries.
///
/// This matches Bitcoin Core's default of approximately 50,000 entries,
/// which provides a good balance between memory usage and cache hit rate.
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;

/// Thread-safe signature/script verification cache.
///
/// This cache stores successful script verification results to avoid
/// redundant verification during block connection. It is particularly
/// useful during IBD when many transactions are verified both in mempool
/// validation and block validation.
///
/// # Cache Key Design
///
/// Keys are derived from the actual cryptographic material:
/// `SHA256(nonce || script_sig || script_pubkey || witness || flags)`.
/// A 256-bit per-session nonce prevents cross-session cache poisoning.
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
    /// Key: 32-byte SHA256 hash of (nonce||material); value: ()
    cache: DashMap<[u8; 32], ()>,
    /// Maximum number of entries before eviction.
    max_entries: usize,
    /// Per-session 256-bit random nonce.
    ///
    /// Generated at construction time from the OS CSPRNG.  Prevents an
    /// attacker who can predict input material from poisoning cache entries
    /// across process restarts or between validation contexts.
    nonce: [u8; 32],
}

impl SigCache {
    /// Create a new signature cache with the specified capacity.
    ///
    /// The per-session nonce is drawn from `OsRng` (the OS CSPRNG).
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
        use rand::RngCore;
        // Ensure sha2's CPUID probe has run before acquiring any test-harness
        // locks (pipe write, stdout capture).  Idempotent across threads.
        ensure_sha2_initialized();
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self {
            cache: DashMap::with_capacity(max_entries),
            max_entries,
            nonce,
        }
    }

    /// Derive the cache key for the given script material and flags.
    ///
    /// `SHA256(nonce[32] || script_sig[..] || script_pubkey[..] || witness_flat[..] || flags_le[4])`
    ///
    /// The first 8 bytes of the SHA256 output are used as a cheap-hash key,
    /// matching Core's `HashWriter::GetCheapHash()`.  We store the full 32
    /// bytes to eliminate false-positive collisions at the cost of a slightly
    /// larger map entry.
    #[inline]
    fn derive_key(
        &self,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[Vec<u8>],
        flags: u32,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.nonce);
        h.update(script_sig);
        h.update(script_pubkey);
        for item in witness {
            h.update(item);
        }
        h.update(flags.to_le_bytes());
        h.finalize().into()
    }

    /// Check if a verification result is cached.
    ///
    /// Returns `true` if the script verification for the given material
    /// and flags has already succeeded in this session.
    ///
    /// # Arguments
    ///
    /// * `script_sig`    - Serialized scriptSig bytes from the input
    /// * `script_pubkey` - The locking script (scriptPubKey) from the UTXO
    /// * `witness`       - Witness stack items for the input
    /// * `flags`         - Script verification flags used
    #[inline]
    pub fn lookup(
        &self,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[Vec<u8>],
        flags: u32,
    ) -> bool {
        let key = self.derive_key(script_sig, script_pubkey, witness, flags);
        self.cache.contains_key(&key)
    }

    /// Insert a successful verification result into the cache.
    ///
    /// If the cache is at capacity, entries will be evicted to make room.
    /// Only call this after a script verification succeeds.
    ///
    /// # Arguments
    ///
    /// * `script_sig`    - Serialized scriptSig bytes from the input
    /// * `script_pubkey` - The locking script (scriptPubKey) from the UTXO
    /// * `witness`       - Witness stack items for the input
    /// * `flags`         - Script verification flags used
    pub fn insert(
        &self,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[Vec<u8>],
        flags: u32,
    ) {
        // Check if we need to evict (with some slack for concurrent inserts)
        if self.cache.len() >= self.max_entries {
            self.evict_batch();
        }

        let key = self.derive_key(script_sig, script_pubkey, witness, flags);
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

    /// Minimal witness helper.
    fn no_witness() -> Vec<Vec<u8>> {
        vec![]
    }

    #[test]
    fn new_cache_is_empty() {
        let cache = SigCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn insert_and_lookup() {
        let cache = SigCache::new(100);
        let script_sig = vec![0xabu8; 72];
        let script_pubkey = vec![0x76u8; 25]; // P2PKH-like
        let witness = no_witness();
        let flags: u32 = 0x1234;

        assert!(!cache.lookup(&script_sig, &script_pubkey, &witness, flags));

        cache.insert(&script_sig, &script_pubkey, &witness, flags);

        assert!(cache.lookup(&script_sig, &script_pubkey, &witness, flags));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn different_script_sigs_are_separate() {
        let cache = SigCache::new(100);
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();
        let flags: u32 = 0x1234;

        let sig_a = vec![0xaau8; 72];
        let sig_b = vec![0xbbu8; 72];

        cache.insert(&sig_a, &script_pubkey, &witness, flags);

        assert!(cache.lookup(&sig_a, &script_pubkey, &witness, flags));
        assert!(!cache.lookup(&sig_b, &script_pubkey, &witness, flags));
    }

    #[test]
    fn different_script_pubkeys_are_separate() {
        let cache = SigCache::new(100);
        let script_sig = vec![0xabu8; 72];
        let witness = no_witness();
        let flags: u32 = 0x1234;

        let spk_a = vec![0x76u8; 25];
        let spk_b = vec![0x00u8; 22]; // P2WPKH-like

        cache.insert(&script_sig, &spk_a, &witness, flags);

        assert!(cache.lookup(&script_sig, &spk_a, &witness, flags));
        assert!(!cache.lookup(&script_sig, &spk_b, &witness, flags));
    }

    #[test]
    fn different_flags_are_separate() {
        let cache = SigCache::new(100);
        let script_sig = vec![0xabu8; 72];
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();

        cache.insert(&script_sig, &script_pubkey, &witness, 0x0001);

        assert!(cache.lookup(&script_sig, &script_pubkey, &witness, 0x0001));
        assert!(!cache.lookup(&script_sig, &script_pubkey, &witness, 0x0002));
        assert!(!cache.lookup(&script_sig, &script_pubkey, &witness, 0x0003));
    }

    #[test]
    fn different_witnesses_are_separate() {
        let cache = SigCache::new(100);
        let script_sig = vec![];
        let script_pubkey = vec![0x00u8, 0x14]; // P2WPKH prefix
        let flags: u32 = 0x1234;

        let witness_a = vec![vec![0xaau8; 72], vec![0x02u8; 33]];
        let witness_b = vec![vec![0xbbu8; 72], vec![0x02u8; 33]];

        cache.insert(&script_sig, &script_pubkey, &witness_a, flags);

        assert!(cache.lookup(&script_sig, &script_pubkey, &witness_a, flags));
        assert!(!cache.lookup(&script_sig, &script_pubkey, &witness_b, flags));
    }

    #[test]
    fn clear_removes_all_entries() {
        let cache = SigCache::new(100);

        // Insert several entries
        for i in 0u8..10 {
            let script_sig = vec![i; 72];
            let script_pubkey = vec![0x76u8; 25];
            cache.insert(&script_sig, &script_pubkey, &no_witness(), 0);
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
        for i in 0u8..(max_entries as u8 + 5) {
            let script_sig = vec![i; 72];
            let script_pubkey = vec![0x76u8; 25];
            cache.insert(&script_sig, &script_pubkey, &no_witness(), 0);
        }

        // Cache should not exceed max_entries
        assert!(cache.len() <= max_entries + 1);
    }

    #[test]
    fn default_creates_standard_cache() {
        let cache = SigCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.max_entries, DEFAULT_MAX_ENTRIES);
    }

    /// Two SigCache instances with different nonces must produce different
    /// keys for the same material — this is the anti-poisoning property.
    #[test]
    fn different_instances_have_different_nonces() {
        let cache_a = SigCache::new(100);
        let cache_b = SigCache::new(100);

        // Nonces must differ (probability of collision is 2^-256).
        assert_ne!(
            cache_a.nonce, cache_b.nonce,
            "two independent SigCache instances should not share a nonce"
        );
    }

    /// The key for the same material must be consistent within one instance.
    #[test]
    fn key_derivation_is_deterministic_within_instance() {
        let cache = SigCache::new(100);
        let script_sig = vec![0x01u8; 72];
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();
        let flags: u32 = 0xdeadbeef;

        let k1 = cache.derive_key(&script_sig, &script_pubkey, &witness, flags);
        let k2 = cache.derive_key(&script_sig, &script_pubkey, &witness, flags);
        assert_eq!(k1, k2);
    }

    /// The key must differ when only a single sig byte changes — this
    /// specifically tests that the signature bytes are part of the key.
    #[test]
    fn key_differs_on_single_sig_byte_change() {
        let cache = SigCache::new(100);
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();
        let flags: u32 = 0x0001;

        let mut sig_a = vec![0x00u8; 72];
        let mut sig_b = sig_a.clone();
        sig_b[10] = 0xff; // one byte differs

        let k_a = cache.derive_key(&sig_a, &script_pubkey, &witness, flags);
        let k_b = cache.derive_key(&sig_b, &script_pubkey, &witness, flags);
        assert_ne!(k_a, k_b);

        // Insert with sig_a — must NOT hit for sig_b.
        cache.insert(&sig_a, &script_pubkey, &witness, flags);
        assert!(cache.lookup(&sig_a, &script_pubkey, &witness, flags));
        assert!(!cache.lookup(&sig_b, &script_pubkey, &witness, flags));

        // Reset last byte on sig_a to satisfy borrow checker cleanly.
        sig_a[10] = 0x00;
        assert!(cache.lookup(&sig_a, &script_pubkey, &witness, flags));
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(SigCache::new(1000));
        let mut handles = vec![];

        // Spawn multiple threads that insert and check
        for thread_id in 0u8..4 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0u8..100 {
                    let script_sig = vec![thread_id, i];
                    let script_pubkey = vec![0x76u8; 25];
                    let witness = no_witness();
                    cache.insert(&script_sig, &script_pubkey, &witness, 0);
                    assert!(cache.lookup(&script_sig, &script_pubkey, &witness, 0));
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
