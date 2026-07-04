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
//! SHA256(nonce[32] || wtxid[32] || input_idx_le[4]
//!        || script_sig[..] || script_pubkey[..] || witness_flat[..] || flags_le[4])
//! ```
//!
//! where `nonce` is a 256-bit random value generated at cache creation time
//! (per process, per session).  The nonce ensures that cache entries from a
//! previous process instance cannot poison the current session even if an
//! attacker can predict or influence the inputs.
//!
//! **Why wtxid + input_idx?** (W160 BUG-9 fix.)  Rustoshi caches at the
//! input/script-execution level, not at the per-signature level as Core
//! does.  Under SegWit malleability, the same `(script_sig, script_pubkey,
//! witness, flags)` tuple can legitimately appear in two distinct
//! transactions whose sighashes (and therefore signature validity) differ
//! — the sighash depends on the entire spending transaction, not just the
//! input under inspection.  Without committing to the sighash, a cache hit
//! on input A in tx X would incorrectly approve input A' in tx Y even
//! though the underlying signatures verify against a different sighash.
//!
//! Committing to the **wtxid + input_idx** binds the cache entry to the
//! exact witness-bearing transaction that produced the successful verify.
//! The wtxid is a SHA256d over the full witness serialization, so any
//! change to the spending transaction (and therefore to any input's
//! sighash, including non-`ANYONECANPAY` sighashes that hash all
//! prevouts/sequences/outputs) yields a different wtxid and therefore a
//! different cache key.  This is functionally equivalent to keying on the
//! sighash itself but avoids plumbing the sighash through every call site
//! and supports script flavors (e.g. legacy multisig) that compute
//! multiple sighashes per script execution.
//!
//! This mirrors Bitcoin Core's `CSignatureCache` design in
//! `bitcoin-core/src/script/sigcache.cpp:39-50`:
//!
//! ```c++
//! // ComputeEntryECDSA / ComputeEntrySchnorr:
//! //   SHA256(nonce_padded[64] || sighash[32] || pubkey[..] || sig[..])
//! ```
//!
//! Core's per-signature granularity is finer-grained than ours, but both
//! schemes share the load-bearing property that **the cache key commits
//! to the sighash** (directly in Core, transitively via wtxid here).
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
//! if !cache.lookup(&wtxid, input_idx, &script_sig, &script_pubkey, &witness, flags) {
//!     // Verify script...
//!     if verification_succeeded {
//!         cache.insert(&wtxid, input_idx, &script_sig, &script_pubkey, &witness, flags);
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
    /// ```text
    /// SHA256(nonce[32] || wtxid[32] || input_idx_le[4]
    ///        || script_sig[..] || script_pubkey[..] || witness_flat[..] || flags_le[4])
    /// ```
    ///
    /// The `wtxid` and `input_idx` bind the cache entry to the exact
    /// spending transaction that produced the successful verify.  Because
    /// `wtxid` is a SHA256d over the full witness-bearing serialization,
    /// any change to the spending transaction (and therefore to any
    /// input's sighash) yields a different cache key — preventing the
    /// SegWit-malleability cache-confusion described in W160 BUG-9, where
    /// the same `(script_sig, script_pubkey, witness, flags)` tuple could
    /// otherwise be reused across distinct spending transactions whose
    /// sighashes differ.
    #[inline]
    fn derive_key(
        &self,
        wtxid: &[u8; 32],
        input_idx: u32,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[Vec<u8>],
        flags: u32,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.nonce);
        h.update(wtxid);
        h.update(input_idx.to_le_bytes());
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
    /// and flags has already succeeded in this session **for this exact
    /// spending transaction and input**.
    ///
    /// # Arguments
    ///
    /// * `wtxid`         - Witness txid of the spending transaction
    /// * `input_idx`     - Index of the input being verified
    /// * `script_sig`    - Serialized scriptSig bytes from the input
    /// * `script_pubkey` - The locking script (scriptPubKey) from the UTXO
    /// * `witness`       - Witness stack items for the input
    /// * `flags`         - Script verification flags used
    #[inline]
    pub fn lookup(
        &self,
        wtxid: &[u8; 32],
        input_idx: u32,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[Vec<u8>],
        flags: u32,
    ) -> bool {
        let key = self.derive_key(wtxid, input_idx, script_sig, script_pubkey, witness, flags);
        self.cache.contains_key(&key)
    }

    /// Insert a successful verification result into the cache.
    ///
    /// If the cache is at capacity, entries will be evicted to make room.
    /// Only call this after a script verification succeeds.
    ///
    /// # Arguments
    ///
    /// * `wtxid`         - Witness txid of the spending transaction
    /// * `input_idx`     - Index of the input being verified
    /// * `script_sig`    - Serialized scriptSig bytes from the input
    /// * `script_pubkey` - The locking script (scriptPubKey) from the UTXO
    /// * `witness`       - Witness stack items for the input
    /// * `flags`         - Script verification flags used
    pub fn insert(
        &self,
        wtxid: &[u8; 32],
        input_idx: u32,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[Vec<u8>],
        flags: u32,
    ) {
        // Check if we need to evict (with some slack for concurrent inserts)
        if self.cache.len() >= self.max_entries {
            self.evict_batch();
        }

        let key = self.derive_key(wtxid, input_idx, script_sig, script_pubkey, witness, flags);
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
        //
        // NOTE: the victim key MUST be copied out into a local `let` binding
        // *before* calling `remove`.  Writing this as
        // `if let Some(k) = self.cache.iter().next().map(|e| *e.key()) { remove(k) }`
        // extends the lifetime of the temporary `Iter` (which holds a
        // shard *read* guard) across the whole `if let` block, so the
        // subsequent `remove` — which needs a *write* guard on that same
        // shard — self-deadlocks the calling thread.  Binding to a local
        // drops the `Iter` (and its read guard) at the `;`, releasing the
        // shard before `remove` runs.  This deadlock is what hung the
        // `eviction_when_full` test for 50+ minutes.
        if evicted == 0 {
            let victim = self.cache.iter().next().map(|e| *e.key());
            if let Some(key) = victim {
                self.cache.remove(&key);
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

    /// Helper: deterministic dummy wtxid built from a single seed byte.
    fn wtxid(seed: u8) -> [u8; 32] {
        [seed; 32]
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
        let wt = wtxid(0x01);

        assert!(!cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness, flags));

        cache.insert(&wt, 0, &script_sig, &script_pubkey, &witness, flags);

        assert!(cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness, flags));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn different_script_sigs_are_separate() {
        let cache = SigCache::new(100);
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();
        let flags: u32 = 0x1234;
        let wt = wtxid(0x02);

        let sig_a = vec![0xaau8; 72];
        let sig_b = vec![0xbbu8; 72];

        cache.insert(&wt, 0, &sig_a, &script_pubkey, &witness, flags);

        assert!(cache.lookup(&wt, 0, &sig_a, &script_pubkey, &witness, flags));
        assert!(!cache.lookup(&wt, 0, &sig_b, &script_pubkey, &witness, flags));
    }

    #[test]
    fn different_script_pubkeys_are_separate() {
        let cache = SigCache::new(100);
        let script_sig = vec![0xabu8; 72];
        let witness = no_witness();
        let flags: u32 = 0x1234;
        let wt = wtxid(0x03);

        let spk_a = vec![0x76u8; 25];
        let spk_b = vec![0x00u8; 22]; // P2WPKH-like

        cache.insert(&wt, 0, &script_sig, &spk_a, &witness, flags);

        assert!(cache.lookup(&wt, 0, &script_sig, &spk_a, &witness, flags));
        assert!(!cache.lookup(&wt, 0, &script_sig, &spk_b, &witness, flags));
    }

    #[test]
    fn different_flags_are_separate() {
        let cache = SigCache::new(100);
        let script_sig = vec![0xabu8; 72];
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();
        let wt = wtxid(0x04);

        cache.insert(&wt, 0, &script_sig, &script_pubkey, &witness, 0x0001);

        assert!(cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness, 0x0001));
        assert!(!cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness, 0x0002));
        assert!(!cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness, 0x0003));
    }

    #[test]
    fn different_witnesses_are_separate() {
        let cache = SigCache::new(100);
        let script_sig = vec![];
        let script_pubkey = vec![0x00u8, 0x14]; // P2WPKH prefix
        let flags: u32 = 0x1234;
        let wt = wtxid(0x05);

        let witness_a = vec![vec![0xaau8; 72], vec![0x02u8; 33]];
        let witness_b = vec![vec![0xbbu8; 72], vec![0x02u8; 33]];

        cache.insert(&wt, 0, &script_sig, &script_pubkey, &witness_a, flags);

        assert!(cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness_a, flags));
        assert!(!cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness_b, flags));
    }

    #[test]
    fn clear_removes_all_entries() {
        let cache = SigCache::new(100);

        // Insert several entries
        for i in 0u8..10 {
            let script_sig = vec![i; 72];
            let script_pubkey = vec![0x76u8; 25];
            cache.insert(&wtxid(i), 0, &script_sig, &script_pubkey, &no_witness(), 0);
        }

        assert_eq!(cache.len(), 10);

        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn eviction_when_full() {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let max_entries = 10;
        let cache = Arc::new(SigCache::new(max_entries));

        // Run the fill (which forces several eviction rounds) on a worker
        // thread so that a regression reintroducing the evict_batch deadlock
        // fails this test in bounded time instead of hanging the whole
        // `cargo test` run for 50+ minutes (as it historically did).
        let worker = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                // Insert max_entries + 5 items
                for i in 0u8..(max_entries as u8 + 5) {
                    let script_sig = vec![i; 72];
                    let script_pubkey = vec![0x76u8; 25];
                    cache.insert(&wtxid(i), 0, &script_sig, &script_pubkey, &no_witness(), 0);
                }
            })
        };

        // Bounded-time guard: eviction must be O(1)/bounded — never loop or
        // deadlock. 10s is astronomically generous for 15 tiny inserts.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !worker.is_finished() {
            assert!(
                Instant::now() < deadline,
                "sig-cache eviction hung: evict_batch deadlocked or looped (regression)"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        worker.join().unwrap();

        // Cache should not exceed max_entries (+1 slack for the forced single eviction).
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
        let wt = wtxid(0x99);

        let k1 = cache.derive_key(&wt, 0, &script_sig, &script_pubkey, &witness, flags);
        let k2 = cache.derive_key(&wt, 0, &script_sig, &script_pubkey, &witness, flags);
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
        let wt = wtxid(0x77);

        let mut sig_a = vec![0x00u8; 72];
        let mut sig_b = sig_a.clone();
        sig_b[10] = 0xff; // one byte differs

        let k_a = cache.derive_key(&wt, 0, &sig_a, &script_pubkey, &witness, flags);
        let k_b = cache.derive_key(&wt, 0, &sig_b, &script_pubkey, &witness, flags);
        assert_ne!(k_a, k_b);

        // Insert with sig_a — must NOT hit for sig_b.
        cache.insert(&wt, 0, &sig_a, &script_pubkey, &witness, flags);
        assert!(cache.lookup(&wt, 0, &sig_a, &script_pubkey, &witness, flags));
        assert!(!cache.lookup(&wt, 0, &sig_b, &script_pubkey, &witness, flags));

        // Reset last byte on sig_a to satisfy borrow checker cleanly.
        sig_a[10] = 0x00;
        assert!(cache.lookup(&wt, 0, &sig_a, &script_pubkey, &witness, flags));
    }

    /// W160 BUG-9 regression: two inputs with identical
    /// (script_sig, script_pubkey, witness, flags) but residing in
    /// transactions with different wtxids (and therefore different
    /// sighashes) must NOT share a cache entry.
    ///
    /// Without binding the cache key to the spending transaction's
    /// witness txid (or, equivalently, the sighash), a previously
    /// successful verification under sighash A would be incorrectly
    /// reused for sighash B, where the signatures do not actually
    /// verify.  Under SegWit malleability this is a consensus-divergence
    /// vector (cache poisoning across transactions).
    #[test]
    fn w160_bug9_different_wtxid_does_not_hit() {
        let cache = SigCache::new(100);
        let script_sig = vec![0xabu8; 72];
        let script_pubkey = vec![0x76u8; 25];
        let witness = no_witness();
        let flags: u32 = 0x0001;

        let wt_a = wtxid(0xAA); // spending tx A
        let wt_b = wtxid(0xBB); // spending tx B with a different sighash

        // Verify + cache for tx A, input 0.
        cache.insert(&wt_a, 0, &script_sig, &script_pubkey, &witness, flags);

        // Same material on tx A still hits — sanity.
        assert!(
            cache.lookup(&wt_a, 0, &script_sig, &script_pubkey, &witness, flags),
            "same wtxid + input must hit after insert"
        );

        // Same material on tx B (different wtxid → different sighash)
        // MUST NOT hit — this is the W160 BUG-9 fix.
        assert!(
            !cache.lookup(&wt_b, 0, &script_sig, &script_pubkey, &witness, flags),
            "different wtxid (different sighash) must NOT hit the cache — W160 BUG-9"
        );

        // Same wtxid but a different input index also must not hit
        // (because the sighash for a different input differs).
        assert!(
            !cache.lookup(&wt_a, 1, &script_sig, &script_pubkey, &witness, flags),
            "different input_idx must NOT hit the cache"
        );
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
                    let wt = wtxid(thread_id.wrapping_mul(101).wrapping_add(i));
                    cache.insert(&wt, 0, &script_sig, &script_pubkey, &witness, 0);
                    assert!(cache.lookup(&wt, 0, &script_sig, &script_pubkey, &witness, 0));
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
