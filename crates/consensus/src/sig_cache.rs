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
//! The cache is split into up to 64 independently locked shards (a salted
//! key selects one); `lookup` takes one shard read lock and `insert` one
//! shard write lock.  No operation on the hot path touches more than one
//! shard, so rayon's script-check threads do not serialize on the cache.
//!
//! # Eviction
//!
//! Every shard has a fixed capacity (the capacities sum to exactly
//! `max_entries`) and a FIFO ring: inserting into a full shard overwrites
//! its oldest entry in O(1).  There is no global scan, no `len()` walk, and
//! no batch eviction on the insert path (see `SigCache` for the eviction
//! storm this replaced — QUEUES.md rustoshi item 0).
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

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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

/// Upper bound on the number of shards.
const MAX_SHARDS: usize = 64;
/// Target minimum entries per shard (keeps small caches single-sharded so
/// their capacity is exact and not fragmented across many tiny shards).
const MIN_ENTRIES_PER_SHARD: usize = 1024;

/// A cache key: `SHA256(nonce || material)`.
///
/// Because the key is already the output of a salted cryptographic hash
/// (the salt is a per-session secret from the OS CSPRNG), its bytes are
/// uniformly distributed and not attacker-steerable, so the hash table can
/// use 8 of those bytes directly as its hash instead of re-hashing with
/// SipHash.  Bytes 0..8 pick the shard, bytes 8..16 are the in-shard hash,
/// so the two are independent.  This is the same trick Core's CuckooCache
/// uses (`SignatureCacheHasher` reads the salted entry's words directly).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key([u8; 32]);

impl Hash for Key {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.0[8..16]);
        state.write_u64(u64::from_le_bytes(b));
    }
}

/// Pass-through hasher for [`Key`] (see there for why this is safe).
#[derive(Default)]
struct KeyHasher(u64);

impl Hasher for KeyHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Not reached for `Key` (which only calls write_u64); fold anything
        // else in so the hasher is still correct if reused.
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }
}

type KeySet = HashSet<Key, BuildHasherDefault<KeyHasher>>;

/// One shard: a hash set for O(1) membership plus a fixed-capacity FIFO
/// ring of the same keys for O(1) eviction.
///
/// Invariant: `set` and `ring` hold exactly the same keys and
/// `ring.len() <= cap`.
struct Shard {
    set: KeySet,
    ring: Vec<Key>,
    /// Next ring slot to overwrite once the ring is full (oldest entry).
    hand: usize,
    cap: usize,
}

impl Shard {
    fn new(cap: usize) -> Self {
        Self {
            set: KeySet::with_capacity_and_hasher(cap, Default::default()),
            ring: Vec::with_capacity(cap),
            hand: 0,
            cap,
        }
    }

    /// Insert `key`; returns `true` if the shard grew by one entry.
    ///
    /// When the shard is full exactly one entry — the oldest — is evicted.
    /// O(1), never scans.
    #[inline]
    fn insert(&mut self, key: Key) -> bool {
        if self.cap == 0 || self.set.contains(&key) {
            return false;
        }
        if self.ring.len() < self.cap {
            self.ring.push(key);
            self.set.insert(key);
            true
        } else {
            let victim = std::mem::replace(&mut self.ring[self.hand], key);
            self.set.remove(&victim);
            self.set.insert(key);
            self.hand += 1;
            if self.hand == self.cap {
                self.hand = 0;
            }
            false
        }
    }
}

/// Cache-line-aligned shard lock, so neighbouring shard locks taken by
/// different script-check threads do not false-share.
#[repr(align(64))]
struct PaddedShard(RwLock<Shard>);

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
/// `SHA256(nonce || wtxid || input_idx || script_sig || script_pubkey ||
/// witness || flags)`.  A 256-bit per-session nonce prevents cross-session
/// cache poisoning.  A hit therefore means that exact material verified.
///
/// # Bounded, O(1) insert (QUEUES.md rustoshi item 0)
///
/// The previous implementation (a `DashMap`) called `len()` on every insert
/// — which read-locks every shard — and, when full, had EVERY inserting
/// thread run a whole-map `retain` that evicted ~10% under shard write
/// locks.  With 16+ script-check threads on a full cache that became an
/// eviction storm (N concurrent full-map scans, each blocking the others'
/// `len()`), captured by gdb on mainnet 2026-09-26 as a ~15-minute
/// block-connection stall.
///
/// Following the design intent of Core's `CuckooCache`
/// (`bitcoin-core/src/cuckoocache.h`: fixed-size table, `insert` bounded by
/// `depth_limit`, no global scan on the hot path), this cache is:
///
/// * **Sharded, each shard with a fixed capacity** summing to exactly
///   `max_entries`, so the size can never exceed the cap — no
///   check-then-insert race.
/// * **O(1) eviction:** a full shard overwrites its oldest entry (FIFO ring).
///   Eviction happens under the one shard write lock the inserter already
///   holds, so there is at most one evictor per shard, each doing O(1) work.
///   Nothing on the insert or lookup path touches more than one shard.
/// * **O(1) `len()`:** an `AtomicUsize` maintained on insert/clear.
pub struct SigCache {
    shards: Box<[PaddedShard]>,
    /// `shards.len() - 1`; `shards.len()` is a power of two.
    shard_mask: usize,
    /// Current number of entries (O(1); maintained on insert and clear).
    count: AtomicUsize,
    /// Maximum number of entries (sum of shard capacities).
    max_entries: usize,
    /// Per-session 256-bit random nonce.
    ///
    /// Generated at construction time from the OS CSPRNG.  Prevents an
    /// attacker who can predict input material from poisoning cache entries
    /// across process restarts or between validation contexts.
    nonce: [u8; 32],
    /// Test instrumentation: number of operations that visited every shard.
    /// Only `clear()` does so; the insert/lookup path must never.
    #[cfg(test)]
    full_scans: AtomicUsize,
}

impl SigCache {
    /// Create a new signature cache with the specified capacity.
    ///
    /// The per-session nonce is drawn from `OsRng` (the OS CSPRNG).
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of entries; the cache never holds
    ///   more.  Use `DEFAULT_MAX_ENTRIES` for the recommended default (50,000).
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

        // Largest power of two <= max_entries / MIN_ENTRIES_PER_SHARD,
        // clamped to [1, MAX_SHARDS].
        let target = (max_entries / MIN_ENTRIES_PER_SHARD).max(1);
        let n_shards = (1usize << (usize::BITS - 1 - target.leading_zeros())).min(MAX_SHARDS);
        let base = max_entries / n_shards;
        let extra = max_entries % n_shards;
        let shards: Box<[PaddedShard]> = (0..n_shards)
            .map(|i| PaddedShard(RwLock::new(Shard::new(base + usize::from(i < extra)))))
            .collect();

        Self {
            shards,
            shard_mask: n_shards - 1,
            count: AtomicUsize::new(0),
            max_entries,
            nonce,
            #[cfg(test)]
            full_scans: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn shard_of(&self, key: &Key) -> &RwLock<Shard> {
        let mut b = [0u8; 8];
        b.copy_from_slice(&key.0[..8]);
        let idx = (u64::from_le_bytes(b) as usize) & self.shard_mask;
        &self.shards[idx].0
    }

    // A panic while holding a shard lock cannot leave the shard in a state
    // that yields a false positive (the set/ring update order only risks a
    // stale key being dropped early), so recover from poisoning rather than
    // cascading panics into every script-check thread.
    #[inline]
    fn read(lock: &RwLock<Shard>) -> RwLockReadGuard<'_, Shard> {
        lock.read().unwrap_or_else(|e| e.into_inner())
    }

    #[inline]
    fn write(lock: &RwLock<Shard>) -> RwLockWriteGuard<'_, Shard> {
        lock.write().unwrap_or_else(|e| e.into_inner())
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
        let key = Key(self.derive_key(wtxid, input_idx, script_sig, script_pubkey, witness, flags));
        Self::read(self.shard_of(&key)).set.contains(&key)
    }

    /// Insert a successful verification result into the cache.
    ///
    /// If the key's shard is full, its oldest entry is evicted (O(1)).
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
        // Hash outside the lock.
        let key = Key(self.derive_key(wtxid, input_idx, script_sig, script_pubkey, witness, flags));
        let mut shard = Self::write(self.shard_of(&key));
        if shard.insert(key) {
            // Bumped under the shard lock so it pairs with clear()'s
            // per-shard decrement (the counter can never transiently wrap).
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Clear all entries from the cache.
    ///
    /// This should be called during chain reorganizations to invalidate
    /// cached results that may no longer be valid on the new chain.
    /// (Visits every shard — off the hot path.)
    pub fn clear(&self) {
        #[cfg(test)]
        self.full_scans.fetch_add(1, Ordering::Relaxed);
        for shard in self.shards.iter() {
            let mut s = Self::write(&shard.0);
            let removed = s.ring.len();
            s.set.clear();
            s.ring.clear();
            s.hand = 0;
            // Decrement while still holding the shard lock so `count` never
            // under-flows relative to a concurrent insert into this shard.
            self.count.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    /// Get the current number of entries in the cache.  O(1).
    #[inline]
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Maximum number of entries the cache will hold.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    /// Check if the cache is empty.  O(1).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    fn full_scan_count(&self) -> usize {
        self.full_scans.load(Ordering::Relaxed)
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

    /// Unique per-(tag, i) wtxid so every insert is a distinct key.
    fn uniq_wtxid(tag: u8, i: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[..8].copy_from_slice(&i.to_le_bytes());
        w[8] = tag;
        w
    }

    /// QUEUES.md rustoshi item 0 (gdb wedge3 2026-09-26): with the cache
    /// full, every script-verify thread's insert ran `evict_batch()` — a
    /// whole-map `retain` under shard write locks — so N threads did N
    /// full-map scans at once (an eviction storm) and block connection
    /// stalled for ~15 min.  Invariants pinned here, on a full cache with
    /// 16 concurrent inserters:
    ///   * the insert path performs ZERO whole-map scans;
    ///   * the size never exceeds `max_entries` (observed during AND after);
    ///   * the cache stays full (eviction does not collapse occupancy);
    ///   * wall time is bounded (very generous: the box may be loaded).
    #[test]
    fn concurrent_full_cache_insert_no_eviction_storm() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        use std::time::{Duration, Instant};

        const CAP: usize = 100_000;
        const THREADS: usize = 16;
        const PER_THREAD: u64 = 20_000;

        let cache = Arc::new(SigCache::new(CAP));
        let spk = vec![0x76u8; 25];
        for i in 0..CAP as u64 {
            cache.insert(&uniq_wtxid(0, i), 0, &[], &spk, &[], 0);
        }
        assert!(
            cache.len() <= CAP,
            "fill overshot: {} > {}",
            cache.len(),
            CAP
        );

        let scans_before = cache.full_scan_count();
        let max_seen = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let start = Instant::now();
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let cache = Arc::clone(&cache);
                let max_seen = Arc::clone(&max_seen);
                let barrier = Arc::clone(&barrier);
                let spk = spk.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for i in 0..PER_THREAD {
                        let wt = uniq_wtxid(t as u8 + 1, i);
                        cache.insert(&wt, 0, &[], &spk, &[], 0);
                        if i % 64 == 0 {
                            max_seen.fetch_max(cache.len(), Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let elapsed = start.elapsed();
        let scans = cache.full_scan_count() - scans_before;
        let max_seen = max_seen.load(Ordering::Relaxed).max(cache.len());
        eprintln!(
            "eviction-storm test: {} inserts by {} threads in {:?}; whole-map scans={}, \
             max observed len={}, final len={}, cap={}",
            THREADS as u64 * PER_THREAD,
            THREADS,
            elapsed,
            scans,
            max_seen,
            cache.len(),
            CAP
        );

        assert_eq!(
            scans, 0,
            "insert path performed {scans} whole-map scans on a full cache (eviction storm)"
        );
        assert!(max_seen <= CAP, "cache size {max_seen} exceeded cap {CAP}");
        assert!(
            cache.len() >= CAP * 9 / 10,
            "occupancy collapsed to {} of {} (over-eviction)",
            cache.len(),
            CAP
        );
        assert!(
            elapsed < Duration::from_secs(60),
            "16-thread insert took {elapsed:?}"
        );
    }

    /// Microbenchmark (not a gate): 16 threads insert 2M distinct entries
    /// into a 100k-cap cache.  Run with:
    ///   cargo test --release -p rustoshi-consensus --lib \
    ///     sig_cache::tests::bench_16_threads_2m_inserts_100k_cap -- --ignored --nocapture
    #[test]
    #[ignore = "microbenchmark; run explicitly with --ignored --nocapture"]
    fn bench_16_threads_2m_inserts_100k_cap() {
        use std::sync::{Arc, Barrier};
        use std::time::Instant;

        const CAP: usize = 100_000;
        const THREADS: usize = 16;
        const TOTAL: u64 = 2_000_000;
        let per_thread = TOTAL / THREADS as u64;
        let spk = vec![0x76u8; 25];

        for round in 0..3 {
            let cache = Arc::new(SigCache::new(CAP));
            let barrier = Arc::new(Barrier::new(THREADS + 1));
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let cache = Arc::clone(&cache);
                    let barrier = Arc::clone(&barrier);
                    let spk = spk.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        for i in 0..per_thread {
                            cache.insert(&uniq_wtxid(t as u8 + 1, i), 0, &[], &spk, &[], 0);
                        }
                    })
                })
                .collect();
            barrier.wait();
            let start = Instant::now();
            for h in handles {
                h.join().unwrap();
            }
            let secs = start.elapsed().as_secs_f64();
            eprintln!(
                "BENCH round {round}: {TOTAL} inserts / {THREADS} threads / cap {CAP}: \
                 {secs:.3}s = {:.0} inserts/s; whole-map scans={}; final len={}",
                TOTAL as f64 / secs,
                cache.full_scan_count(),
                cache.len()
            );
        }
    }

    /// Shard capacities sum to exactly `max_entries` (so the hard cap is
    /// exact), and the shard count is a power of two in [1, 64].
    #[test]
    fn shard_capacities_sum_to_max() {
        for &cap in &[
            0usize, 1, 10, 1000, 2047, 50_000, 100_000, 100_003, 10_000_000,
        ] {
            let c = SigCache::new(cap);
            let n = c.shards.len();
            assert!(
                n.is_power_of_two() && n <= MAX_SHARDS,
                "cap {cap}: {n} shards"
            );
            assert_eq!(c.shard_mask, n - 1);
            let sum: usize = c.shards.iter().map(|s| s.0.read().unwrap().cap).sum();
            assert_eq!(sum, cap, "shard caps must sum to max_entries");
        }
    }

    /// Below capacity nothing is evicted, even across many shards; at and
    /// beyond capacity the size is exactly the cap and the newest entries
    /// are retained (FIFO evicts the oldest).
    #[test]
    fn sharded_fifo_keeps_recent_and_exact_cap() {
        const CAP: usize = 100_000;
        let cache = SigCache::new(CAP);
        assert!(cache.shards.len() > 1);
        let spk = vec![0x76u8; 25];
        for i in 0..(CAP / 2) as u64 {
            cache.insert(&uniq_wtxid(1, i), 0, &[], &spk, &[], 0);
        }
        assert_eq!(cache.len(), CAP / 2);
        for i in 0..(CAP / 2) as u64 {
            assert!(cache.lookup(&uniq_wtxid(1, i), 0, &[], &spk, &[], 0));
        }
        // Re-inserting an existing key does not grow the cache.
        cache.insert(&uniq_wtxid(1, 0), 0, &[], &spk, &[], 0);
        assert_eq!(cache.len(), CAP / 2);
        // Overfill 3x.
        for i in 0..(3 * CAP) as u64 {
            cache.insert(&uniq_wtxid(2, i), 0, &[], &spk, &[], 0);
            assert!(cache.len() <= CAP);
        }
        assert_eq!(cache.len(), CAP);
        let per_shard: usize = cache
            .shards
            .iter()
            .map(|s| s.0.read().unwrap().set.len())
            .sum();
        assert_eq!(per_shard, CAP, "atomic count must match the real contents");
        // The very last insert is always present; the very first are gone.
        assert!(cache.lookup(&uniq_wtxid(2, 3 * CAP as u64 - 1), 0, &[], &spk, &[], 0));
        let old_hits = (0..(CAP / 2) as u64)
            .filter(|&i| cache.lookup(&uniq_wtxid(1, i), 0, &[], &spk, &[], 0))
            .count();
        assert_eq!(old_hits, 0, "oldest entries must have been evicted");
        cache.clear();
        assert!(cache.is_empty());
        for i in 0..100u64 {
            assert!(!cache.lookup(&uniq_wtxid(2, 3 * CAP as u64 - 1 - i), 0, &[], &spk, &[], 0));
        }
    }

    /// Zero-capacity cache never caches (and never panics).
    #[test]
    fn zero_capacity_never_caches() {
        let cache = SigCache::new(0);
        cache.insert(&wtxid(1), 0, &[1], &[2], &[], 0);
        assert!(!cache.lookup(&wtxid(1), 0, &[1], &[2], &[], 0));
        assert!(cache.is_empty());
    }

    /// Instrument check for `concurrent_full_cache_insert_no_eviction_storm`:
    /// the scan counter DOES move when an all-shard operation runs, so a
    /// zero reading in that test is a measurement, not a dead counter.
    #[test]
    fn full_scan_counter_sees_all_shard_ops() {
        let cache = SigCache::new(100_000);
        assert_eq!(cache.full_scan_count(), 0);
        cache.insert(&wtxid(1), 0, &[], &[], &[], 0);
        assert_eq!(cache.full_scan_count(), 0);
        cache.clear();
        assert_eq!(cache.full_scan_count(), 1);
    }
}
