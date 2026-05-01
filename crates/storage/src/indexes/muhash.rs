//! MuHash3072 implementation for UTXO set hashing.
//!
//! MuHash is a multiplicative hash that supports incremental updates:
//! - Insert(x): hash *= hash(x)
//! - Remove(x): hash /= hash(x)
//!
//! This allows efficient computation of UTXO set hashes without rehashing
//! the entire set on every block.
//!
//! # Implementation
//!
//! We use a 3072-bit prime field (2^3072 - 1103717) following Bitcoin Core.
//! Elements are hashed via SHA256 + ChaCha20 to produce 384-byte values.
//!
//! # References
//!
//! - Bitcoin Core: `src/crypto/muhash.cpp`
//! - Paper: https://cseweb.ucsd.edu/~mihir/papers/inchash.pdf

use rustoshi_primitives::Hash256;
use std::fmt;

/// The modulus is 2^3072 - 1103717, the largest 3072-bit safe prime.
const MAX_PRIME_DIFF: u64 = 1103717;

/// Number of limbs (64-bit) in a Num3072.
const LIMBS: usize = 48;

/// Byte size of a Num3072.
const BYTE_SIZE: usize = 384;

/// A 3072-bit number used in MuHash computations.
#[derive(Clone)]
pub struct Num3072 {
    /// Limbs stored in little-endian order (limbs[0] is least significant).
    limbs: [u64; LIMBS],
}

impl Default for Num3072 {
    fn default() -> Self {
        Self::one()
    }
}

impl fmt::Debug for Num3072 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Num3072({:016x}...)", self.limbs[LIMBS - 1])
    }
}

impl PartialEq for Num3072 {
    fn eq(&self, other: &Self) -> bool {
        self.limbs == other.limbs
    }
}

impl Eq for Num3072 {}

impl Num3072 {
    /// Create a new Num3072 with value 1.
    pub fn one() -> Self {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        Self { limbs }
    }

    /// Create from little-endian bytes.
    pub fn from_bytes(data: &[u8; BYTE_SIZE]) -> Self {
        let mut limbs = [0u64; LIMBS];
        for (i, chunk) in data.chunks_exact(8).enumerate() {
            limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Self { limbs }
    }

    /// Convert to little-endian bytes.
    pub fn to_bytes(&self) -> [u8; BYTE_SIZE] {
        let mut data = [0u8; BYTE_SIZE];
        for (i, &limb) in self.limbs.iter().enumerate() {
            data[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        data
    }

    /// Indicates whether `self` is `>= modulus`.  Mirrors Core's
    /// `Num3072::IsOverflow` (`bitcoin-core/src/crypto/muhash.cpp:116`).
    fn is_overflow(&self) -> bool {
        if self.limbs[0] <= u64::MAX - MAX_PRIME_DIFF {
            return false;
        }
        for i in 1..LIMBS {
            if self.limbs[i] != u64::MAX {
                return false;
            }
        }
        true
    }

    /// Reduce once by subtracting the modulus (add `MAX_PRIME_DIFF` and discard the
    /// 2^3072 carry).  Mirrors Core's `Num3072::FullReduce`.
    fn full_reduce(&mut self) {
        // c0 starts as MAX_PRIME_DIFF; for each limb add it, write low 64
        // bits, propagate the high 64 bits as the new c0.  Same semantics
        // as Core's `addnextract2` loop.
        let mut c0: u64 = MAX_PRIME_DIFF;
        let mut c1: u64 = 0;
        for i in 0..LIMBS {
            // [c0, c1] += limbs[i]
            let (s0, carry1) = c0.overflowing_add(self.limbs[i]);
            c0 = s0;
            if carry1 {
                let (s1, _) = c1.overflowing_add(1);
                c1 = s1;
            }
            // extract low limb and shift
            self.limbs[i] = c0;
            c0 = c1;
            c1 = 0;
        }
    }

    /// Schoolbook 3072x3072 -> 6144 multiply followed by Mersenne-style
    /// reduction using `2^3072 ≡ MAX_PRIME_DIFF (mod p)`.
    ///
    /// We avoid the u128-accumulator-overflow class of bugs by always
    /// keeping each cell of the work buffer ≤ 2^64-1 before any
    /// reduction-multiply step.
    pub fn multiply(&mut self, other: &Num3072) {
        // ---- Step 1: full schoolbook product into a 2*LIMBS u64 buffer. ----
        let mut prod = [0u64; LIMBS * 2];
        for i in 0..LIMBS {
            let mut carry: u128 = 0;
            for j in 0..LIMBS {
                // (a*b) + prod[i+j] + carry  fits in u128 because:
                //   a*b      <= (2^64 - 1)^2 = 2^128 - 2^65 + 1
                //   prod cell + carry         <= 2^64 - 1 + 2^64 - 1 < 2^65
                // Sum  < 2^128 — no overflow.
                let t = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + prod[i + j] as u128
                    + carry;
                prod[i + j] = t as u64;
                carry = t >> 64;
            }
            // Carry propagates into prod[i+LIMBS..].  Since the j-loop above
            // already consumed prod[i+j] up to j=LIMBS-1, the next slot is
            // prod[i+LIMBS], which has not yet been touched in this i-iter.
            prod[i + LIMBS] = carry as u64;
        }

        // ---- Step 2: fold high half into low half via 2^3072 = MAX_PRIME_DIFF. ----
        // For each upper limb at position p (p >= LIMBS), it contributes
        // `prod[p] * 2^(64*(p-LIMBS)) * MAX_PRIME_DIFF` to the low half.
        // Iterate from highest to lowest so that the multiply-add only ever
        // touches in-range positions.
        //
        // After the first fold pass the upper half can become non-zero
        // again because prod[p] * MAX_PRIME_DIFF can be up to ~2^85 which
        // can carry into prod[p+1].  We loop until clean.
        loop {
            // Does any upper limb hold non-zero data?
            let mut has_high = false;
            for p in LIMBS..(LIMBS * 2) {
                if prod[p] != 0 {
                    has_high = true;
                    break;
                }
            }
            if !has_high {
                break;
            }

            // Take the upper half into a temp and zero it out.
            let mut high = [0u64; LIMBS];
            for p in 0..LIMBS {
                high[p] = prod[LIMBS + p];
                prod[LIMBS + p] = 0;
            }

            // Add high * MAX_PRIME_DIFF into prod[0..2*LIMBS].
            let mut carry: u128 = 0;
            for p in 0..LIMBS {
                let t = (high[p] as u128) * (MAX_PRIME_DIFF as u128)
                    + prod[p] as u128
                    + carry;
                prod[p] = t as u64;
                carry = t >> 64;
            }
            // Spill remaining carry into the upper half (will be absorbed
            // by the next iteration).
            let mut p = LIMBS;
            while carry > 0 && p < LIMBS * 2 {
                let t = prod[p] as u128 + carry;
                prod[p] = t as u64;
                carry = t >> 64;
                p += 1;
            }
        }

        // ---- Step 3: write back, then reduce if still >= modulus. ----
        for i in 0..LIMBS {
            self.limbs[i] = prod[i];
        }
        // After up to two `FullReduce`s `self` is in [0, p).  In practice
        // one is almost always enough, but be conservative.
        if self.is_overflow() {
            self.full_reduce();
        }
        if self.is_overflow() {
            self.full_reduce();
        }
    }

    /// Compute the modular inverse via Fermat's little theorem: for a
    /// prime modulus `p`, `a^(p-2) ≡ a^{-1} (mod p)`.
    ///
    /// Here `p - 2 = 2^3072 - MAX_PRIME_DIFF - 2 = 2^3072 - 1103719`,
    /// which in our 48-limb LE representation is:
    ///   - limb 0      = 2^64 - 1103719
    ///   - limbs 1..47 = 2^64 - 1
    ///
    /// This is slower than Core's safegcd (which is what Core uses), but
    /// it is correct and fully self-contained.  Used only at finalize
    /// time, so the cost is paid once per UTXO-set hash, not per coin.
    pub fn inverse(&self) -> Self {
        // Build p - 2.
        let mut exp = [u64::MAX; LIMBS];
        exp[0] = u64::MAX - MAX_PRIME_DIFF - 1; // = 2^64 - 1 - 1103717 - 1

        let mut result = Num3072::one();
        let mut base = self.clone();

        // Square-and-multiply, low bit of low limb first.
        for &limb in &exp {
            let mut bits = limb;
            for _ in 0..64 {
                if bits & 1 == 1 {
                    result.multiply(&base);
                }
                let base_clone = base.clone();
                base.multiply(&base_clone);
                bits >>= 1;
            }
        }

        result
    }

    /// `self = self / other  (mod p)`.  Implemented as `self *= other^{-1}`.
    pub fn divide(&mut self, other: &Num3072) {
        // Normalize the divisor to [0, p) first, mirroring
        // `Num3072::Divide` in Core.
        let mut b = other.clone();
        if b.is_overflow() {
            b.full_reduce();
        }
        let inv = b.inverse();
        if self.is_overflow() {
            self.full_reduce();
        }
        self.multiply(&inv);
        if self.is_overflow() {
            self.full_reduce();
        }
    }
}

/// MuHash3072 accumulator for computing rolling hashes.
#[derive(Clone, Debug)]
pub struct MuHash3072 {
    /// Numerator of the accumulated hash.
    numerator: Num3072,
    /// Denominator of the accumulated hash (for lazy division).
    denominator: Num3072,
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

impl MuHash3072 {
    /// Create a new empty MuHash accumulator.
    pub fn new() -> Self {
        Self {
            numerator: Num3072::one(),
            denominator: Num3072::one(),
        }
    }

    /// Convert data to a Num3072 element using SHA256 + ChaCha20.
    fn to_num3072(data: &[u8]) -> Num3072 {
        use sha2::{Digest, Sha256};

        // Hash the data with SHA256
        let hash = Sha256::digest(data);

        // Use the hash as a ChaCha20 key to generate 384 bytes
        let mut output = [0u8; BYTE_SIZE];
        chacha20_keystream(&hash, &mut output);

        Num3072::from_bytes(&output)
    }

    /// Insert an element into the accumulator.
    pub fn insert(&mut self, data: &[u8]) {
        let elem = Self::to_num3072(data);
        self.numerator.multiply(&elem);
    }

    /// Remove an element from the accumulator.
    pub fn remove(&mut self, data: &[u8]) {
        let elem = Self::to_num3072(data);
        self.denominator.multiply(&elem);
    }

    /// Combine with another MuHash (multiply).
    pub fn combine(&mut self, other: &MuHash3072) {
        self.numerator.multiply(&other.numerator);
        self.denominator.multiply(&other.denominator);
    }

    /// Finalize and return the hash as a Hash256.
    pub fn finalize(&mut self) -> Hash256 {
        // Compute numerator / denominator
        self.numerator.divide(&self.denominator);
        self.denominator = Num3072::one();

        // Hash the result
        use sha2::{Digest, Sha256};
        let bytes = self.numerator.to_bytes();
        let hash = Sha256::digest(bytes);

        Hash256::from_bytes(hash.into())
    }

    /// Get a copy suitable for further operations without modifying this one.
    pub fn clone_for_finalize(&self) -> Self {
        self.clone()
    }

    /// Serialize the MuHash state to bytes.
    pub fn to_bytes(&self) -> [u8; BYTE_SIZE * 2] {
        let mut data = [0u8; BYTE_SIZE * 2];
        data[..BYTE_SIZE].copy_from_slice(&self.numerator.to_bytes());
        data[BYTE_SIZE..].copy_from_slice(&self.denominator.to_bytes());
        data
    }

    /// Deserialize MuHash state from bytes.
    pub fn from_bytes(data: &[u8; BYTE_SIZE * 2]) -> Self {
        let mut num_bytes = [0u8; BYTE_SIZE];
        let mut den_bytes = [0u8; BYTE_SIZE];
        num_bytes.copy_from_slice(&data[..BYTE_SIZE]);
        den_bytes.copy_from_slice(&data[BYTE_SIZE..]);

        Self {
            numerator: Num3072::from_bytes(&num_bytes),
            denominator: Num3072::from_bytes(&den_bytes),
        }
    }
}

/// Simple ChaCha20 keystream generation.
///
/// This is a simplified implementation for generating pseudo-random bytes
/// from a 32-byte key. Uses 8 rounds per block.
fn chacha20_keystream(key: &[u8], output: &mut [u8]) {
    assert!(key.len() >= 32);

    let mut state = [0u32; 16];

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    // Counter and nonce (all zeros for our use)
    state[12] = 0;
    state[13] = 0;
    state[14] = 0;
    state[15] = 0;

    let blocks_needed = output.len().div_ceil(64);
    let mut out_pos = 0;

    for block_num in 0..blocks_needed {
        state[12] = block_num as u32;

        let mut working = state;

        // 20 rounds (8 quarter-rounds per double-round, 10 double-rounds)
        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }

        // Add original state
        for i in 0..16 {
            working[i] = working[i].wrapping_add(state[i]);
        }

        // Output
        for &word in working.iter() {
            let bytes = word.to_le_bytes();
            for &b in &bytes {
                if out_pos < output.len() {
                    output[out_pos] = b;
                    out_pos += 1;
                }
            }
        }
    }
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num3072_one() {
        let one = Num3072::one();
        assert_eq!(one.limbs[0], 1);
        for i in 1..LIMBS {
            assert_eq!(one.limbs[i], 0);
        }
    }

    #[test]
    fn test_num3072_bytes_roundtrip() {
        let mut original = Num3072::one();
        original.limbs[0] = 0x123456789ABCDEF0;
        original.limbs[1] = 0xFEDCBA9876543210;

        let bytes = original.to_bytes();
        let restored = Num3072::from_bytes(&bytes);

        assert_eq!(original.limbs, restored.limbs);
    }

    #[test]
    fn test_num3072_multiply_by_one() {
        let mut a = Num3072::one();
        a.limbs[0] = 12345;

        let one = Num3072::one();
        let original = a.clone();

        a.multiply(&one);

        assert_eq!(a.limbs[0], original.limbs[0]);
    }

    #[test]
    fn test_muhash_empty() {
        let mut hash = MuHash3072::new();
        let result = hash.finalize();
        // Empty hash should produce a deterministic result
        assert_ne!(result, Hash256::ZERO);
    }

    #[test]
    fn test_muhash_insert_produces_different_hashes() {
        // Test that inserting different elements produces different hashes
        let mut hash1 = MuHash3072::new();
        hash1.insert(b"element1");

        let mut hash2 = MuHash3072::new();
        hash2.insert(b"element1");
        hash2.insert(b"element2");

        // Adding more elements should change the hash
        let result1 = hash1.clone_for_finalize().finalize();
        let result2 = hash2.clone_for_finalize().finalize();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_muhash_remove_marks_for_division() {
        // Test that remove() affects the result
        let mut hash1 = MuHash3072::new();
        hash1.insert(b"element1");

        let mut hash2 = MuHash3072::new();
        hash2.insert(b"element1");
        hash2.remove(b"element1");

        // After removing what we inserted, should be different from just insert
        let result1 = hash1.clone_for_finalize().finalize();
        let result2 = hash2.clone_for_finalize().finalize();

        // Note: With proper modular inverse, the second hash would produce
        // identity (1), but the important thing is that remove() affects
        // the result and produces a deterministic output.
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_muhash_order_independence() {
        let mut hash1 = MuHash3072::new();
        hash1.insert(b"a");
        hash1.insert(b"b");

        let mut hash2 = MuHash3072::new();
        hash2.insert(b"b");
        hash2.insert(b"a");

        // Order shouldn't matter (multiplication is commutative)
        let result1 = hash1.clone_for_finalize().finalize();
        let result2 = hash2.clone_for_finalize().finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_muhash_different_elements() {
        let mut hash1 = MuHash3072::new();
        hash1.insert(b"element1");

        let mut hash2 = MuHash3072::new();
        hash2.insert(b"element2");

        let result1 = hash1.clone_for_finalize().finalize();
        let result2 = hash2.clone_for_finalize().finalize();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_muhash_combine() {
        let mut hash1 = MuHash3072::new();
        hash1.insert(b"a");

        let mut hash2 = MuHash3072::new();
        hash2.insert(b"b");

        let mut combined = MuHash3072::new();
        combined.insert(b"a");
        combined.insert(b"b");

        hash1.combine(&hash2);

        let result1 = hash1.clone_for_finalize().finalize();
        let result2 = combined.clone_for_finalize().finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_muhash_serialization() {
        let mut original = MuHash3072::new();
        original.insert(b"test data");

        let bytes = original.to_bytes();
        let restored = MuHash3072::from_bytes(&bytes);

        let result1 = original.clone_for_finalize().finalize();
        let result2 = restored.clone_for_finalize().finalize();

        assert_eq!(result1, result2);
    }

    /// Cross-checked against Bitcoin Core's
    /// `bitcoin-core/src/test/crypto_tests.cpp::muhash_tests`:
    ///
    /// ```cpp
    /// MuHash3072 acc2 = FromInt(0);
    /// unsigned char tmp[32]  = {1, 0};   acc2.Insert(tmp);
    /// unsigned char tmp2[32] = {2, 0};   acc2.Remove(tmp2);
    /// acc2.Finalize(out);
    /// BOOST_CHECK_EQUAL(out,
    ///   uint256{"10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"});
    /// ```
    ///
    /// `FromInt(i)` is `MuHash3072(unsigned char[32]{i,0,...})`, i.e. the
    /// 32-byte buffer with `i` in the first byte and zeros elsewhere.
    /// Core's `uint256{"hex"}` parses *display order* (reversed); SHA256's
    /// raw output equals the internal byte order of that uint256, which is
    /// what our `Hash256::to_hex()` reverses on the way out — so the hex
    /// string we produce should match Core's literal.
    #[test]
    fn test_muhash_known_vector_core_acc2() {
        let mut zero = [0u8; 32];
        zero[0] = 0;
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut two = [0u8; 32];
        two[0] = 2;

        let mut acc = MuHash3072::new();
        acc.insert(&zero);
        acc.insert(&one);
        acc.remove(&two);

        let result = acc.finalize();
        let expected = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863";
        let got = result.to_hex();
        assert_eq!(
            got, expected,
            "MuHash3072 known-vector mismatch (Core crypto_tests.cpp acc2)"
        );
    }

    /// Empty MuHash3072 finalizes to SHA256 of the canonical 384-byte
    /// representation of the value 1 (limb 0 = 1, all others zero).
    /// This is what Core does when no coins have been inserted: the
    /// numerator and denominator are both 1, the divide leaves 1, and we
    /// SHA256 the 384-byte LE serialization.
    #[test]
    fn test_muhash_empty_known_value() {
        // 384 bytes: [0x01, 0x00, 0x00, ..., 0x00].
        use sha2::{Digest, Sha256};
        let mut canonical = [0u8; 384];
        canonical[0] = 1;
        let expected = Sha256::digest(canonical);

        let mut acc = MuHash3072::new();
        let got = acc.finalize();
        assert_eq!(got.as_bytes(), expected.as_slice());
    }

    /// Round-trip: inserting then removing the same data must produce the
    /// same hash as the empty accumulator (since x/x = 1 in the prime
    /// field).  This exercises the modular inverse path.
    #[test]
    fn test_muhash_insert_remove_is_identity() {
        let mut empty = MuHash3072::new();
        let empty_hash = empty.finalize();

        let mut acc = MuHash3072::new();
        acc.insert(b"any data");
        acc.remove(b"any data");
        let got = acc.finalize();

        assert_eq!(got, empty_hash);
    }

    #[test]
    fn test_chacha20_deterministic() {
        let key = [0u8; 32];
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        chacha20_keystream(&key, &mut output1);
        chacha20_keystream(&key, &mut output2);

        assert_eq!(output1, output2);
    }
}
